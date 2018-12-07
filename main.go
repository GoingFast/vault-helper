package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	vault "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	k8sTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type commands struct {
	TokenRenew     bool
	TokenSave      bool
	InitContainer  bool
	KubernetesRole string
	VaultAddr      string
	VaultSchema    string
	AppRole        string
	SecretSavePath string
	CertPath       string
}

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	app := cli.NewApp()
	app.Name = "Vault helper"
	app.Action = run
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   "tokenrenew",
			Usage:  "renew the token",
			EnvVar: "VAULTHELPER_TOKEN_RENEW",
		},
		cli.BoolFlag{
			Name:   "initcontainer",
			Usage:  "pod is in init container",
			EnvVar: "VAULTHELPER_INITCONTAINER",
		},
		cli.BoolFlag{
			Name:   "tokensave",
			Usage:  "save the vault token to k8s secret",
			EnvVar: "VAULTHELPER_TOKEN_SAVE",
		},
		cli.StringFlag{
			Name:   "kubernetesrole",
			Usage:  "vault kubernetes role",
			EnvVar: "VAULTHELPER_KUBERNETES_ROLE",
		},
		cli.StringFlag{
			Name:   "vaultaddr",
			Usage:  "vault address",
			EnvVar: "VAULTHELPER_VAULT_ADDR",
		},
		cli.StringFlag{
			Name: "vaultschema",

			EnvVar: "VAULTHELPER_VAULT_SCHEMA",
		},
		cli.StringFlag{
			Name:   "approle",
			Usage:  "approle",
			EnvVar: "VAULTHELPER_APPROLE",
		},
		cli.StringFlag{
			Name:   "secretsavepath",
			Usage:  "path where to save all the variables",
			EnvVar: "VAULTHELPER_SECRET_SAVEPATH",
			Value:  "/etc/vault/variables",
		},
		cli.StringFlag{
			Name:   "certpath",
			Usage:  "location of vault ca certificates",
			EnvVar: "VAULTHELPER_VAULT_CA_PATH",
			Value:  "/etc/certs/vault.pem",
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func run(c *cli.Context) error {
	cmds := commands{
		TokenRenew:     c.Bool("tokenrenew"),
		InitContainer:  c.Bool("initcontainer"),
		KubernetesRole: c.String("kubernetesrole"),
		VaultAddr:      c.String("vaultaddr"),
		VaultSchema:    c.String("vaultschema"),
		AppRole:        c.String("approle"),
		TokenSave:      c.Bool("tokensave"),
		SecretSavePath: c.String("secretsavepath"),
		CertPath:       c.String("certpath"),
	}
	return cmds.exec()
}

func (c commands) exec() error {
	d := newData(c)
	d.cmds = c

	log.WithFields(log.Fields{
		"tokenrenew":     d.cmds.TokenRenew,
		"initcontainer":  d.cmds.InitContainer,
		"kubernetesrole": d.cmds.KubernetesRole,
		"vaultaddr":      d.cmds.VaultAddr,
		"vaultschema":    d.cmds.VaultSchema,
		"approle":        d.cmds.AppRole,
		"tokensave":      d.cmds.TokenSave,
		"secretsavepath": d.cmds.SecretSavePath,
		"certpath":       d.cmds.CertPath,
	}).Info("Environment variables and flags")

	err := d.getVaultToken()
	if err != nil {
		return err
	}

	if c.TokenSave {
		err := d.saveTokenToKubeSecret()
		if err != nil {
			return err
		}
	}

	if c.TokenRenew {
		renewer, err := d.renewAuthToken()
		if err != nil {
			return err
		}
		defer renewer.Stop()
		go func() {
			for {
				select {
				case err := <-renewer.DoneCh():
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}()
		log.Info("Renewing auth token")
	}
	d.parseEnvs()
	if len(d.secrets) > 0 {
		err := d.getSecrets()
		if err != nil {
			return err
		}
		err = d.saveSecrets()
		if err != nil {
			return err
		}
	}

	sigchan := make(chan os.Signal, 1)
	if c.InitContainer {
		sigchan <- syscall.SIGINT
	}

	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan
	return nil
}

type secret struct {
	env map[string]string
	res response
}

type data struct {
	secrets []*secret
	client  *vault.Client
	res     response
	cmds    commands
}

type response struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		Accessor      string `json:"accessor"`
	} `json:"auth"`
	LeaseID       string            `json:"lease_id"`
	LeaseDuration int               `json:"lease_duration"`
	Data          map[string]string `json:"data"`
	Renewable     bool              `json:"renewable"`
}

func newData(c commands) data {
	var (
		err    error
		client *vault.Client
	)
	if c.VaultSchema == "https" {
		cert, err := ioutil.ReadFile(c.CertPath)
		if err != nil {
			log.Fatal(err)
		}
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(cert)
		tlsConf := &tls.Config{RootCAs: roots}
		tr := &http.Transport{TLSClientConfig: tlsConf}
		if !ok {
			log.Fatal("couldnt parse the certificate")
		}
		client, err = vault.NewClient(&vault.Config{
			Address: fmt.Sprintf("%s://%s", c.VaultSchema, c.VaultAddr), HttpClient: &http.Client{Transport: tr},
		})
	} else {
		client, err = vault.NewClient(&vault.Config{
			Address: fmt.Sprintf("%s://%s", c.VaultSchema, c.VaultAddr),
		})
	}
	if err != nil {
		log.Fatal(err)
	}

	return data{
		client: client,
	}
}

func (d *data) parseEnvs() {
	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")
		if strings.Contains(pair[0], "SECRET") {
			tr := strings.TrimLeft(pair[0], "SECRET_")
			d.secrets = append(d.secrets, &secret{
				env: map[string]string{
					tr: pair[1],
				},
			})
		}
	}
}

func getServiceAccountToken() (string, error) {
	_, err := os.Stat(k8sTokenPath)
	if err != nil {
		return "", err
	}

	token, err := ioutil.ReadFile(k8sTokenPath)
	if err != nil {
		return "", err
	}
	log.Info("Got service account token")
	return string(token), nil
}

func (d *data) getVaultToken() error {
	var (
		v1 response
		v2 response
		v3 response
		v4 response
	)
	{
		sa, err := getServiceAccountToken()
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		err = json.NewEncoder(&buf).Encode(map[string]string{
			"jwt":  sa,
			"role": d.cmds.KubernetesRole,
		})
		if err != nil {
			return err
		}

		req := d.client.NewRequest("POST", "/v1/auth/kubernetes/login")
		req.Body = &buf

		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		err = json.NewDecoder(res.Body).Decode(&v1)
		if err != nil {
			return err
		}

		log.WithFields(log.Fields{
			"token": v1.Auth.ClientToken,
		}).Info("Got kubernetes client token")
	}
	{
		d.client.SetToken(v1.Auth.ClientToken)
		req := d.client.NewRequest("GET", fmt.Sprintf("/v1/auth/approle/role/%s/role-id", d.cmds.AppRole))
		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		err = json.NewDecoder(res.Body).Decode(&v2)
		if err != nil {
			return err
		}

		log.WithFields(log.Fields{
			"id": v2.Data["role_id"],
		}).Info("Retrieved role id")
	}
	{
		req := d.client.NewRequest("POST", fmt.Sprintf("/v1/auth/approle/role/%s/secret-id", d.cmds.AppRole))
		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		err = json.NewDecoder(res.Body).Decode(&v3)
		if err != nil {
			return err
		}

		log.WithFields(log.Fields{
			"id": v3.Data["secret_id"],
		}).Info("Got secret id")
	}
	{
		req := d.client.NewRequest("POST", "/v1/auth/approle/login")
		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(map[string]string{
			"role_id":   v2.Data["role_id"],
			"secret_id": v3.Data["secret_id"],
		})
		if err != nil {
			return err
		}

		req.Body = &buf

		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		err = json.NewDecoder(res.Body).Decode(&v4)
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{
			"token": v4.Auth.ClientToken,
		}).Info("Got approle token")
	}
	d.res = v4
	return nil
}

func (d *data) getSecrets() error {
	d.client.SetToken(d.res.Auth.ClientToken)

	values := make([]string, len(d.secrets))

	var n int
	for _, secret := range d.secrets {
		for _, v := range secret.env {
			values[n] = v
		}
		n++
	}

	log.Println(fmt.Sprintf("Amount of secret groups in environment variables: %v", len(d.secrets)))

	for i := 0; i < len(d.secrets); i++ {
		req := d.client.NewRequest("GET", fmt.Sprintf("/v1/%s", values[i]))
		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		var v response
		err = json.NewDecoder(res.Body).Decode(&v)
		if err != nil {
			log.Fatal(err)
		}
		d.secrets[i] = &secret{res: v}
	}
	return nil
}

func (d *data) renewSecrets() error {
	for _, secret := range d.secrets {
		if secret.res.LeaseID != "" && secret.res.Renewable {
			log.Println("Got renewable secret")
			renewer, err := d.client.NewRenewer(&vault.RenewerInput{Secret: &vault.Secret{
				LeaseID:       secret.res.LeaseID,
				LeaseDuration: secret.res.LeaseDuration,
			}})
			if err != nil {
				return err
			}
			go renewer.Renew()
			go func() {
				defer renewer.Stop()
				for {
					select {
					case err := <-renewer.DoneCh():
						if err != nil {
							log.Fatal(err)
						}
					}
				}
			}()
		}
	}
	return nil
}

func (d *data) renewAuthToken() (*vault.Renewer, error) {
	renewer, err := d.client.NewRenewer(&vault.RenewerInput{Secret: &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken:   d.res.Auth.ClientToken,
			LeaseDuration: d.res.Auth.LeaseDuration,
			Accessor:      d.res.Auth.Accessor,
			Renewable:     d.res.Auth.Renewable,
		},
	}})
	if err != nil {
		return nil, err
	}
	go renewer.Renew()
	return renewer, nil
}

func (d *data) saveSecrets() error {
	var buf bytes.Buffer
	for _, secret := range d.secrets {
		for k, v := range secret.res.Data {
			fmt.Fprintf(&buf, "%s=\"%s\"\n", strings.ToUpper(k), v)
		}
	}
	err := ioutil.WriteFile(d.cmds.SecretSavePath, buf.Bytes(), 0644)
	if err != nil {
		return err
	}
	log.Println(fmt.Sprintf("Saved %v secret group variables", len(d.secrets)))
	return nil
}

func (d *data) revokeAuthToken() error {
	auth := d.client.Auth()
	tokenAuth := auth.Token()
	err := tokenAuth.RevokeSelf("")
	if err != nil {
		return err
	}
	log.Println("Successfully revoked the auth token")
	return nil
}

func getNamespace() (string, error) {
	_, err := os.Stat(k8sNamespacePath)
	if err != nil {
		return "", err
	}

	ns, err := ioutil.ReadFile(k8sNamespacePath)
	if err != nil {
		return "", err
	}

	return string(ns), nil
}

func (d *data) saveTokenToKubeSecret() error {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return err
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	kubeAPI := clientSet.CoreV1()
	ns, err := getNamespace()
	if err != nil {
		return err
	}

	secrets := kubeAPI.Secrets(ns)
	_, err = secrets.Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-vault-token", d.cmds.KubernetesRole),
			Namespace: ns,
		},
		Data: map[string][]byte{
			"token": []byte(d.res.Auth.ClientToken),
		},
	})
	if errors.IsAlreadyExists(err) {
		m, err := json.Marshal([]map[string]interface{}{
			map[string]interface{}{
				"op":    "replace",
				"path":  "/data/token",
				"value": []byte(d.res.Auth.ClientToken),
			},
		})
		if err != nil {
			return err
		}

		_, err = secrets.Patch(fmt.Sprintf("%s-vault-token", d.cmds.KubernetesRole), types.JSONPatchType, m)
		if err != nil {
			return err
		}
	}
	log.Info("Saved the token to Kubernetes secret")
	return nil
}
