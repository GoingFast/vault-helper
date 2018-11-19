package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	vault "github.com/hashicorp/vault/api"
)

var (
	k8sTokenPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	renewAuthToken  = flag.Bool("renewtoken", false, "renew the auth token")
	getSecrets      = flag.Bool("secrets", false, "get secrets from vault")
	renewSecrets    = flag.Bool("renewsecrets", false, "renews secrets")
	revokeAuthToken = flag.Bool("revoketoken", false, "revokes the auth token")
)

func main() {
	flag.Parse()
	d := newData()
	switch {
	case *getSecrets:
		err := d.getVaultToken()
		if err != nil {
			log.Fatal(err)
		}
		d.getSecrets()
		d.saveSecrets()
	case *renewSecrets:
		err := d.renewSecrets()
		if err != nil {
			log.Fatal(err)
		}
	case *renewAuthToken:
		renewer, err := d.renewAuthToken()
		if err != nil {
			log.Fatal(err)
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
	case *revokeAuthToken:
		err := d.revokeAuthToken()
		if err != nil {
			log.Fatal(err)
		}
	default:
		flag.Usage()
	}
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan
}

type secret struct {
	env map[string]string
	res response
}

type data struct {
	secrets []*secret
	client  *vault.Client
	res     response
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

func newData() data {
	client, err := vault.NewClient(&vault.Config{
		Address: fmt.Sprintf("%s://%s", os.Getenv("VAULT_SCHEMA"), os.Getenv("VAULT_ADDR")),
	})
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

	log.Println("Got service account token")
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
			"role": os.Getenv("VAULT_K8S_ROLE"),
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
		log.Println("Successfully retrieved: kubernetes client token")
	}
	{
		d.client.SetToken(v1.Auth.ClientToken)
		req := d.client.NewRequest("GET", fmt.Sprintf("/v1/auth/approle/role/%s/role-id", os.Getenv("VAULT_LOGIN_ROLE")))
		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		err = json.NewDecoder(res.Body).Decode(&v2)
		if err != nil {
			return err
		}
		log.Println("Successfully retrieved: role-id")
	}
	{
		req := d.client.NewRequest("POST", fmt.Sprintf("/v1/auth/approle/role/%s/secret-id", os.Getenv("VAULT_LOGIN_ROLE")))
		res, err := d.client.RawRequest(req)
		if err != nil {
			return err
		}

		err = json.NewDecoder(res.Body).Decode(&v3)
		if err != nil {
			return err
		}
		log.Println("Successfully retrieved: secret-id")
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
		log.Println("Successfully retrieved: approle token")
	}
	d.res = v4
	return nil
}

func (d *data) getSecrets() error {
	d.parseEnvs()
	d.client.SetToken(d.res.Auth.ClientToken)

	values := make([]string, len(d.secrets))

	var n int
	for _, secret := range d.secrets {
		for _, v := range secret.env {
			values[n] = v
		}
		n++
	}
	log.Println(fmt.Sprintf("Amount of environment variables: %v", len(d.secrets)))
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
	err := ioutil.WriteFile("/etc/variables", buf.Bytes(), 0644)
	if err != nil {
		return err
	}
	log.Println(fmt.Sprintf("Saved %v variables", len(d.secrets)))
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
