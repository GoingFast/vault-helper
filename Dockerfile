FROM golang:alpine AS builder
COPY . /vault-helper
WORKDIR /vault-helper
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o binary -mod=vendor

FROM alpine
COPY --from=builder /vault-helper/binary
ENTRYPOINT ["./binary"]
