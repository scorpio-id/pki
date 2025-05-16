package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/pkg/certificate"
)

// Creates Key Pair and CSR for Scorpio Web Client to establish TLS 
func CreateWebServerCSR(cfg config.Config) (*rsa.PrivateKey, []byte,  error) {
	// Creates a RSA public/private key pair for web server
	private, err := rsa.GenerateKey(rand.Reader, cfg.PKI.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := certificate.GenerateDomainClientCSR(cfg, private)
	if err != nil {
		log.Fatal(err)
	}

	return private, csr, nil
}


// SerializeX509 installs certs on the local linux filesystem
func SerializeX509(private *rsa.PrivateKey, webCert []byte) error {
	// TODO: move filepath to config
	out, err := os.Create("/etc/ssl/certs/scorpio-root.pem")
    if err != nil {
        return err
    }

	defer out.Close()

	w := bufio.NewWriter(out)

	root := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: webCert,
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &root)
	if err != nil {
		return err
	}

	w.Flush()

	key, err := os.Create("/etc/ssl/certs/scorpio-private.key")
    if err != nil {
        return err
    }

	defer key.Close()

	w = bufio.NewWriter(key)

	privateBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private), 
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &privateBlock)
	if err != nil {
		return err
	}

	w.Flush()

	return nil
}