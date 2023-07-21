package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"math/big"
	"time"
	b64 "encoding/base64"
)

// Sign takes a private key and a CSR and produces a signed x.509 certificate
// TODO - add CSR byte[] as input argument
func Sign(private *rsa.PrivateKey) ([]byte, error) {
	// Check CSR if SAN is taken
	// Fail otherwise
	// Create X.509 signed with Private keys

	// sample identity for CSR
	sample, _ := rsa.GenerateKey(rand.Reader, 2048)

	// after is two years past the current date
	t := time.Now()
	after := t.AddDate(2, 0, 0)

	template := x509.Certificate{
		DNSNames:  []string{"scorpio.io", "*.scorpio.io"},
		NotAfter:  after,
		NotBefore: t,
		SerialNumber: big.NewInt(111000),
	}

	// FIXME - sample public key here, normally extract public key from CSR
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &sample.PublicKey, private)
	if err != nil {
		return nil, err
	}

	log.Print(b64.StdEncoding.EncodeToString(cert))
	return cert, nil
}
