package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"math/big"
	"time"
)

// Sign takes a private key and a CSR and produces a signed x.509 certificate
// TODO - add CSR byte[] as input argument
func Sign(csr []byte, private *rsa.PrivateKey) ([]byte, error) {
	// Check CSR if SAN is taken
	// Fail otherwise
	// Create X.509 signed with Private keys

	// parse CSR into template
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	// TODO copy request contents into new cert template?
	// after is two years past the current date
	t := time.Now()
	after := t.AddDate(2, 0, 0)

	template := x509.Certificate{
		DNSNames:  request.DNSNames,
		NotAfter:  after,
		NotBefore: t,
		SerialNumber: big.NewInt(1),
	}

	// FIXME - sample public key here, normally extract public key from CSR
	// 'cert' is ASN.1 DER data
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, request.PublicKey, private)
	if err != nil {
		return nil, err
	}

	// 'parsed' is a populated *Certificate struct (for example purposes)
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(parsed.DNSNames)

	return cert, nil
}

// Generate creates a sample CSR for testing purposes
func GenerateCSR() ([]byte, error) {
	// sample identity for CSR
	sample, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 1 is RSA
	template := x509.CertificateRequest{
		PublicKeyAlgorithm: 1,
		PublicKey: &sample.PublicKey,
		DNSNames: []string{"scorpio.io", "*.scorpio.io"},
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, sample)
}
