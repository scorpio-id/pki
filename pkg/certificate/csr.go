package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"math/big"
	"time"
)

// TODO - add issuer information
// Sign takes a CSR, private key, serial number, and TTL duration; produces a signed x.509 certificate
func Sign(csr []byte, private *rsa.PrivateKey, serial *big.Int, duration time.Duration) ([]byte, error) {
	// parse CSR into template
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	// compute TTL
	t := time.Now()
	after := t.Add(duration)

	template := x509.Certificate{
		Subject:      request.Subject,
		DNSNames:     request.DNSNames,
		NotAfter:     after,
		NotBefore:    t,
		SerialNumber: serial,
	}

	// 'cert' is ASN.1 DER data
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, request.PublicKey, private)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Generate creates a CSR
func GenerateCSR(sans []string, bits int) ([]byte, error) {
	// identity for CSR
	sample, _ := rsa.GenerateKey(rand.Reader, bits)

	// 1 is RSA
	template := x509.CertificateRequest{
		PublicKeyAlgorithm: 1,
		PublicKey:          &sample.PublicKey,
		DNSNames:           sans,
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, sample)
}
