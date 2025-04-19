package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	math2 "math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/scorpio-id/pki/internal/config"
)

// TODO - add issuer information
// Sign takes a CSR, private key, serial number, and TTL duration; produces a signed x.509 certificate
func Sign(csr []byte, private *rsa.PrivateKey, serial int64, duration time.Duration, parent *x509.Certificate) ([]byte, error) {
	// parse CSR into template
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	// compute TTL
	t := time.Now()
	after := t.Add(duration)

	template := x509.Certificate{
		Issuer:                 parent.Subject,
		Subject:                request.Subject,
		DNSNames:               request.DNSNames,
		IsCA:                   false,
		IssuingCertificateURL: 	[]string{parent.Subject.CommonName},
		NotAfter:               after,
		NotBefore:              t,
		SerialNumber:           big.NewInt(serial),
	}

	// 'cert' is ASN.1 DER data
	cert, err := x509.CreateCertificate(rand.Reader, &template, parent, request.PublicKey, private)
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

// Generate creates a CSR with existing rsa key pair
func GenerateCSRWithPrivateKey(sans []string, private *rsa.PrivateKey) ([]byte, error) {
	// FIXME generate subject content and add to template
	template := x509.CertificateRequest{
		PublicKeyAlgorithm: 1,
		PublicKey:          &private.PublicKey,
		DNSNames:           sans,
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, private)
}


func GenerateRootCertificate(cfg config.Config, private *rsa.PrivateKey, duration time.Duration) ([]byte, error){
	// compute TTL
	t := time.Now()
	after := t.Add(duration)

	serial := uuid.NewString()

	name := pkix.Name{
		Country: []string{cfg.Root.Country},
		Organization: []string{cfg.Root.Organization},
		OrganizationalUnit: []string{cfg.Root.OrganizationalUnit},
		Locality: []string{cfg.Root.Locality},
		Province: []string{cfg.Root.Province},
		StreetAddress: []string{cfg.Root.StreetAddress},
		PostalCode: []string{cfg.Root.PostalCode},
		SerialNumber: serial,
		CommonName: cfg.Root.CommonName,
	}

	// using Common Name as issuer in root x509 template
	template := x509.Certificate{
		Issuer: 	  			name,	
		Subject:      			name,
		DNSNames:     			cfg.Root.SANs,
		IssuingCertificateURL: 	[]string{cfg.Root.CommonName},
		IsCA: 					true,	
		NotAfter:     			after,
		NotBefore:    			t,
		SerialNumber: 			big.NewInt(math2.Int63()),
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
}