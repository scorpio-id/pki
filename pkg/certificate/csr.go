package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
	math2 "math/rand"

	"github.com/google/uuid"
)

// TODO - add issuer information
// Sign takes a CSR, private key, serial number, and TTL duration; produces a signed x.509 certificate
func Sign(csr []byte, private *rsa.PrivateKey, serial int64, duration time.Duration) ([]byte, error) {
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
		SerialNumber: big.NewInt(serial),
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

// Generate creates a CSR with existing rsa key pair
func GenerateCSRWithPrivateKey(sans []string, private *rsa.PrivateKey) ([]byte, error) {
	template := x509.CertificateRequest{
		PublicKeyAlgorithm: 1,
		PublicKey:          &private.PublicKey,
		DNSNames:           sans,
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, private)
}


func GenerateRootCertificate(issuer, common string, sans []string, private *rsa.PrivateKey, duration time.Duration) ([]byte, error){
	// compute TTL
	t := time.Now()
	after := t.Add(duration)

	serial := uuid.NewString()

	name := pkix.Name{
		Country: []string{"USA"},
		Organization: []string{"Ordinary Computing Co."},
		OrganizationalUnit: []string{"Technology"},
		Locality: []string{"Lewes"},
		Province: []string{"Delaware"},
		StreetAddress: []string{"16192 Coastal Highway"},
		PostalCode: []string{"19958"},
		SerialNumber: serial,
		CommonName: common,
	}

	template := x509.Certificate{
		Issuer: 	  			name,	
		Subject:      			name,
		DNSNames:     			sans,
		IssuingCertificateURL: 	[]string{issuer},
		IsCA: 					true,	
		NotAfter:     			after,
		NotBefore:    			t,
		SerialNumber: 			big.NewInt(math2.Int63()),
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &private.PublicKey, private)
}