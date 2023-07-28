package signatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"net/http"

	"encoding/pem"

	"github.com/scorpio-id/pki/pkg/certificate"
)

// Generates RSA Public & Private Key Pair and signs
// FIXME - needs to include self-signed cert for CA bundle
type Signer struct {
	Certificate *x509.Certificate
	private     *rsa.PrivateKey
}

// TODO - make bits configurable!
// TODO - make configurable
func NewSigner() *Signer {
	// start by creating a 2048-bit RSA public/private key pair
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := certificate.GenerateCSR([]string{"scorpio.io", "*.scorpio.io"})
	if err != nil {
		log.Fatal(err)
	}

	cert, err := certificate.Sign(csr, private)
	if err != nil {
		log.Fatal(err)
	}

	x509, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatal(err)
	}

	return &Signer{
		Certificate: x509,
		private: private,
	}

}

// TODO - should accept a CSR (PEM-ecoded)
func (s *Signer) CreateX509(csr []byte) ([]byte, error) {
	// FIXME - call ValidateCSR() ...
	return certificate.Sign(csr, s.private)
}

// TODO - should check required fields of CSR before signing, as well as any security policy (ie: no *.com)
func (s *Signer) ValidateCSR(csr []byte) {
	// parsed, err := x509.ParseCertificateRequest(csr)
	// if err != nil {
	// 	log.Fatal(err)
	// }
}

// Handler for Certificate Signing Requests
func (s *Signer) CSRHandler(w http.ResponseWriter, r *http.Request) {

	// if r.Header.Get("Content-Type") != "application/json" {
	// 	w.WriteHeader(http.StatusUnsupportedMediaType)
	// }

	// TODO - accept PEM-encoded CSR string in JSON
	// TODO - add config
	csr, err := certificate.GenerateCSR([]string{"example.com", "*.example.com"})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	output := pem.EncodeToMemory(&block)
	log.Print(string(output))

	// 'csr' is ASN.1 DER data (the client gives a PEM-encoded CSR)
	cert, err := s.CreateX509(csr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	// leaf certificate
	block = pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	err = pem.Encode(w, &block)
	if err != nil {
		log.Fatal(err)
	}

	// add self-signed root ca
	block = pem.Block{
		Type: "CERTIFICATE",
		Bytes: s.Certificate.Raw,
	}

	err = pem.Encode(w, &block)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Signer) PublicHandler(w http.ResponseWriter, r *http.Request) {
	public, err := x509.MarshalPKIXPublicKey(&s.private.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: public,
	}

	err = pem.Encode(w, &block)
	if err != nil {
		log.Fatal(err)
	}
}
