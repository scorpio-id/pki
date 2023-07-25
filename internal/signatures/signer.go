package signatures

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"

	"encoding/pem"

	"github.com/scorpio-id/pki/pkg/certificate"
)

// Generates RSA Public & Private Key Pair and signs
// FIXME - needs to include self-signed cert for CA bundle
type Signer struct {
	private *rsa.PrivateKey
}

// TODO - make bits configurable!
// TODO - generate root certificate
func NewSigner() *Signer {
	// start by creating a 2048-bit RSA public/private key pair
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	return &Signer{
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

// Handler for Certificate Signing Requests,
// Creates and Verifies to create a X.509 certificates
func (s *Signer) HandleCSR(w http.ResponseWriter, r *http.Request) {

	// if r.Header.Get("Content-Type") != "application/json" {
	// 	w.WriteHeader(http.StatusUnsupportedMediaType)
	// }

	csr, err := certificate.GenerateCSR()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	//log.Print(base64.StdEncoding.EncodeToString(csr))
	block := pem.Block{
		Type: "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	output := pem.EncodeToMemory(&block)
	log.Print(string(output))

	cert, err := s.CreateX509(csr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	block = pem.Block{
		Type: "CERTIFICATE",
		Bytes: cert,
	}

	err = pem.Encode(w, &block)
	if err != nil {
		log.Fatal(err)
	}

	//w.WriteHeader(http.StatusOK)
	//w.Write([]byte(base64.StdEncoding.EncodeToString(cert)))
}
