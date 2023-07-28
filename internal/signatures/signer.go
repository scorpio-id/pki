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

	// TODO - generate self-signed certificate

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
func (s *Signer) ValidateCSR(csr []byte) error {
	_, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	return err
}

type RequestCSR struct {
	CertificateRequest string `json:"csr"`
}

// Handler for Certificate Signing Requests
func (s *Signer) CSRHandler(w http.ResponseWriter, r *http.Request) {

	if r.Header.Get("Content-Type") != "multipart/form-data" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}

	//FIXME: INVESTIGATE FORM DATA LIMITATIONS
	r.ParseMultipartForm(1000)

	csr := r.FormValue("csr")

	block, _ := pem.Decode([]byte(csr))
	
	cert, err := s.CreateX509(block.Bytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	block2 := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	err = pem.Encode(w, &block2)
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
