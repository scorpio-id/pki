package signatures

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"github.com/scorpio-id/pki/pkg/certificate"
)

// Generates RSA Public & Private Key Pair and signs

type Signer struct {
	private *rsa.PrivateKey
}

// TODO - make bits configurable!
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
func (s *Signer) CreateX509() ([]byte, error){
	// FIXME - call ValidateCSR() ...
	return certificate.Sign(s.private)
}

// TODO - should check required fields of CSR before signing, as well as any security policy (ie: no *.com)
func (s *Signer) ValidateCSR() {

}

// Handler for Certificate Signing Requests,
// Creates and Verifies to create a X.509 certificates
func (s *Signer) HandleCSR(w http.ResponseWriter, r *http.Request) {

	// if r.Header.Get("Content-Type") != "application/json" {
	// 	w.WriteHeader(http.StatusUnsupportedMediaType)
	// }

	cert, err := s.CreateX509()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	// r.Body = http.MaxBytesReader(w, r.Body, 1000000) // Each Request at max takes 1 KB

	// decoder := json.NewDecoder(r.Body)
	// decoder.DisallowUnknownFields()

	// var c certificate.CSR

	// err := decoder.Decode(&c)
	// if err != nil{
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }

	w.WriteHeader(http.StatusOK)
	w.Write(cert)
}
