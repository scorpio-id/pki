package signatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"net/http"
	"regexp"

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
		private:     private,
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

func verifyMultipartForm(w http.ResponseWriter, r *http.Request) error{
	match, err := regexp.MatchString("multipart/form-data; boundary=.*", r.Header.Get("Content-Type"))
	if err != nil {
		log.Fatal(err)
	}

	if !match {
		return http.ErrBodyNotAllowed
	}

	//FIXME: INVESTIGATE FORM DATA LIMITATIONS
	r.ParseMultipartForm(1000)

	return nil
}

type RequestCSR struct {
	CertificateRequest string `json:"csr"`
}


// Handler for Certificate Signing Requests
func (s *Signer) CSRHandler(w http.ResponseWriter, r *http.Request) {

	err := verifyMultipartForm(w, r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	csr := r.FormValue("csr")

	// 'block' is ASN.1 DER data (the client gives a PEM-encoded CSR)
	block, _ := pem.Decode([]byte(csr))

	cert, err := s.CreateX509(block.Bytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	// leaf certificate
	leaf := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	err = pem.Encode(w, &leaf)
	if err != nil {
		log.Fatal(err)
	}

	// add self-signed root (intermediate) ca
	root := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate.Raw,
	}

	err = pem.Encode(w, &root)
	if err != nil {
		log.Fatal(err)
	}
}


// Handler for PKCS12 Request
func (s *Signer) PKCSHandler(w http.ResponseWriter, r *http.Request) {
	err := verifyMultipartForm(w, r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}
	cr := r.FormValue("cr")

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode([]byte(cr))

	csr, err := certificate.InsertKeyCSR(block.Bytes, private)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := s.CreateX509(csr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	caCert := s.Certificate.Raw

	// Returns DER Encoded PKCS12 file
	pfxData, _, err := certificate.EncodePFX(private, cert, caCert)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}


	w.WriteHeader(http.StatusOK)

	pkcs12 := pem.Block{
		Type:  "PKCS12",
		Bytes:pfxData,
	}

	err = pem.Encode(w, &pkcs12)
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
