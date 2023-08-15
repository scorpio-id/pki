package signatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"time"

	"encoding/pem"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/pkg/certificate"
)

// Generates RSA Public & Private Key Pair and signs
// FIXME - needs to include self-signed cert for CA bundle
type Signer struct {
	AllowedSANs         []string
	Duration            time.Duration
	CurrentSerialNumber *big.Int
	Certificate         *x509.Certificate
	private             *rsa.PrivateKey
}

func NewSigner(cfg config.Config) *Signer {
	// start by creating a 2048-bit RSA public/private key pair
	private, err := rsa.GenerateKey(rand.Reader, cfg.PKI.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := certificate.GenerateCSR(cfg.PKI.CertificateAuthority)
	if err != nil {
		log.Fatal(err)
	}

	serial := big.NewInt(int64(cfg.PKI.SerialNumber))
	duration, err := time.ParseDuration(cfg.PKI.CertificateTTL)
	cert, err := certificate.Sign(csr, private, serial, duration)
	if err != nil {
		log.Fatal(err)
	}

	// add one to current serial number
	serial.Add(serial, big.NewInt(1))

	x509, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatal(err)
	}

	// TODO - create SAN store and attach here
	return &Signer{
		AllowedSANs:         cfg.PKI.AllowedSANs,
		Duration:            duration,
		CurrentSerialNumber: serial,
		Certificate:         x509,
		private:             private,
	}

}

// CreateX509 allows the signer to generate a signed X.509 based off configurations and while keeping track of serial number
func (s *Signer) CreateX509(csr []byte) ([]byte, error) {
	// TODO - call ValidateCSR() ...

	// increment serial number (need mutex here?)
	defer s.CurrentSerialNumber.Add(s.CurrentSerialNumber, big.NewInt(1))

	return certificate.Sign(csr, s.private, s.CurrentSerialNumber, s.Duration)
}

// TODO - should check required fields of CSR before signing, as well as any security policy (ie: no *.com)
func (s *Signer) ValidateCSR(csr []byte) error {
	_, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	return err
}

func verifyMultipartForm(w http.ResponseWriter, r *http.Request) error {
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

	if r.Header.Get("Accept") == "application/json" {
		// some function to return JSON content for X.509 or PKCS
	}

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
	// FIXME: Give just strings for specified SANS
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
		Bytes: pfxData,
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
