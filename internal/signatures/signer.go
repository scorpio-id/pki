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
	"github.com/scorpio-id/pki/internal/data"
	"github.com/scorpio-id/pki/pkg/certificate"
)

// Generates RSA Public & Private Key Pair and signs X.509 certificates
type Signer struct {
	RSABits             int
	CSRMaxMemory        int
	AllowedSANs         []string
	Duration            time.Duration
	CurrentSerialNumber *big.Int
	Certificate         *x509.Certificate
	private             *rsa.PrivateKey
	Store               data.SubjectAlternateNameStore
}

func NewSigner(cfg config.Config) *Signer {
	// start by creating a 2048-bit RSA public/private key pair
	private, err := rsa.GenerateKey(rand.Reader, cfg.PKI.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := certificate.GenerateCSR(cfg.PKI.CertificateAuthority, cfg.PKI.RSABits)
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
		RSABits:             cfg.PKI.RSABits,
		CSRMaxMemory:        cfg.PKI.CSRMaxMemory,
		AllowedSANs:         cfg.PKI.AllowedSANs,
		Duration:            duration,
		CurrentSerialNumber: serial,
		Certificate:         x509,
		private:             private,
		Store:               data.NewSubjectAlternateNameStore(),
	}
}

// CreateX509 allows the signer to generate a signed X.509 based off configurations and while keeping track of serial number
func (s *Signer) CreateX509(csr []byte) ([]byte, error) {
	// TODO - call ValidateCSR() ...

	// increment serial number (need mutex here?)
	defer s.CurrentSerialNumber.Add(s.CurrentSerialNumber, big.NewInt(1))

	content, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	san := data.SANs{
		SerialNumber: s.CurrentSerialNumber,
		Names:        content.DNSNames,
	}

	err = s.Store.Add(san)
	if err != nil {
		return nil, err
	}

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

func (s *Signer) verifyMultipartForm(w http.ResponseWriter, r *http.Request) error {
	match, err := regexp.MatchString("multipart/form-data; boundary=.*", r.Header.Get("Content-Type"))
	if err != nil {
		log.Fatal(err)
	}

	if !match {
		return http.ErrBodyNotAllowed
	}

	//FIXME: INVESTIGATE FORM DATA LIMITATIONS
	r.ParseMultipartForm(int64(s.CSRMaxMemory))

	return nil
}

// CSRHandler accepts a CSR in a multipart form data request and returns a PEM file or JSON content given HTTP Accept header
func (s *Signer) CSRHandler(w http.ResponseWriter, r *http.Request) {
	// verify boundary of multipart form data request
	err := s.verifyMultipartForm(w, r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	csr := r.FormValue("csr")

	// 'block' is ASN.1 DER data (the client gives a PEM-encoded CSR)
	block, _ := pem.Decode([]byte(csr))

	// TODO - support JSON responses
	if r.Header.Get("Accept") == "application/json" {
		// some function to return JSON content for X.509 or PKCS
	}

	w.Header().Set("Content-Type", "application/octet-stream")

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

// PKCSHandler accepts SAN data and returns a PKCS12 file or JSON content given HTTP Accept header
func (s *Signer) PKCSHandler(w http.ResponseWriter, r *http.Request) {
	// generate new RSA identity for PKCS12
	private, err := rsa.GenerateKey(rand.Reader, s.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	values := r.URL.Query()
	if values == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// FIXME - do we need to do this to get duplicate query params?
	var sans []string
	for k, v := range values {
		if k == "san" {
			sans = v
		}
	}

	csr, err := certificate.GenerateCSR(sans, s.RSABits)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	csr, err = certificate.InsertKeyCSR(csr, private)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := s.CreateX509(csr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	intermediate := s.Certificate.Raw

	// returns DER-encoded PKCS12 file
	pfx, _, err := certificate.EncodePFX(private, cert, intermediate)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}

	// TODO - support JSON responses
	if r.Header.Get("Accept") == "application/json" {
		// some function to return JSON content for X.509 or PKCS
	}

	w.Header().Set("Content-Type", "application/octet-stream")

	pkcs12 := pem.Block{
		Type:  "PKCS12",
		Bytes: pfx,
	}

	err = pem.Encode(w, &pkcs12)
	if err != nil {
		log.Fatal(err)
	}
}

// PublicHandler returns the public key of the certificate authority
func (s *Signer) PublicHandler(w http.ResponseWriter, r *http.Request) {
	// TODO - return JSON (JWKS?) representation
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
