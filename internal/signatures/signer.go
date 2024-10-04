package signatures

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"encoding/pem"

	_ "github.com/scorpio-id/pki/docs"
	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/data"
	"github.com/scorpio-id/pki/pkg/certificate"
)

// Signer generates an RSA public, private key pair and signs X.509 certificates
type Signer struct {
	RSABits             int
	CSRMaxMemory        int
	CurrentSerialNumber int64
	AllowedSANs         []string
	Duration            time.Duration
	Certificate         *x509.Certificate
	private             *rsa.PrivateKey
	Store               *data.SubjectAlternateNameStore
}

func NewSigner(cfg config.Config) *Signer {
	// start by creating a RSA public/private key pair
	private, err := rsa.GenerateKey(rand.Reader, cfg.PKI.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := certificate.GenerateCSR([]string{cfg.PKI.CertificateAuthority.CommonName}, cfg.PKI.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	duration, err := time.ParseDuration(cfg.PKI.CertificateTTL)
	cert, err := certificate.Sign(csr, private, cfg.PKI.SerialNumber, duration)
	if err != nil {
		log.Fatal(err)
	}

	// create store and add own name to store
	// FIXME - currently add the CA's Common Name, do we need to add *.CommonName as well to prevent impersonation?
	store := data.NewSubjectAlternateNameStore()
	ca := data.SANs{
		SerialNumber: cfg.PKI.SerialNumber,
		Names:        []string{cfg.PKI.CertificateAuthority.CommonName},
	}

	err = store.Add(ca)
	if err != nil {
		log.Fatalf("issue adding [%v] to blank SAN store", err)
	}

	x509, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatal(err)
	}

	return &Signer{
		RSABits:             cfg.PKI.RSABits,
		CSRMaxMemory:        cfg.PKI.CSRMaxMemory,
		CurrentSerialNumber: cfg.PKI.SerialNumber,
		AllowedSANs:         cfg.PKI.AllowedNames,
		Duration:            duration,
		Certificate:         x509,
		private:             private,
		Store:               store,
	}
}

// CreateX509 allows the signer to generate a signed X.509 based off configurations and while keeping track of serial number
func (s *Signer) CreateX509(csr []byte) ([]byte, error) {
	// ensure desired SAN is allowed per policy configuration
	err := s.EnforceNamePolicy(csr)
	if err != nil {
		return nil, err
	}

	content, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	// increment serial number
	s.CurrentSerialNumber += 1

	// the SAN store enforces all names be unique; add requested Common Name to requested SANs
	names := append(content.DNSNames, content.Subject.CommonName)

	san := data.SANs{
		SerialNumber: s.CurrentSerialNumber,
		Names:        names,
	}

	err = s.Store.Add(san)
	if err != nil {
		return nil, err
	}

	return certificate.Sign(csr, s.private, s.CurrentSerialNumber, s.Duration)
}

// EnforceNamePolicy ensures that requested Common Name and SANs are within configured naming standards policy
func (s *Signer) EnforceNamePolicy(csr []byte) error {
	template, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Fatal(err)
	}

	names := append(template.DNSNames, template.Subject.CommonName)

	for _, san := range names {
		allowed := false
		for _, expression := range s.AllowedSANs {
			match, err := regexp.MatchString(expression, san)
			if err != nil {
				return err
			}
			if match {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("name [%v] is prohibited by certificate authority policy", san)
		}
	}

	return err
}

// SerializeX509 installs certs on the local linux filesystem
func (s *Signer) SerializeX509() error {
	// TODO: move filepath to config
	out, err := os.Create("/etc/ssl/certs/scorpio-root.pem")
    if err != nil {
        return err
    }

	defer out.Close()

	w := bufio.NewWriter(out)

	root := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate.Raw,
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &root)
	if err != nil {
		return err
	}

	w.Flush()

	key, err := os.Create("/etc/ssl/certs/scorpio-private.key")
    if err != nil {
        return err
    }

	defer key.Close()

	w = bufio.NewWriter(key)

	private := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(s.private), 
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &private)
	if err != nil {
		return err
	}

	w.Flush()

	return nil
}


//  CSR Handler Swagger Documentation
//
//	@Summary		Processes Certificate Signing Requests and returns X.509
//	@Description	The CSR handler is responsible for processing Certificate Signing Requests (CSRs). It validates incoming CSR data, ensuring compliance with formatting and policy standardsnn are met. Once validated, the handler creates a new digital certificate with the entity's public key and associated identity information. The handler produces and returns a PEM encoded certificate 
//	@Tags			CSR 
//	@Accept			mpfd
//	@Produce		octet-stream
//	@Success		200				{body}		file		"Certificate.pem"
//	@Failure		400				{string}	http.error	"Bad Request"
//	@Failure		415				{string}	http.error	"Unsuported Media - Must be Multipart Form Data"
//
//	@Router	/certificate [post]
//
// CSRHandler accepts a CSR in a multipart form data request and returns a PEM file or JSON content given HTTP Accept header
func (s *Signer) CSRHandler(w http.ResponseWriter, r *http.Request) {
	// verify boundary of multipart form data request
	err := VerifyMultipartForm(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}

	// FIXME: INVESTIGATE FORM DATA LIMITATIONS
	err = r.ParseMultipartForm(int64(s.CSRMaxMemory))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	csr := r.PostForm.Get("csr")
	if csr == "" {
		http.Error(w, "csr post form field is blank", http.StatusBadRequest)
		return
	}

	// 'block' is ASN.1 DER data (the client gives a PEM-encoded CSR)
	block, _ := pem.Decode([]byte(csr))

	cert, err := s.CreateX509(block.Bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// return 'file' content type
	w.Header().Set("Content-Type", "application/octet-stream")

	// TODO - support JSON responses
	if r.Header.Get("Accept") == "application/json" {
		// some function to return JSON content for X.509 or PKCS
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
// PKCS #12 Handler Swagger Documentation
//
//	@Summary		Handles PKCS #12 request
//	@Description	CSRHandler accepts a CSR in a multipart form data request and returns a PEM file or JSON content given HTTP Accept header
//	@Tags			PKCS-12
//	@Accept			x-www-form-urlencoded
//	@Produce		octet-stream
//	@Success		200				{file}		Certificate.pfx
//	@Failure		400				{string}	string	"Bad Request"
//	@Failure		500				{string}	string	"Internal Server Error"
//	@Router			/p12 [post]
//
// PKCSHandler accepts SAN data and returns a PKCS12 file or JSON content given HTTP Accept header
func (s *Signer) PKCSHandler(w http.ResponseWriter, r *http.Request) {
	// verify Content-Type
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	
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
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	cert, err := s.CreateX509(csr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	intermediate := s.Certificate.Raw

	// returns DER-encoded PKCS12 file
	pfx, _, err := certificate.EncodePFX(private, cert, intermediate)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
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

// Public X.509 Handler Swagger Documentation
//
//	@Summary	Exposes the CAs Public X.509
//	@Tags		Certificates
//	@Success	200	{file}	Public	X.509	(PEM Encoded)
//	@Router		/public [get]
// 
// PublicHandler returns the public X.509 of the certificate authority
func (s *Signer) PublicHandler(w http.ResponseWriter, r *http.Request) {
	// TODO - return JSON (JWKS?) representation
	w.Header().Set("Content-Type", "application/octet-stream")

	root := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate.Raw,
	}

	// TODO: check to ensure serialized correctly
	err := pem.Encode(w, &root)
	if err != nil {
		w.WriteHeader(500)
	}
}

func VerifyMultipartForm(w http.ResponseWriter, r *http.Request) error {
	match, err := regexp.MatchString("multipart/form-data; boundary=.*", r.Header.Get("Content-Type"))
	if err != nil {
		log.Fatal(err)
	}

	if !match {
		return fmt.Errorf("Content-Type header must contain multipart/form-data with boundary") 
	}

	return nil
}


