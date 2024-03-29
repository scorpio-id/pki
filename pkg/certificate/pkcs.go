package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"
)

// Generates CSR after parsing certificate request and then embeding public key within request
// <cr> must be DER Encoded
func InsertKeyCSR(csr []byte, private *rsa.PrivateKey) ([]byte, error){
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		DNSNames:  request.DNSNames,
	}

	return x509.CreateCertificateRequest(rand.Reader,&template, private)
}


// Generates DER Encoded PFX file using passed in private keys and certificates
func EncodePFX(private interface{}, certificate []byte, intermediates []byte) ([]byte, string, error){

	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, "", err
	}

	intermediate, err := x509.ParseCertificate(intermediates)
	if err != nil {
		return nil, "", err
	}

	p := uuid.New()

	// TODO: CONSIDER WHETHER PASSWORD SHOULD BE CONFIGURABLE 
	// TODO: CONSIDER BUILDING ENCODE FUNCTION
	pfx, err := pkcs12.Encode(rand.Reader, private, parsed, []*x509.Certificate{intermediate},  "")
	return pfx, p.String(), err
}