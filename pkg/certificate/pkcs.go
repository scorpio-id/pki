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
func InsertKeyCSR(cr []byte, private *rsa.PrivateKey)([]byte, error){
	request, err := x509.ParseCertificateRequest(cr)
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		DNSNames:  request.DNSNames,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader,&template, private)

	return csr, err
}


// Generates DER Encoded PFX file using passed in private keys and certificates
func EncodePFX(private interface{}, certificate []byte, caCerts []byte)([]byte, string, error){

	parsedCert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, "", err
	}

	parsedCACert, err := x509.ParseCertificate(caCerts)
	if err != nil {
		return nil, "", err
	}

	p := uuid.New()

	// TODO: CONSIDER WHETHER PASSWORD SHOULD BE CONFIGURABLE 
	// TODO: CONSIDER BUILDING ENCODE FUNCTION
	pfxData, err := pkcs12.Encode(rand.Reader, private, parsedCert, []*x509.Certificate{parsedCACert},  "")
	return pfxData, p.String(), err
}