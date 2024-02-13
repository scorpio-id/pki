package client

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/scorpio-id/pki/pkg/certificate"
)

// X509Client is a default client for X509 certificate services
type X509Client struct {
	certificateAuthorityURL string
	private                 *rsa.PrivateKey
	transport               *http.Client
}

func NewX509Client(certificateAuthorityURL string, private *rsa.PrivateKey, transport *http.Client) *X509Client {
	return &X509Client{
		certificateAuthorityURL: certificateAuthorityURL,
		private: private,
		transport: transport,
	}
}

// AuthenticateCredentials performs a client credentials OAuth grant for a JWT given an issuer URL and a client ID
func (xclient *X509Client) AuthenticateCredentials(issuerURL, clientID string) (string, error) {
	endpoint := "/token?client_id=" + clientID + "&grant_type=client_credentials"
	
	req, err := http.NewRequest("POST", issuerURL + endpoint, nil)
	if err != nil {
	  return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := xclient.transport.Do(req)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	content :=  make(map[string]string)
	json.Unmarshal(body, &content)

	return content["access_token"], nil
}

// GetCertificate generates a signed x509 certificate given SANs and an OAuth JWT
func (xclient *X509Client) GetCertificate(sans []string, jwt string) (string, error) {
	// generate CSR
	csr, err := certificate.GenerateCSRWithPrivateKey(sans, xclient.private)
	if err != nil {
		return "", err
	}

	// CSR byte slice is originally ASN.1 encoding, convert to PEM
	block := pem.Block{
		Type:  "NEW CERTIFICATE REQUEST",
		Bytes: csr,
	}

	payload := &bytes.Buffer{}
    writer := multipart.NewWriter(payload)

    _ = writer.WriteField("csr", string(pem.EncodeToMemory(&block)))

	// writer must be closed to correctly calculate boundary in multipart form request header
	writer.Close()

    client := &http.Client{}
    req, err := http.NewRequest("POST", xclient.certificateAuthorityURL, payload)
    if err != nil {
    	return "", err
    }

	req.Header.Set("Authorization", "Bearer " + jwt)
    req.Header.Set("Content-Type", writer.FormDataContentType())

    res, err := client.Do(req)
    if err != nil {
    	return "", err
    }

    defer res.Body.Close()

    body, err := io.ReadAll(res.Body)
    if err != nil {
		return "", err
    }

	return string(body), nil
}