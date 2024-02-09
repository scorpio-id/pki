package client

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/scorpio-id/pki/pkg/certificate"
)

type X509Client struct {
	certificateAuthorityURL string
	private                 *rsa.PrivateKey
}

func NewX509Client(certificateAuthorityURL string, private *rsa.PrivateKey) *X509Client {
	return &X509Client{
		certificateAuthorityURL: certificateAuthorityURL,
		private: private,
	}
}

func (xclient *X509Client) AuthenticateCredentials(issuerURL, clientId string) (string, error) {
	endpoint := "/token?client_id=" + clientId + "&grant_type=client_credentials"

	client := &http.Client{}
	
	req, err := http.NewRequest("POST", issuerURL + endpoint, nil)
	if err != nil {
	  return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
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

func (xclient *X509Client) GetCertificate(sans []string, jwt string) (string, error) {
	// generate CSR
	csr, err := certificate.GenerateCSRWithPrivateKey(sans, xclient.private)
	if err != nil {
		return "", err
	}

	payload := &bytes.Buffer{}
    writer := multipart.NewWriter(payload)

    _ = writer.WriteField("csr", string(csr))

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