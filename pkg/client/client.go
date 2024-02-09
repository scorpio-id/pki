package client

import (
	"crypto/rand"
	"crypto/rsa"
    "bytes"
    "mime/multipart"
    "net/http"
    "io/ioutil"

	"github.com/scorpio-id/pki/pkg/certificate"
)

type X509Client struct {
	certificateAuthorityURL string
	private                 *rsa.PrivateKey
}

func NewX509Client(certificateAuthorityURL string) *X509Client {
	// create 2048 RSA key pair
	keys, _ := rsa.GenerateKey(rand.Reader, 2048)

	return &X509Client{
		certificateAuthorityURL: certificateAuthorityURL,
		private: keys,
	}
}

func (client *X509Client) Authenticate() error {
	// TODO - add OAuth here
	return nil
}

func (xclient *X509Client) GetCertificate(sans []string) (string, error) {
	// generate CSR
	csr, err := certificate.GenerateCSR(sans, 2048)
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

    req.Header.Set("Content-Type", writer.FormDataContentType())

    res, err := client.Do(req)
    if err != nil {
    	return "", err
    }

    defer res.Body.Close()

    body, err := ioutil.ReadAll(res.Body)
    if err != nil {
		return "", err
    }

	return string(body), nil
}