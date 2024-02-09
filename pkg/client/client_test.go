package client

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"

)

func TestX509ClientWithCredentials(t *testing.T) {
	// ----------- Starting PKI Server ----------------------

	// note that test.yml config has *.example.com as allowed SANs
	cfg := config.NewConfig("../../internal/config/test.yml")

	s := signatures.NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	// -----------------------------------------------------

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	xclient := NewX509Client("http://localhost:8081/certificate", priv)

	jwt, err := xclient.AuthenticateCredentials("http://localhost:8082", "scorpio")
	if err != nil {
		log.Fatal(err)
	}
	
	sans := []string{"myapp.example.com"}
	cert, err := xclient.GetCertificate(sans, jwt)
	if err != nil {
		log.Fatal(err)
	}

	log.Print(cert)
}
