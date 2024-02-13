package client

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jarcoal/httpmock"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"
)

const (
	JWKS = `{
		"keys": [
			{
				"use": "sig",
				"kty": "RSA",
				"kid": "fd3b991d-1834-4cbf-b8b4-db0d8116aeee",
				"alg": "RS256",
				"n": "7HhIYn1HDd84zXP519F6CoH9ZvsC5KG6F39AW11ObjH9V1gJL991XKNl0NVhh0_g98duiFz8-HDWjoVM1Xz8pvqBTmsDwMvKCZPezWmLJe3HAQZMIIAkdS0AFWs0a2vWVKbZp_nrtPSUQgTDejjbgOCdiF23cRuJMraVHqTWB8MqQWHypvDJ48moqq7ddFVCLDZXrAVTfTED074VfDeRy4qncn9Bm-DJZDx7MBvXR1iU1IBSliiObyB4sdb8HpkoJ4ibNLEIaKCuTyPIKsvCNeynzo84rAxD1sOG7xM6mwZvN1y2N1_7EJ2Cdmf287gLeSdJ146MUby_H5YJ59Zsdw",
				"e": "AQAB"
			}
		]
	}`

	ACCESSTOKEN = `{
		"access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZkM2I5OTFkLTE4MzQtNGNiZi1iOGI0LWRiMGQ4MTE2YWVlZSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJpbXBvcnRhbnQtcmVzb3VyY2Utc2VydmVyIiwiZXhwIjo0ODYzNjIzNTgyLCJpYXQiOjE3MDc4NjM1ODIsImlzcyI6Imh0dHBzOi8vc2NvcnBpby5pby9qd2tzIiwianRpIjoiOWE5ZDIwN2EtNGY5OS00NGFjLWIyYWUtMTBmNDE2NWZhNzRmIiwibmJmIjoxNzA3ODYzNTczLCJzdWIiOiJzY29ycGlvIn0.j10Rw9FNsn0nxY_1EmhzCGmMdLPBVw-Usuw-Qx2-aqFVyvOJeu3WwP7nwn09GNC_KKhB8pdw8ovTjLwMF_TIdc7NghRf2qozV2HufbfD6ocIjsaMrQmR_vbn7w-LV71H3cWHViFfieIDo4Bhrb7zgUyQ7fOh3MyaQ6EPqJmQnlyWmEfkzZ-VP1BaMuqq0KC4V0P5U2Gj8CtHFCDs-b53NvnsPnVP0YLD7y5yQ4y_MtUtNzklB2gxri6YwsX5-R9Q__LBBvLkiZXobad6ZoOzD4jvZfduxRP4diX67w0_7V9CJGAOkVIWENDXqsmKreNR-saB6cUWLUDd0K04m6g9Ig",
		"token_type": "bearer",
		"expires_in": 3155760000
	}`
)

func TestX509ClientWithCredentials(t *testing.T) {
	// set up HTTPMock for OAuth server
	// use the below statement to bypass endpoints which are not explicitly mocked
	httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://scorpio.io/jwks",
		httpmock.NewStringResponder(200, JWKS))

	httpmock.RegisterResponder("POST", "https://scorpio.io/token?client_id=scorpio&grant_type=client_credentials",
		httpmock.NewStringResponder(200, ACCESSTOKEN))

	// start the PKI server
	// note that test.yml config has *.example.com as allowed SANs
	cfg := config.NewConfig("../../internal/config/test.yml")

	s := signatures.NewSigner(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/certificate", s.CSRHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	// create an RSA identity for the client
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// create HTTP client for testing purposes
	transport := &http.Client{}

	// create x509 client
	xclient := NewX509Client(server.URL + "/certificate", priv, transport)

	jwt, err := xclient.AuthenticateCredentials("https://scorpio.io", "scorpio")
	if err != nil {
		log.Fatal(err)
	}
	
	sans := []string{"myapp.example.com"}

	// cert is ignored element here
	_, err = xclient.GetCertificate(sans, jwt)
	if err != nil {
		log.Fatal(err)
	}
}
