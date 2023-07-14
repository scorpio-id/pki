package signatures

import (
	"encoding/json"
	"net/http"

	"github.com/scorpio-id/pki/pkg/pki/certificate"
)

// Generates RSA Public & Private Key Pair and signs

type Signer struct{
	// Access to Known SARS
	// Keys Saved
}


// Handler for Certificate Signing Requests,
// Creates and Verifies to create a X.509 certificates 
func HandleCSR(w http.ResponseWriter, r *http.Request){

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
    }

	r.Body = http.MaxBytesReader(w, r.Body, 1000000) // Each Request at max takes 1 KB

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var c certificate.CSR

	err := decoder.Decode(&c)
	if err != nil{
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func SignCSR(csr certificate.CSR){
	// Check CSR if SAR is taken
	// Fail otherwise
	// Create X.509 signed with Private keys 
}