package signatures

import "net/http"

// Generates RSA Public & Private Key Pair and signs

// Creates Certificates and signes certificate
func SignCertificate(w http.ResponseWriter, r *http.Request){

	// TODO: Use signer to approve CSR

	w.WriteHeader(http.StatusAccepted)
}