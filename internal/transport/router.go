package transport

import (
	"net/http"
	"github.com/gorilla/mux"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"
)


// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config) *mux.Router{

	// create gorilla mux router
	router := mux.NewRouter()

	router.HandleFunc("/sign", signatures.SignCertificate).Methods(http.MethodPost, http.MethodOptions)


	return router
}