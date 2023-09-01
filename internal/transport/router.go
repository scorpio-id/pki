package transport

import (
	"net/http"
	"github.com/gorilla/mux"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"
)


// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config) *mux.Router{

	router := mux.NewRouter()

	signer := signatures.NewSigner(cfg)

	router.HandleFunc("/certificate", signer.CSRHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/p12", signer.PKCSHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/public", signer.PublicHandler).Methods(http.MethodGet, http.MethodOptions)

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware {
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		router.Use(om.Middleware)
	}

	return router
}