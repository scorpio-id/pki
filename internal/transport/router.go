package transport

import (
	"net/http"
	"github.com/gorilla/mux"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"
	"github.com/swaggo/http-swagger/v2"
	_ "github.com/scorpio-id/pki/docs"

)


// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config) *mux.Router{

	// FIXME: break into subroutes
	router := mux.NewRouter()

	signer := signatures.NewSigner(cfg)

	// adding swagger endpoint
	router.PathPrefix("/swagger").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://localhost:"+cfg.Server.Port+"/swagger/doc.json"), 
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	)).Methods(http.MethodGet)

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