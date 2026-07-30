package transport

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/gorilla/mux"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	_ "github.com/scorpio-id/pki/docs"
	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// NewRouters creates a new mux router with applied server
func NewRouters(cfg config.Config) (*mux.Router, *mux.Router) {
	router := mux.NewRouter()

	signer := signatures.NewSigner(cfg)

	// adding swagger endpoint
	router.PathPrefix("/swagger").Handler(httpSwagger.Handler(
		httpSwagger.URL("https://ca.scorpio.ordinarycomputing.com:"+cfg.Server.Port+"/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	)).Methods(http.MethodGet)

	router.HandleFunc("/certificate", signer.CSRHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/p12", signer.PKCSHandler).Methods(http.MethodPost, http.MethodOptions)

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware{
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		router.Use(om.Middleware)
	}

	// install CA certificates locally if target OS is linux
	if runtime.GOOS == "linux" {
		private, webCert, err := signer.ObtainWebServerIdentity(cfg)
		if err != nil {
			log.Fatal(err)
		}

		// FIXME private key does not match, tls error!
		if private == nil {
			fmt.Println("private is nil!")
		}

		if webCert == nil {
			fmt.Println("web cert is nil!")
		}

		// install certificates
		err = InstallX509(private, webCert)
		if err != nil {
			log.Fatal(err)
		}
	}

	// generate keytab for SPNEGO handler
	if runtime.GOOS == "linux" {
		httpRouter := mux.NewRouter()

		err := signer.GenerateKeytab(cfg)
		if err != nil {
			log.Fatal(err)
		}

		// instantiate SPNEGO authentication for PKI SPN
		kt, err := keytab.Load(cfg.Spnego.Volume + "/" + cfg.Spnego.Keytab)
		if err != nil {
			log.Fatal(err)
		}

		// TODO convert to structured JSON logs
		l := log.New(os.Stderr, "PKI SPNEGO: ", log.Ldate|log.Ltime|log.Lshortfile)

		h := spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(signer.SPNEGOHandler), kt, service.Logger(l), service.DecodePAC(false))

		httpRouter.HandleFunc("/spnego", h.ServeHTTP).Methods(http.MethodPost, http.MethodOptions).Schemes("http")
		httpRouter.HandleFunc("/public", signer.PublicHandler).Methods(http.MethodGet, http.MethodOptions).Schemes("http")

		// create subrouter for CORS-enabled UIs
		subr := router.PathPrefix("/ui").Subrouter()

		// config endpoint for console
		subr.HandleFunc("/config", cfg.ConfigHandler).Methods(http.MethodGet, http.MethodOptions)

		// metadata endpoint for console UI
		subr.HandleFunc("/metadata", signer.CertificateStoreHandler).Methods(http.MethodGet, http.MethodOptions)

		// enable CORS
		subr.Use(mux.CORSMethodMiddleware(subr))

		return router, httpRouter
	}

	return router, nil
}
