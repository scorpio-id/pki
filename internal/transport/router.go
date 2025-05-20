package transport

import (
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/scorpio-id/pki/pkg/certificate"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// NewRouters creates a new mux router with applied server
func NewRouters(cfg config.Config) (*mux.Router, *mux.Router){

	// FIXME: break into subroutes
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
	router.HandleFunc("/public", signer.PublicHandler).Methods(http.MethodGet, http.MethodOptions)

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware{
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		router.Use(om.Middleware)
	}

	// install CA certificates locally if target OS is linux
	if runtime.GOOS == "linux" {
		private, err := rsa.GenerateKey(rand.Reader, cfg.PKI.RSABits)
		if err != nil {
			log.Fatal(err)
		}
	
		csr, err := certificate.GenerateDomainClientCSR(cfg, private)
		if err != nil {
			log.Fatal(err)
		}

		webCert, err := signer.CreateX509(csr)
		if err != nil {
			log.Fatal(err)
		}				

		// install certificates
		err = SerializeX509(private, webCert)
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

		// TODO : get keytab file from Kerberos
		l := log.New(os.Stderr, "PKI SPNEGO: ", log.Ldate|log.Ltime|log.Lshortfile)

		h := spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(signer.SPNEGOHandler), kt, service.Logger(l), service.DecodePAC(false))

		httpRouter.HandleFunc("/spnego", h.ServeHTTP).Methods(http.MethodPost, http.MethodOptions).Schemes("http")

		return router, httpRouter
	}

	return router, nil
}

