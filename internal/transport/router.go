package transport

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/gorilla/mux"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	_ "github.com/scorpio-id/pki/docs"
	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/signatures"
	"github.com/swaggo/http-swagger/v2"
)

// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config) *mux.Router{

	// FIXME: break into subroutes
	router := mux.NewRouter()

	signer := signatures.NewSigner(cfg)

	// adding swagger endpoint
	router.PathPrefix("/swagger").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://ca.scorpio.ordinarycomputing.com:" + cfg.Server.Port + "/swagger/doc.json"), 
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

	// only install certificates locally if target OS is linux
	if runtime.GOOS == "linux" {
		// install certificates
		err := signer.SerializeX509()
		if err != nil {
			log.Fatal(err)
		}
	}

	// WARNING - scorpio kerberos service must have already created keytab on mounted volume prior to start
	// check for presence of keytab before init
	fmt.Printf("checking for mounted volume at: " + cfg.Spnego.Volume + "/" + cfg.Spnego.Keytab)
	for {
		_, err := os.Stat(cfg.Spnego.Volume + "/" + cfg.Spnego.Keytab)
		if err == nil {
			break
		} else {
			fmt.Printf("not found -- sleeping ...")
			time.Sleep(time.Second * 2)
		}
	}
	
	// instantiate SPNEGO authentication for PKI SPN
	kt, err := keytab.Load(cfg.Spnego.Volume + "/" + cfg.Spnego.Keytab)
	if err != nil {
		log.Fatal(err)
	}
	
	// TODO : get keytab file from Kerberos
	l := log.New(os.Stderr, "PKI SPNEGO: ", log.Ldate|log.Ltime|log.Lshortfile)

	h := spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(signer.SPNEGOHandler), kt, service.Logger(l))

	router.HandleFunc("/spnego", h.ServeHTTP).Methods(http.MethodPost, http.MethodOptions)

	fmt.Printf("PKI router ready!")

	return router
}