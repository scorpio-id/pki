package main

import(
	"log"
	"net/http"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/transport"
	"github.com/scorpio-id/pki/docs"

)

//	@title			Scorpio PKI Service
//	@version		1.0
//	@description	A configurable X509 Certificate Authority management tool implemented in Go.
//  @termsOfService http://swagger.io/terms/

//  @securityDefinitions.oauth2 OAuth2

//  @contact.name API Support
//  @contact.url http://www.swagger.io/support
//  @contact.email support@swagger.io
//	@license.name	MIT
//	@license.url	https://mit-license.org

//	@BasePath		/
func main() {
	// parse local config (could be added as cmd line arg)
	cfg := config.NewConfig("internal/config/local.yml")

	// configuring swagger documentation
	docs.SwaggerInfo.Host = cfg.Server.Host + ":" + cfg.Server.Host

	// create a new mux router
	router := transport.NewRouter(cfg)

	// start the server
	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
}