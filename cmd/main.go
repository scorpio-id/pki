package main

import (
	"log"
	"context"
	"net/http"
	"runtime"

	"github.com/scorpio-id/pki/docs"
	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/transport"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

// @BasePath		/
func main() {
	// parse local config (could be added as cmd line arg)
	cfg := config.NewConfig("internal/config/local.yml")

	// configuring swagger documentation
	docs.SwaggerInfo.Host = cfg.Server.Host + ":" + cfg.Server.Port

	// create a new mux router
	router, httpRouter := transport.NewRouters(cfg)

	if runtime.GOOS == "linux" {
		certFilePath := cfg.Root.Install.Path + "/" + cfg.Root.Install.CertFilename
		privateKeyFilePath := cfg.Root.Install.Path + "/" + cfg.Root.Install.PrivateKeyFilename

		// start the server with TLS
		go func (){
			log.Fatal(http.ListenAndServeTLS(":"+cfg.Server.Port, certFilePath, privateKeyFilePath, router))
		}()

		log.Fatal(http.ListenAndServe(":80", httpRouter))

		
	} else {
		// run the MCP server over stdin/stdout until the client disconnects
		server := transport.NewMCPServer()

		go func() {
			log.Default().Println("starting mcp server ...")
			if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
				log.Fatal(err)
			}
		}()
		
		log.Default().Println("starting http server ...")
		log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
	}
}
