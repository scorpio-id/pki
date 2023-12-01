package main

import(
	"log"
	"net/http"

	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/internal/transport"
)

// @title Scorpio PKI Service
// @version 1.0
// @license.name MIT
// @license.url https://mit-license.org
// @host localhost
// @BasePath /
func main() {
	// parse local config (could be added as cmd line arg)
	cfg := config.NewConfig("internal/config/local.yml")

	// create a new mux router
	router := transport.NewRouter(cfg)

	// start the server
	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
}