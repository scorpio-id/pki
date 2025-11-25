package config

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// TODO - add version property
// TODO - add to OU, Region, etc to Certificate Authority struct
// Config provides a template for marshalling .yml configuration files
type Config struct {
	Server struct {
		Port string `yaml:"port" json:"port"`
		Host string `yaml:"host" json:"host"`
	} `yaml:"server" json:"server"`
	Persistence struct {
		Enabled  bool   `yaml:"enabled" json:"enabled"`
		Port     string `yaml:"port" json:"port"`
		Host     string `yaml:"host" json:"host"`
		Password string `yaml:"password" json:"password"`
		Database int    `yaml:"database" json:"database"`
	} `yaml:"persistence" json:"persistence"`
	PKI struct {
		RSABits              int      `yaml:"rsa_bits" json:"rsa_bits"`
		CSRMaxMemory         int      `yaml:"csr_max_memory" json:"csr_max_memory"`
		SerialNumber         int64    `yaml:"serial_number" json:"serial_number"`
		CertificateTTL       string   `yaml:"certificate_ttl" json:"certificate_ttl"`
		AllowedNames         []string `yaml:"allowed_names" json:"allowed_names"`
		CertificateAuthority struct {
			CommonName string `yaml:"common_name" json:"common_name"`
		} `yaml:"certificate_authority" json:"certificate_authority"`
	} `yaml:"pki" json:"pki"`
	OAuth struct {
		Enabled        bool     `yaml:"enabled" json:"enabled"`
		TrustedIssuers []string `yaml:"trusted_issuers" json:"trusted_issuers"`
	} `yaml:"oauth" json:"oauth"`
	Root struct {
		Country            string   `yaml:"country" json:"country"`	
		Organization       string   `yaml:"org" json:"org"`	
		OrganizationalUnit string   `yaml:"ou" json:"ou"`	
		Locality           string   `yaml:"locality" json:"locality"`	
		Province           string   `yaml:"province" json:"province"`	
		StreetAddress      string   `yaml:"address" json:"address"`	
		PostalCode         string   `yaml:"postal" json:"postal"`	
		CommonName         string   `yaml:"cn" json:"cn"`	
		SANs               []string `yaml:"sans" json:"sans"`
		Install struct{
			Path               string `yaml:"path" json:"path"`
			CertFilename       string `yaml:"cert_filename" json:"cert_filename"`
			PrivateKeyFilename string `yaml:"private_filename" json:"private_filename"`
		} `yaml:"install" json:"install"`
	} `yaml:"root" json:"root"`
	Spnego struct{
		ServicePrincipal string `yaml:"service_principal" json:"service_principal"`
		Password         string `yaml:"password" json:"-"`
		Realm            string `yaml:"realm" json:"realm"`
		Volume           string `yaml:"volume" json:"volume"`
		Keytab           string `yaml:"keytab" json:"keytab"`
	} `yaml:"spnego" json:"spnego"`
}


// NewConfig takes a .yml filename from the same /config directory, and returns a populated configuration
func NewConfig(s string) Config {
	f, err := os.Open(s)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)

	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	return cfg
}

func (conf *Config) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	// FIXME move CORS URLs to config
	// check CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "*")
        return
    }

	// return JSON representation of client id store
	w.Header().Set("Content-Type", "application/json")

	content, err := json.Marshal(conf)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	w.Write(content)
}
