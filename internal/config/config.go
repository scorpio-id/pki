package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// TODO - add version property
// TODO - add to OU, Region, etc to Certificate Authority struct
// Config provides a template for marshalling .yml configuration files
type Config struct {
	Server struct {
		Port string `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"server"`
	PKI struct {
		RSABits              int      `yaml:"rsa_bits"`
		CSRMaxMemory         int      `yaml:"csr_max_memory"`
		SerialNumber         int64    `yaml:"serial_number"`
		CertificateTTL       string   `yaml:"certificate_ttl"`
		AllowedNames         []string `yaml:"allowed_names"`
		CertificateAuthority struct {
			CommonName string `yaml:"common_name"`
		} `yaml:"certificate_authority"`
	} `yaml:"pki"`
	OAuth struct {
		Enabled        bool     `yaml:"enabled"`
		TrustedIssuers []string `yaml:"trusted_issuers"`
	} `yaml:"oauth"`
	Root struct {
		Country string `yaml:"country"`	
		Organization string `yaml:"org"`	
		OrganizationalUnit string `yaml:"ou"`	
		Locality string `yaml:"locality"`	
		Province string `yaml:"province"`	
		StreetAddress string `yaml:"address"`	
		PostalCode string `yaml:"postal"`	
		CommonName string `yaml:"cn"`	
		SANs []string `yaml:"sans"`
		Install struct{
			Path string `yaml:"path"`
			CertFilename string `yaml:"cert_filename"`
			PrivateKeyFilename string `yaml:"private_filename"`
		} `yaml:"install"`
	} `yaml:"root"`
	Spnego struct{
		ServicePrincipal string `yaml:"service_principal"`
		Password         string `yaml:"password"`
		Realm            string `yaml:"realm"`
		Volume           string `yaml:"volume"`
		Keytab           string `yaml:"keytab"`
	} `yaml:"spnego"`
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
