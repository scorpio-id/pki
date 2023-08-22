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
		SerialNumber         int      `yaml:"serial_number"`
		CSRMaxMemory         int      `yaml:"csr_max_memory"`
		CertificateTTL       string   `yaml:"certificate_ttl"`
		AllowedNames         []string `yaml:"allowed_names"`
		CertificateAuthority struct {
			CommonName            string   `yaml:"common_name"`
		} `yaml:"certificate_authority"`
	} `yaml:"pki"`
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
