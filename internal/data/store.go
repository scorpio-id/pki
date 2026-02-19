package data

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/pki/internal/config"
	"github.com/scorpio-id/pki/pkg/certificate"
	"software.sslmate.com/src/go-pkcs12"
)

// new certificate metadata store implementation
type CertificateStore struct {
	Data    []CertificateMetadata `json:"certificate_data"`
	Revoked []CertificateMetadata `json:"revoked"`
	Persist Persistence
	mu      sync.Mutex
}

// TODO apply Redis struct tags: https://redis.io/docs/latest/develop/clients/go/#connect
type CertificateMetadata struct {
	CommonName             string         `json:"common_name"`
	SubjectAlternateNames  []string       `json:"subject_alternate_names"`
	SerialNumber           *big.Int       `json:"serial_number"`
	PublicKey              *rsa.PublicKey `json:"public_key"`
	IssuedDate             time.Time      `json:"issued"`
	ExpirationDate         time.Time      `json:"expires"`
	IsCertificateAuthority bool           `json:"is_certificate_authority"`
}

func NewCertificateStore(cfg config.Config) *CertificateStore {

	return &CertificateStore{
		Data:    make([]CertificateMetadata, 0),
		Revoked: make([]CertificateMetadata, 0),
		Persist: NewPersistenceClient(cfg),
	}
}

func (store *CertificateStore) Populate() error {
	// TODO query all redis entries using the persistance client with the 'certificate' key (ie: GetAll) marshal results
	// into metadata structs and add to certificate store.

	data, err := store.Persist.GetAllCertificateMetadata()
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	store.Data = data

	return nil
}

func (store *CertificateStore) LoadRootX509(id *big.Int) (*x509.Certificate, error) {
	// Check if persistence enabled, and if so repopulate root CA x509
	if store.Persist.cfg.Persistence.Enabled {
		root, err := store.Persist.GetX509(id)
		if err == redis.Nil {
			log.Default().Printf("No existing x509 detected, generating & storing new x509 with id [%d]", id)

			// load RSA keypair
			private, err := store.LoadKeyPair(id)
			if err != nil {
				log.Fatal(err)
			}

			duration, err := time.ParseDuration(store.Persist.cfg.PKI.CertificateTTL)
			if err != nil {
				log.Fatal(err)
			}

			cert, err := certificate.GenerateRootCertificate(store.Persist.cfg, private, duration)
			if err != nil {
				log.Fatal(err)
			}

			err = store.AddX509Metadata(cert)
			if err != nil {
				log.Fatal(err)
			}

			current, err := x509.ParseCertificate(cert)
			if err != nil {
				log.Fatal(err)
			}

			err = store.Persist.SetX509(current)
			if err != nil {
				return nil, err
			}

			return current, nil

		} else if err != nil {
			return nil, err
		}

		return root, nil
	}

	// load RSA keypair
	private, err := store.LoadKeyPair(id)
	if err != nil {
		log.Fatal(err)
	}

	duration, err := time.ParseDuration(store.Persist.cfg.PKI.CertificateTTL)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := certificate.GenerateRootCertificate(store.Persist.cfg, private, duration)
	if err != nil {
		log.Fatal(err)
	}

	x509, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatal(err)
	}

	return x509, nil
}

// LoadWebX509AndPrivateKey is used to retrieve x509 and private key data for local web server HTTPS
func (store *CertificateStore) LoadWebX509AndPrivateKey(id *big.Int) (*rsa.PrivateKey, []byte, error) {
	private, err := store.Persist.GetRSAKeyPair(id)
	if err != nil {
		return nil, nil, err
	}

	cert, err := store.Persist.GetX509(id)
	if err != nil {
		return nil, nil, err
	}

	return private, cert.Raw, nil
}

func (store *CertificateStore) LoadKeyPair(id *big.Int) (*rsa.PrivateKey, error) {
	if !store.Persist.cfg.Persistence.Enabled {
		return rsa.GenerateKey(rand.Reader, store.Persist.cfg.PKI.RSABits)
	}

	stored, err := store.Persist.GetRSAKeyPair(id)

	// case: key doesn't exist in persistence store
	if err == redis.Nil {
		// start by creating a RSA public/private key pair
		private, err := rsa.GenerateKey(rand.Reader, store.Persist.cfg.PKI.RSABits)
		if err != nil {
			return nil, err
		}

		err = store.Persist.SetRSAKeyPair(private, id)
		if err != nil {
			return nil, err
		}

		return private, nil

	} else if err != nil {
		return nil, err
	}

	return stored, nil
}

func (store *CertificateStore) AddX509Metadata(der []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	// convert DER content into a *x509.Certificate
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	// ensure SANs comply with uniqueness policy
	err = store.CheckSANsUnique(cert.DNSNames)
	if err != nil {
		return err
	}

	// convert public key interface into a *rsa.PublicKey
	public, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("unable to convert RSA public key from interface")
	}

	// TODO - check if issued and expiration dates are correctly formatted
	metadata := CertificateMetadata{
		CommonName:             cert.Subject.CommonName,
		SubjectAlternateNames:  cert.DNSNames,
		SerialNumber:           cert.SerialNumber,
		PublicKey:              public,
		IssuedDate:             cert.NotBefore,
		ExpirationDate:         cert.NotAfter,
		IsCertificateAuthority: cert.IsCA,
	}

	// add to metadata cache
	store.Data = append(store.Data, metadata)

	// add to persistent store
	err = store.Persist.SetCertificateMetadata(metadata)
	if err != nil {
		return err
	}

	return nil
}

func (store *CertificateStore) AddPKCS12Metadata(der []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	// convert PKCS DER content into *x509.Certificate -- leaf only!
	_, cert, _, err := pkcs12.DecodeChain(der, "")
	if err != nil {
		return err
	}

	// ensure SANs comply with uniqueness policy
	err = store.CheckSANsUnique(cert.DNSNames)
	if err != nil {
		return err
	}

	// convert public key interface into a *rsa.PublicKey
	public, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("unable to convert RSA public key from interface")
	}

	// TODO - check if issued and expiration dates are correctly formatted
	metadata := CertificateMetadata{
		CommonName:             cert.Subject.CommonName,
		SubjectAlternateNames:  cert.DNSNames,
		SerialNumber:           cert.SerialNumber,
		PublicKey:              public,
		IssuedDate:             cert.NotBefore,
		ExpirationDate:         cert.NotAfter,
		IsCertificateAuthority: cert.IsCA,
	}

	store.Data = append(store.Data, metadata)

	return nil
}

// TODO implement
func (store *CertificateStore) Revoke(sans []string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	return nil
}

func (store *CertificateStore) CheckSANsUnique(names []string) error {

	// ensure SAN is free.
	for _, data := range store.Data {
		for _, san := range data.SubjectAlternateNames {
			for _, name := range names {
				// uniqueness check
				if name == san && name != "" {
					return fmt.Errorf("subject alternate name [%v] is already in use", san)
				}

				// if current SAN contains a wildcard create regex and match
				if strings.Contains(san, "*") {
					// ex: *.test.com must become regex .*.test.com
					match, err := regexp.MatchString("."+san, name)
					if err != nil {
						return err
					}

					if match {
						return fmt.Errorf("subject alternate name [%v] is already in use by [%v]", name, san)
					}
				}

				// checks if an existing issued certificate has a SAN under the desired wildcard SAN
				if strings.Contains(name, "*") {
					// ex: *.test.com must become regex .*.test.com
					match, err := regexp.MatchString("."+name, san)
					if err != nil {
						return err
					}

					if match {
						return fmt.Errorf("subject alternate name [%v] is already in use by [%v]", name, san)
					}
				}
			}
		}
	}

	return nil
}
