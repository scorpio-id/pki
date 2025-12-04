package data

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/scorpio-id/pki/internal/config"
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
	CommonName             string         `json:"common_name" redis:"common_name"`
	SubjectAlternateNames  []string       `json:"subject_alternate_names" redis:"subject_alternate_names"`
	SerialNumber           int64          `json:"serial_number" redis:"serial_number"`
	PublicKey              *rsa.PublicKey `json:"public_key" redis:"public_key"`
	IssuedDate             time.Time      `json:"issued" redis:"issued"`
	ExpirationDate         time.Time      `json:"expires" redis:"expires"`
	IsCertificateAuthority bool           `json:"is_certificate_authority" redis:"certificate_authority"`
}

func NewCertificateStore(cfg config.Config) *CertificateStore {

	return &CertificateStore{
		Data:    make([]CertificateMetadata, 0),
		Revoked: make([]CertificateMetadata, 0),
		Persist: NewPersistenceClient(cfg),
	}
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
	metadata := CertificateMetadata {
		CommonName: cert.Subject.CommonName,
		SubjectAlternateNames: cert.DNSNames,
		SerialNumber: cert.SerialNumber.Int64(),
		PublicKey: public,
		IssuedDate: cert.NotBefore,
		ExpirationDate: cert.NotAfter,
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
	metadata := CertificateMetadata {
		CommonName: cert.Subject.CommonName,
		SubjectAlternateNames: cert.DNSNames,
		SerialNumber: cert.SerialNumber.Int64(),
		PublicKey: public,
		IssuedDate: cert.NotBefore,
		ExpirationDate: cert.NotAfter,
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
