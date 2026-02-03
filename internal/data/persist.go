package data

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/pki/internal/config"
)

type Persistence struct {
	Client  *redis.Client
	Context context.Context
    cfg  config.Config
}

func NewPersistenceClient(cfg config.Config) Persistence {

    // TODO read documentation on rdb.Close() usage
    rdb := redis.NewClient(&redis.Options{
        Addr:     cfg.Persistence.Host + ":" + cfg.Persistence.Port,
        Username: cfg.Persistence.User,
        Password: cfg.Persistence.Password, 
        DB:       cfg.Persistence.Database,
        // TODO enable TLS for redis >_>;
        TLSConfig: &tls.Config{InsecureSkipVerify: true},
    })

    // Test the connection with a Ping command
	pong, err := rdb.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

    // TODO remove print statement!
    fmt.Println("Connected to Redis! Response:", pong)

    return Persistence {
		Client:  rdb,
		Context: context.Background(),
        cfg:     cfg,
	}
}

func (persist *Persistence) SetRSAKeyPair(private *rsa.PrivateKey) error {
    // convert RSA key pair into a PEM-encoded string
    bytes := x509.MarshalPKCS1PrivateKey(private)
    block := pem.EncodeToMemory(
                &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: bytes,
                },
            )
  
    // store RSA key value pair
    err := persist.Client.Set(persist.Context, "rsa", string(block), 0).Err()
    if err != nil {
        return err
    }
    
    return nil
}

func (persist *Persistence) GetRSAKeyPair() (*rsa.PrivateKey, error) {
    result, err := persist.Client.Get(persist.Context, "rsa").Result()
    if err != nil {
        return nil, err
    }

    // convert PEM-encoded string back into *rsa.PrivateKey interface
    block, _ := pem.Decode([]byte(result))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    
    return private, nil
}

func (persist *Persistence) Setx509(cert *x509.Certificate) error {
    sserial := cert.SerialNumber.String()

	certBlock := pem.EncodeToMemory(
        &pem.Block{
		    Type:  "CERTIFICATE",
		    Bytes: cert.Raw,
	    },
    )

    err := persist.Client.Set(persist.Context, "certificate:"+sserial, string(certBlock), 0).Err()
    if err != nil {
        return err
    }

    return nil
}
func (persist *Persistence) Getx509(id *big.Int) (*x509.Certificate, error) {
    result, err := persist.Client.Get(persist.Context,"certificate:" + id.String()).Result()
    if err != nil {
        return nil, err
    }

    // convert PEM-encoded string back into *x509.Certificate interface
    block, _ := pem.Decode([]byte(result))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the certificate")
    }

    return x509.ParseCertificate(block.Bytes)
}

// TODO implement root CA x509 loading for persistence.
func (persist *Persistence) LoadRootCAx509(current *x509.Certificate) (*x509.Certificate, error) {
    // Check if persistence enabled, and if so repopulate root CA x509
	if persist.cfg.Persistence.Enabled {
		root, err := persist.Getx509(big.NewInt(persist.cfg.PKI.SerialNumber))
		if err == redis.Nil {
			log.Default().Println("No existing root x509 detected ... generating & storing new root x509.")
            err = persist.Setx509(current)
            if err != nil {
                return nil, err
            }

            return current, nil

		} else if err != nil {
            return nil, err
        }

        return root, nil
	}

    return current, nil
}

func (persist *Persistence) LoadKeyPair() (*rsa.PrivateKey, error) {
    if !persist.cfg.Persistence.Enabled {
        return rsa.GenerateKey(rand.Reader, persist.cfg.PKI.RSABits)
    }

	stored, err := persist.GetRSAKeyPair()

    // case: key doesn't exist in persistence store
    if err == redis.Nil {
        // start by creating a RSA public/private key pair
        private, err := rsa.GenerateKey(rand.Reader, persist.cfg.PKI.RSABits)
        if err != nil {
            return nil, err
        }

        err = persist.SetRSAKeyPair(private)
        if err != nil {
            return nil, err
        }

        return private, nil

    } else if err != nil {
        return nil, err
    }

    return stored, nil
}

func(persist *Persistence) SetCertificateMetadata(metadata CertificateMetadata) error {

    // marshal metadata struct to json and store with gob: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
    result, err := json.Marshal(metadata) 
    if err != nil {
        return err
    }
    
    err = persist.Client.Set(persist.Context, "metadata:" + metadata.SerialNumber.String(), result, 0).Err()
    if err != nil {
        return err
    }

    return nil
}

func (persist *Persistence) GetCertificateMetadata(id *big.Int) (*CertificateMetadata, error) {

    // unmarshal json gob bytes into struct: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
    var metadata CertificateMetadata
    result, err := persist.Client.Get(persist.Context, "metadata:" + id.String()).Result()
    if err != nil {
        return nil, err
    }

    err = json.Unmarshal([]byte(result), &metadata)
    if err != nil {
        return nil, err
    }

    return &metadata, nil
}
