package data

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/pki/internal/config"
)

type Persistence struct {
	Client  *redis.Client
	Context context.Context
    cfg  config.Config
}

func NewPersistenceClient(cfg config.Config) Persistence {

	// TODO move password to Kube secrets
    // TODO read documentation on rdb.Close() usage
    rdb := redis.NewClient(&redis.Options{
        Addr:     cfg.Persistence.Host + ":" + cfg.Persistence.Port,
        Password: "", 
        DB:       cfg.Persistence.Database,
    })

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

func (persist *Persistence) LoadKeyPair()(*rsa.PrivateKey, error){
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
    
    err = persist.Client.Set(persist.Context, "certificate:" + strconv.FormatInt(metadata.SerialNumber, 10), result, 0).Err()
    if err != nil {
        return err
    }

    return nil
}

func (persist *Persistence) GetCertificateMetadata(id int64) (*CertificateMetadata, error) {

    // unmarshal json gob bytes into struct: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
    var metadata CertificateMetadata
    result, err := persist.Client.Get(persist.Context, "certificate:" + strconv.FormatInt(id, 10)).Result()
    if err != nil {
        return nil, err
    }

    err = json.Unmarshal([]byte(result), &metadata)
    if err != nil {
        return nil, err
    }

    return &metadata, nil
}
