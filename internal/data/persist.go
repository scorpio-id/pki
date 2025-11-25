package data

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/pki/internal/config"
)

type Persistence struct {
	Client  *redis.Client
	Context context.Context
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
        fmt.Println(err.Error())
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