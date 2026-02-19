package data

import (
	"context"
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
	cfg     config.Config
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

	// WARNING clearing db for testing purposes!
	fmt.Println("Flushing DB for testing purposes ...")
	err = rdb.FlushDB(context.Background()).Err()
	if err != nil {
		log.Fatal("Failed to flush DB!")
	}

	return Persistence{
		Client:  rdb,
		Context: context.Background(),
		cfg:     cfg,
	}
}

func (persist *Persistence) SetRSAKeyPair(private *rsa.PrivateKey, id *big.Int) error {
	// convert RSA key pair into a PEM-encoded string
	bytes := x509.MarshalPKCS1PrivateKey(private)
	block := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)

	// store RSA key value pair
	err := persist.Client.Set(persist.Context, "rsa:"+id.String(), string(block), 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (persist *Persistence) GetRSAKeyPair(id *big.Int) (*rsa.PrivateKey, error) {
	result, err := persist.Client.Get(persist.Context, "rsa:"+id.String()).Result()
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

func (persist *Persistence) SetX509(cert *x509.Certificate) error {
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
func (persist *Persistence) GetX509(id *big.Int) (*x509.Certificate, error) {
	result, err := persist.Client.Get(persist.Context, "certificate:"+id.String()).Result()
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

func (persist *Persistence) SetCertificateMetadata(metadata CertificateMetadata) error {

	// marshal metadata struct to json and store with gob: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
	result, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	err = persist.Client.Set(persist.Context, "metadata:"+metadata.SerialNumber.String(), result, 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (persist *Persistence) GetCertificateMetadata(id *big.Int) (*CertificateMetadata, error) {

	// unmarshal json gob bytes into struct: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
	var metadata CertificateMetadata
	result, err := persist.Client.Get(persist.Context, "metadata:"+id.String()).Result()
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(result), &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (persist *Persistence) GetAllCertificateMetadata() ([]CertificateMetadata, error) {

	// result, err := persist.Client.HGetAll(persist.Context, "metadata:*").Result()
	// TODO SCAN, then MGET with all keys
	// TODO check what the 0 value implies in the Scan() function
	var cursor uint64
	keys, cursor, err := persist.Client.Scan(persist.Context, cursor, "metadata:*", 0).Result()
	if err != nil {
		return nil, err
	}

	// WARNING this may result in a large function invocation!
	result, err := persist.Client.MGet(persist.Context, keys...).Result()

	// printing for visual
	// fmt.Println(string(result))

	var metadata []CertificateMetadata

	for _, entry := range result {

		// marshal the entry of type interface{} into a CertificateMetadata struct
		var template CertificateMetadata

		err = json.Unmarshal([]byte(entry.(string)), &template)
		if err != nil {
			return nil, err
		}

		metadata = append(metadata, template)
	}

	return metadata, nil
}
