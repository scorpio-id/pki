package data

import (
	"context"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/pki/internal/config"
)

type Persistence struct {
	Client  *redis.Client
	Context context.Context
}

func NewPersistenceClient(cfg config.Config) Persistence {

	// TODO move password to Kube secrets
    rdb := redis.NewClient(&redis.Options{
        Addr:     cfg.Persistence.Host + ":" + cfg.Persistence.Port,
        Password: "", 
        DB:       cfg.Persistence.Database,
    })

	return Persistence {
		Client: rdb,
		Context: context.Background(),
	}

    // err := rdb.Set(ctx, "key", "value", 0).Err()
    // if err != nil {
    //     panic(err)
    // }

    // val, err := rdb.Get(ctx, "key").Result()
    // if err != nil {
    //     panic(err)
    // }
    // fmt.Println("key", val)

    // val2, err := rdb.Get(ctx, "key2").Result()
    // if err == redis.Nil {
    //     fmt.Println("key2 does not exist")
    // } else if err != nil {
    //     panic(err)
    // } else {
    //     fmt.Println("key2", val2)
    // }
    // Output: key value
    // key2 does not exist
}