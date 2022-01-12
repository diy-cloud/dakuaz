package cache

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/snowmerak/dakuaz/dakuaz"
)

var ctx, cancel = context.WithTimeout(context.Background(), time.Second*10)

var client *redis.Client

func init() {
	url := os.Getenv("CACHE_URL")

	client = redis.NewClient(&redis.Options{
		Addr:     url,
		Password: "",
		DB:       0,
	})
}

func CompareAndSwap(prev [dakuaz.DakuazSize]byte, next [dakuaz.DakuazSize]byte) error {
	d := dakuaz.Deserialize(prev)
	cachedHash := client.Get(ctx, toString(d.Token[:]))
	if cachedHash.Err() != nil {
		if cachedHash.Err() == redis.Nil {
			goto REGISTER_NEW
		}
		return fmt.Errorf("cache.CompareAndSwap: %w", cachedHash.Err())
	}
	if cachedHash.Val() != toString(d.Hash[:]) {
		return fmt.Errorf("cache.CompareAndSwap: hash mismatch")
	}
REGISTER_NEW:
	d = dakuaz.Deserialize(next)
	if stats := client.Set(ctx, toString(d.Token[:]), toString(d.Hash[:]), 0); stats.Err() != nil {
		return fmt.Errorf("cache.CompareAndSwap: %w", stats.Err())
	}
	if boolStats := client.ExpireAt(ctx, string(d.Token[:]), time.Unix(d.ExpireAt, 0)); boolStats.Err() != nil {
		return fmt.Errorf("cache.CompareAndSwap: %w", boolStats.Err())
	}
	return nil
}

func toString(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
