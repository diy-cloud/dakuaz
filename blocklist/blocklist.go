package blocklist

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/snowmerak/dakuaz/dakuaz"
)

var client *redis.Client

var ctx, cancel = context.WithTimeout(context.Background(), time.Second*10)

func init() {
	url := os.Getenv("BLOCKLIST_URL")

	client = redis.NewClient(&redis.Options{
		Addr:     url,
		Password: "",
		DB:       0,
	})
}

func Register(key [dakuaz.DakuazSize]byte) error {
	d := dakuaz.Deserialize(key)
	if stats := client.Set(ctx, toString(d.Token[:]), toString(d.Hash[:]), 0); stats.Err() != redis.Nil {
		return fmt.Errorf("blocklist.Register: %w", stats.Err())
	}
	if boolStats := client.ExpireAt(ctx, toString(d.Token[:]), time.Unix(d.ExpireAt, 0)); boolStats.Err() != redis.Nil {
		return fmt.Errorf("blocklist.Register: %w", boolStats.Err())
	}
	return nil
}

func IsExists(key [dakuaz.TokenSize]byte) error {
	if stats := client.Get(ctx, toString(key[:])); stats.Err() != nil {
		if stats.Err() == redis.Nil {
			return nil
		}
		return fmt.Errorf("blocklist.IsExists: %w", stats.Err())
	}
	return fmt.Errorf("blocklist.IsExists: token is exists")
}

func toString(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
