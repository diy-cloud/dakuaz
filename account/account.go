package account

import (
	"os"

	"github.com/go-pg/pg/v10"
)

var db *pg.DB

func init() {
	url := os.Getenv("ACCOUNT_DB_URL")

	db = pg.Connect(&pg.Options{
		Addr: url,
		User: "postgres",
	})
}
