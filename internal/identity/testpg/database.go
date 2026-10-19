//go:build integration

package testpg

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"

	platformpostgres "github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/migrations"
)

var (
	migrateOnce sync.Once
	migrateErr  error
)

func OpenDatabase(t *testing.T) *platformpostgres.DB {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := platformpostgres.Open(ctx, databaseURL, 10)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(db.Close)

	migrateOnce.Do(func() {
		migrator, err := migrations.Open(databaseURL)
		if err != nil {
			migrateErr = err
			return
		}
		defer func() { _, _ = migrator.Close() }()

		if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			migrateErr = err
		}
	})
	if migrateErr != nil {
		t.Fatalf("apply migrations: %v", migrateErr)
	}

	return db
}
