//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	platformpostgres "github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/migrations"
)

var (
	migrateOnce sync.Once
	migrateErr  error
)

func openTestDatabase(t *testing.T) *platformpostgres.DB {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := platformpostgres.Open(ctx, databaseURL, 4)
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

func uniqueEmail(t *testing.T) string {
	t.Helper()

	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("generate unique email: %v", err)
	}
	return fmt.Sprintf("repo-%s@example.com", hex.EncodeToString(suffix[:]))
}

func TestRepositoryCreatesAndFindsUser(t *testing.T) {
	db := openTestDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	email := uniqueEmail(t)

	created, err := repository.Create(context.Background(), identity.NewUser{
		Email:        email,
		PasswordHash: "$argon2id$test-hash",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == "" {
		t.Error("created.ID is empty")
	}
	if created.ID == email {
		t.Error("created.ID must be independent from the email")
	}
	if created.Email != email {
		t.Errorf("created.Email = %q, want %q", created.Email, email)
	}
	if created.EmailVerified {
		t.Error("created.EmailVerified = true, want false")
	}
	if created.Status != identity.StatusActive {
		t.Errorf("created.Status = %q, want %q", created.Status, identity.StatusActive)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("timestamps are zero")
	}

	found, err := repository.FindByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if found.ID != created.ID || found.Email != created.Email || found.Status != created.Status {
		t.Errorf("found = %+v, want the created user %+v", found, created)
	}
	if !found.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("found.CreatedAt = %v, want %v", found.CreatedAt, created.CreatedAt)
	}
}

func TestRepositoryReturnsNotFoundForUnknownEmail(t *testing.T) {
	db := openTestDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)

	_, err := repository.FindByEmail(context.Background(), uniqueEmail(t))
	if !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("FindByEmail() error = %v, want ErrUserNotFound", err)
	}
}

func TestRepositoryRejectsDuplicateEmail(t *testing.T) {
	db := openTestDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	email := uniqueEmail(t)

	if _, err := repository.Create(context.Background(), identity.NewUser{Email: email, PasswordHash: "hash"}); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	_, err := repository.Create(context.Background(), identity.NewUser{Email: email, PasswordHash: "other-hash"})
	if !errors.Is(err, identity.ErrEmailAlreadyExists) {
		t.Fatalf("second Create() error = %v, want ErrEmailAlreadyExists", err)
	}
}

func TestRepositoryRejectsConcurrentDuplicateCreates(t *testing.T) {
	db := openTestDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	email := uniqueEmail(t)

	const workers = 8
	results := make(chan error, workers)
	var start sync.WaitGroup
	start.Add(1)

	for range workers {
		go func() {
			start.Wait()
			_, err := repository.Create(context.Background(), identity.NewUser{Email: email, PasswordHash: "hash"})
			results <- err
		}()
	}

	start.Done()

	var created, duplicates int
	for range workers {
		err := <-results
		switch {
		case err == nil:
			created++
		case errors.Is(err, identity.ErrEmailAlreadyExists):
			duplicates++
		default:
			t.Errorf("Create() unexpected error = %v", err)
		}
	}

	if created != 1 || duplicates != workers-1 {
		t.Errorf("created = %d, duplicates = %d, want 1 and %d", created, duplicates, workers-1)
	}
}

func TestRepositoryPersistsAcrossPoolReopen(t *testing.T) {
	db := openTestDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	email := uniqueEmail(t)

	created, err := repository.Create(context.Background(), identity.NewUser{Email: email, PasswordHash: "hash"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	db.Close()

	reopened := openTestDatabase(t)
	found, err := identitypostgres.NewRepository(reopened.Pool).FindByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("FindByEmail() after reopen error = %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, created.ID)
	}
}
