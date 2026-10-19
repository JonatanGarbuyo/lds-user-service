//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testpg"
)

func uniqueEmail(t *testing.T) string {
	t.Helper()

	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("generate unique email: %v", err)
	}
	return fmt.Sprintf("repo-%s@example.com", hex.EncodeToString(suffix[:]))
}

func TestRepositoryCreatePersistsUser(t *testing.T) {
	db := testpg.OpenDatabase(t)
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

	var (
		storedEmail     string
		storedHash      string
		storedVerified  bool
		storedStatus    string
		storedCreatedAt time.Time
		storedUpdatedAt time.Time
	)
	err = db.Pool.QueryRow(
		context.Background(),
		`SELECT email, password_hash, email_verified, status, created_at, updated_at FROM users WHERE id = $1`,
		created.ID,
	).Scan(&storedEmail, &storedHash, &storedVerified, &storedStatus, &storedCreatedAt, &storedUpdatedAt)
	if err != nil {
		t.Fatalf("query stored user: %v", err)
	}
	if storedEmail != created.Email || storedHash != "$argon2id$test-hash" {
		t.Errorf("stored email/hash = %q/%q, want %q/%q", storedEmail, storedHash, created.Email, "$argon2id$test-hash")
	}
	if storedVerified {
		t.Error("stored email_verified = true, want false")
	}
	if storedStatus != string(identity.StatusActive) {
		t.Errorf("stored status = %q, want %q", storedStatus, identity.StatusActive)
	}
	if !storedCreatedAt.Equal(created.CreatedAt) || !storedUpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("stored timestamps = %v/%v, want %v/%v", storedCreatedAt, storedUpdatedAt, created.CreatedAt, created.UpdatedAt)
	}
}

func TestRepositoryRejectsDuplicateEmail(t *testing.T) {
	db := testpg.OpenDatabase(t)
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
	db := testpg.OpenDatabase(t)
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
	db := testpg.OpenDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	email := uniqueEmail(t)

	_, err := repository.Create(context.Background(), identity.NewUser{Email: email, PasswordHash: "hash"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	db.Close()

	reopened := testpg.OpenDatabase(t)
	_, err = identitypostgres.NewRepository(reopened.Pool).Create(context.Background(), identity.NewUser{Email: email, PasswordHash: "hash"})
	if !errors.Is(err, identity.ErrEmailAlreadyExists) {
		t.Fatalf("Create() after reopen error = %v, want ErrEmailAlreadyExists", err)
	}
}
