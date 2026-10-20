//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testpg"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
	sessionspostgres "github.com/JonatanGarbuyo/lds-user-service/internal/sessions/postgres"
)

func createSessionUser(t *testing.T) string {
	t.Helper()
	db := testpg.OpenDatabase(t)

	var suffix [10]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("generate email suffix: %v", err)
	}
	email := fmt.Sprintf("sessions-%s@example.com", hex.EncodeToString(suffix[:]))
	var id string
	if err := db.Pool.QueryRow(
		context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id::text`,
		email,
		"$argon2id$test",
	).Scan(&id); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func TestRepositoryPersistsOnlyOpaqueSessionHashesAndSlidesActivity(t *testing.T) {
	db := testpg.OpenDatabase(t)
	userID := createSessionUser(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	service := sessions.NewService(sessionspostgres.NewRepository(db.Pool), sessions.Options{
		IdleTTL:     30 * 24 * time.Hour,
		AbsoluteTTL: 40 * 24 * time.Hour,
		Now:         clock,
	})

	issued, err := service.CreateWebSession(context.Background(), userID)
	if err != nil {
		t.Fatalf("CreateWebSession() error = %v", err)
	}

	var (
		storedKind   string
		storedHash   []byte
		storedUserID string
	)
	if err := db.Pool.QueryRow(
		context.Background(),
		`SELECT user_id::text, kind, secret_hash FROM sessions WHERE id = $1`,
		issued.Session.ID,
	).Scan(&storedUserID, &storedKind, &storedHash); err != nil {
		t.Fatalf("query stored session: %v", err)
	}
	if storedUserID != userID {
		t.Errorf("stored user_id = %q, want %q", storedUserID, userID)
	}
	if storedKind != "web" {
		t.Errorf("stored kind = %q, want web", storedKind)
	}
	if string(storedHash) == issued.Secret {
		t.Error("session secret was stored in plaintext")
	}
	if len(storedHash) != 32 {
		t.Errorf("stored hash length = %d, want 32", len(storedHash))
	}

	now = now.Add(10 * 24 * time.Hour)
	authenticated, err := service.AuthenticateWebSession(context.Background(), issued.Secret)
	if err != nil {
		t.Fatalf("AuthenticateWebSession() error = %v", err)
	}
	if authenticated.ID != issued.Session.ID {
		t.Errorf("authenticated session = %q, want %q", authenticated.ID, issued.Session.ID)
	}
	if !authenticated.LastActivityAt.Equal(now) {
		t.Errorf("LastActivityAt = %s, want %s", authenticated.LastActivityAt, now)
	}
	if !authenticated.ExpiresAt.Equal(issued.Session.AbsoluteExpiresAt) {
		t.Errorf("ExpiresAt = %s, want absolute %s", authenticated.ExpiresAt, issued.Session.AbsoluteExpiresAt)
	}

	now = now.Add(31 * 24 * time.Hour)
	if _, err := service.AuthenticateWebSession(context.Background(), issued.Secret); !errors.Is(err, sessions.ErrInvalidSession) {
		t.Errorf("expired session error = %v, want ErrInvalidSession", err)
	}
}

func TestRepositoryRejectsRevokedSessionsImmediately(t *testing.T) {
	db := testpg.OpenDatabase(t)
	userID := createSessionUser(t)
	service := sessions.NewService(sessionspostgres.NewRepository(db.Pool), sessions.Options{
		IdleTTL:     time.Hour,
		AbsoluteTTL: 24 * time.Hour,
	})

	issued, err := service.CreateWebSession(context.Background(), userID)
	if err != nil {
		t.Fatalf("CreateWebSession() error = %v", err)
	}
	if _, err := db.Pool.Exec(
		context.Background(),
		`UPDATE sessions SET revoked_at = now() WHERE id = $1`,
		issued.Session.ID,
	); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, err := service.AuthenticateWebSession(context.Background(), issued.Secret); !errors.Is(err, sessions.ErrInvalidSession) {
		t.Errorf("revoked session error = %v, want ErrInvalidSession", err)
	}
}
