package sessions_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
)

type memoryRepository struct {
	session   sessions.Session
	new       sessions.NewSession
	findErr   error
	touchErr  error
	touchedAt time.Time
}

func (r *memoryRepository) Create(_ context.Context, newSession sessions.NewSession) (sessions.Session, error) {
	r.new = newSession
	r.session = sessions.Session{
		ID:                "session-1",
		UserID:            newSession.UserID,
		Kind:              newSession.Kind,
		CreatedAt:         newSession.CreatedAt,
		LastActivityAt:    newSession.LastActivityAt,
		ExpiresAt:         newSession.ExpiresAt,
		AbsoluteExpiresAt: newSession.AbsoluteExpiresAt,
	}
	return r.session, nil
}

func (r *memoryRepository) FindBySecretHash(_ context.Context, secretHash []byte) (sessions.Session, error) {
	if r.findErr != nil {
		return sessions.Session{}, r.findErr
	}
	return r.session, nil
}

func (r *memoryRepository) Touch(_ context.Context, _ string, lastActivityAt, idleExpiresAt time.Time) (sessions.Session, error) {
	if r.touchErr != nil {
		return sessions.Session{}, r.touchErr
	}
	r.touchedAt = lastActivityAt
	r.session.LastActivityAt = lastActivityAt
	r.session.ExpiresAt = idleExpiresAt
	return r.session, nil
}

func TestCreateWebSessionReturnsOpaqueSecretAndPersistsOnlyItsHash(t *testing.T) {
	repository := &memoryRepository{}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	service := sessions.NewService(repository, sessions.Options{
		IdleTTL:     30 * 24 * time.Hour,
		AbsoluteTTL: 90 * 24 * time.Hour,
		Now:         func() time.Time { return now },
	})

	issued, err := service.CreateWebSession(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("CreateWebSession() error = %v", err)
	}

	if issued.Secret == "" {
		t.Fatal("secret is empty")
	}
	if len(issued.Secret) < 40 {
		t.Errorf("secret length = %d, want at least 40 characters", len(issued.Secret))
	}
	if string(repository.new.SecretHash) == issued.Secret {
		t.Error("repository received the plaintext secret")
	}
	expectedHash := sha256.Sum256([]byte(issued.Secret))
	if string(repository.new.SecretHash) != string(expectedHash[:]) {
		t.Error("repository did not receive the SHA-256 hash of the secret")
	}
	if repository.new.UserID != "user-1" {
		t.Errorf("userID = %q, want user-1", repository.new.UserID)
	}
	if repository.new.Kind != sessions.KindWeb {
		t.Errorf("kind = %q, want web", repository.new.Kind)
	}
	if !repository.new.ExpiresAt.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Errorf("ExpiresAt = %s, want %s", repository.new.ExpiresAt, now.Add(30*24*time.Hour))
	}
	if !repository.new.AbsoluteExpiresAt.Equal(now.Add(90 * 24 * time.Hour)) {
		t.Errorf("AbsoluteExpiresAt = %s, want %s", repository.new.AbsoluteExpiresAt, now.Add(90*24*time.Hour))
	}
}

func TestAuthenticateWebSessionSlidesActivityButNeverExceedsAbsoluteExpiry(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	repository := &memoryRepository{}
	service := sessions.NewService(repository, sessions.Options{
		IdleTTL:     30 * 24 * time.Hour,
		AbsoluteTTL: 40 * 24 * time.Hour,
		Now:         func() time.Time { return now },
	})
	issued, err := service.CreateWebSession(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("CreateWebSession() error = %v", err)
	}

	now = now.Add(20 * 24 * time.Hour)
	session, err := service.AuthenticateWebSession(context.Background(), issued.Secret)
	if err != nil {
		t.Fatalf("AuthenticateWebSession() error = %v", err)
	}
	if !session.ExpiresAt.Equal(issued.Session.AbsoluteExpiresAt) {
		t.Errorf("ExpiresAt = %s, want the absolute limit %s", session.ExpiresAt, issued.Session.AbsoluteExpiresAt)
	}

	now = now.Add(20*24*time.Hour + time.Second)
	if _, err := service.AuthenticateWebSession(context.Background(), issued.Secret); !errors.Is(err, sessions.ErrInvalidSession) {
		t.Errorf("AuthenticateWebSession() error = %v, want ErrInvalidSession", err)
	}
}

func TestAuthenticateWebSessionRejectsUnknownRevokedAndExpiredSessions(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		secret     string
		repository *memoryRepository
	}{
		{
			name:   "unknown",
			secret: "unknown-secret",
			repository: &memoryRepository{
				findErr: sessions.ErrSessionNotFound,
			},
		},
		{
			name:   "revoked",
			secret: "revoked-secret",
			repository: &memoryRepository{
				session: sessions.Session{
					ID:                "session-1",
					ExpiresAt:         now.Add(time.Hour),
					AbsoluteExpiresAt: now.Add(time.Hour),
					RevokedAt:         ptr(now.Add(-time.Minute)),
				},
			},
		},
		{
			name:   "expired",
			secret: "expired-secret",
			repository: &memoryRepository{
				session: sessions.Session{
					ID:                "session-1",
					ExpiresAt:         now.Add(-time.Second),
					AbsoluteExpiresAt: now.Add(time.Hour),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := sessions.NewService(test.repository, sessions.Options{
				IdleTTL:     time.Hour,
				AbsoluteTTL: 24 * time.Hour,
				Now:         func() time.Time { return now },
			})
			if _, err := service.AuthenticateWebSession(context.Background(), test.secret); !errors.Is(err, sessions.ErrInvalidSession) {
				t.Errorf("AuthenticateWebSession() error = %v, want ErrInvalidSession", err)
			}
		})
	}
}

func ptr[T any](value T) *T {
	return &value
}
