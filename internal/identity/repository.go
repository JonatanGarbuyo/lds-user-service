package identity

import (
	"context"
	"time"
)

type UserCredentials struct {
	User         User
	PasswordHash string
}

type UserRepository interface {
	Create(ctx context.Context, newUser NewUser) (User, error)
	FindByEmail(ctx context.Context, email string) (User, error)
	FindCredentialsByEmail(ctx context.Context, email string) (UserCredentials, error)
	FindByID(ctx context.Context, userID string) (User, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type PasswordVerifier interface {
	Verify(password, encoded string) (bool, error)
}

type SecretHasher interface {
	Hash(secret string) (string, error)
	Verify(secret, encoded string) (bool, error)
}

type VerificationEmail struct {
	To        string
	Code      string
	ExpiresAt time.Time
}

type VerificationEmailSender interface {
	SendVerificationCode(ctx context.Context, message VerificationEmail) error
}

type VerificationChallenge struct {
	ID        string
	UserID    string
	Email     string
	CodeHash  string
	Attempts  int
	CreatedAt time.Time
	ExpiresAt time.Time
}

type EmailVerificationRepository interface {
	CreateChallenge(ctx context.Context, userID, codeHash string, now, expiresAt time.Time, resendCooldown time.Duration) (VerificationChallenge, error)
	DeleteChallenge(ctx context.Context, challengeID string) error
	FindActiveChallengeByEmail(ctx context.Context, email string, now time.Time, maxAttempts int) (VerificationChallenge, error)
	RecordFailedAttempt(ctx context.Context, challengeID string, now time.Time, maxAttempts int) error
	ConsumeAndVerify(ctx context.Context, challengeID string, now time.Time, maxAttempts int) (User, error)
}

type AbuseLimiter interface {
	Allow(key string) (bool, time.Duration)
}
