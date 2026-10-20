package sessions

import (
	"context"
	"errors"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type Repository interface {
	Create(ctx context.Context, newSession NewSession) (Session, error)
	FindBySecretHash(ctx context.Context, secretHash []byte) (Session, error)
	Touch(ctx context.Context, sessionID string, lastActivityAt, idleExpiresAt time.Time) (Session, error)
}
