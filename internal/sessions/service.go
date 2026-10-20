package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

const secretBytes = 32

var ErrInvalidSession = errors.New("invalid session")

type Options struct {
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	Now         func() time.Time
	Random      io.Reader
}

type Service struct {
	repository  Repository
	idleTTL     time.Duration
	absoluteTTL time.Duration
	now         func() time.Time
	random      io.Reader
}

func NewService(repository Repository, options Options) *Service {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &Service{
		repository:  repository,
		idleTTL:     options.IdleTTL,
		absoluteTTL: options.AbsoluteTTL,
		now:         options.Now,
		random:      options.Random,
	}
}

func (s *Service) CreateWebSession(ctx context.Context, userID string) (Issued, error) {
	now := s.now().UTC()
	absoluteExpiresAt := now.Add(s.absoluteTTL)
	idleExpiresAt := now.Add(s.idleTTL)
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}

	secret, err := newSecret(s.random)
	if err != nil {
		return Issued{}, err
	}

	created, err := s.repository.Create(ctx, NewSession{
		UserID:            userID,
		Kind:              KindWeb,
		SecretHash:        hashSecret(secret),
		CreatedAt:         now,
		LastActivityAt:    now,
		ExpiresAt:         idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
	})
	if err != nil {
		return Issued{}, fmt.Errorf("create web session: %w", err)
	}

	return Issued{Session: created, Secret: secret}, nil
}

func (s *Service) AuthenticateWebSession(ctx context.Context, secret string) (Session, error) {
	if !validSecret(secret) {
		return Session{}, ErrInvalidSession
	}

	now := s.now().UTC()
	session, err := s.repository.FindBySecretHash(ctx, hashSecret(secret))
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return Session{}, ErrInvalidSession
		}
		return Session{}, fmt.Errorf("find session: %w", err)
	}
	if session.RevokedAt != nil || !now.Before(session.ExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		return Session{}, ErrInvalidSession
	}

	idleExpiresAt := now.Add(s.idleTTL)
	if idleExpiresAt.After(session.AbsoluteExpiresAt) {
		idleExpiresAt = session.AbsoluteExpiresAt
	}

	touched, err := s.repository.Touch(ctx, session.ID, now, idleExpiresAt)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return Session{}, ErrInvalidSession
		}
		return Session{}, fmt.Errorf("touch session: %w", err)
	}
	if touched.RevokedAt != nil || !now.Before(touched.ExpiresAt) || !now.Before(touched.AbsoluteExpiresAt) {
		return Session{}, ErrInvalidSession
	}

	return touched, nil
}

func newSecret(random io.Reader) (string, error) {
	var buffer [secretBytes]byte
	if _, err := io.ReadFull(random, buffer[:]); err != nil {
		return "", fmt.Errorf("generate session secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer[:]), nil
}

func validSecret(secret string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	return err == nil && len(decoded) == secretBytes
}

func hashSecret(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}
