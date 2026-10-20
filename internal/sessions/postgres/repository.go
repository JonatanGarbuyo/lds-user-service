package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
)

const sessionColumns = `
	id::text, user_id::text, kind, created_at, last_activity_at,
	idle_expires_at, absolute_expires_at, revoked_at`

const (
	createSessionQuery = `
		INSERT INTO sessions (
			user_id, kind, secret_hash, created_at, last_activity_at,
			idle_expires_at, absolute_expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING` + sessionColumns

	findSessionBySecretHashQuery = `
		SELECT` + sessionColumns + `
		FROM sessions
		WHERE secret_hash = $1`

	touchSessionQuery = `
		UPDATE sessions
		SET last_activity_at = $2,
		    idle_expires_at = $3
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND $2 < idle_expires_at
		  AND $2 < absolute_expires_at
		RETURNING` + sessionColumns
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(ctx context.Context, newSession sessions.NewSession) (sessions.Session, error) {
	session, err := scanSession(r.pool.QueryRow(
		ctx,
		createSessionQuery,
		newSession.UserID,
		string(newSession.Kind),
		newSession.SecretHash,
		newSession.CreatedAt,
		newSession.LastActivityAt,
		newSession.ExpiresAt,
		newSession.AbsoluteExpiresAt,
	))
	if err != nil {
		return sessions.Session{}, fmt.Errorf("insert session: %w", err)
	}
	return session, nil
}

func (r *Repository) FindBySecretHash(ctx context.Context, secretHash []byte) (sessions.Session, error) {
	session, err := scanSession(r.pool.QueryRow(ctx, findSessionBySecretHashQuery, secretHash))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sessions.Session{}, sessions.ErrSessionNotFound
		}
		return sessions.Session{}, fmt.Errorf("find session: %w", err)
	}
	return session, nil
}

func (r *Repository) Touch(ctx context.Context, sessionID string, lastActivityAt, idleExpiresAt time.Time) (sessions.Session, error) {
	session, err := scanSession(r.pool.QueryRow(ctx, touchSessionQuery, sessionID, lastActivityAt, idleExpiresAt))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sessions.Session{}, sessions.ErrSessionNotFound
		}
		return sessions.Session{}, fmt.Errorf("touch session: %w", err)
	}
	return session, nil
}

func scanSession(row pgx.Row) (sessions.Session, error) {
	var (
		session sessions.Session
		kind    string
	)
	err := row.Scan(
		&session.ID,
		&session.UserID,
		&kind,
		&session.CreatedAt,
		&session.LastActivityAt,
		&session.ExpiresAt,
		&session.AbsoluteExpiresAt,
		&session.RevokedAt,
	)
	if err != nil {
		return sessions.Session{}, err
	}
	session.Kind = sessions.Kind(kind)
	session.CreatedAt = session.CreatedAt.UTC()
	session.LastActivityAt = session.LastActivityAt.UTC()
	session.ExpiresAt = session.ExpiresAt.UTC()
	session.AbsoluteExpiresAt = session.AbsoluteExpiresAt.UTC()
	if session.RevokedAt != nil {
		revokedAt := session.RevokedAt.UTC()
		session.RevokedAt = &revokedAt
	}
	return session, nil
}
