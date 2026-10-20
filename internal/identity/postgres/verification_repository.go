package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

const (
	lockUserQuery = `
		SELECT id::text, email_verified
		FROM users
		WHERE id = $1
		FOR UPDATE`
	lastChallengeQuery = `
		SELECT created_at
		FROM email_verification_challenges
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1`
	invalidateActiveChallengesQuery = `
		UPDATE email_verification_challenges
		SET invalidated_at = $2
		WHERE user_id = $1
		  AND consumed_at IS NULL
		  AND invalidated_at IS NULL`
	createChallengeQuery = `
		INSERT INTO email_verification_challenges (user_id, code_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id::text, user_id::text, created_at, expires_at`
	deleteChallengeQuery = `
		DELETE FROM email_verification_challenges
		WHERE id = $1`
	findActiveChallengeQuery = `
		SELECT c.id::text, c.user_id::text, u.email, c.code_hash, c.attempts, c.expires_at
		FROM email_verification_challenges c
		JOIN users u ON u.id = c.user_id
		WHERE u.email = $1
		  AND c.consumed_at IS NULL
		  AND c.invalidated_at IS NULL
		  AND c.expires_at > $2
		  AND c.attempts < $3
		ORDER BY c.created_at DESC
		LIMIT 1`
	recordFailedAttemptQuery = `
		UPDATE email_verification_challenges
		SET attempts = attempts + 1,
		    invalidated_at = CASE WHEN attempts + 1 >= $3 THEN $2 ELSE invalidated_at END
		WHERE id = $1
		  AND consumed_at IS NULL
		  AND invalidated_at IS NULL
		  AND expires_at > $2
		  AND attempts < $3`
	consumeChallengeQuery = `
		UPDATE email_verification_challenges
		SET consumed_at = $2
		WHERE id = $1
		  AND consumed_at IS NULL
		  AND invalidated_at IS NULL
		  AND expires_at > $2
		  AND attempts < $3
		RETURNING user_id::text`
	invalidateOtherChallengesQuery = `
		UPDATE email_verification_challenges
		SET invalidated_at = $2
		WHERE user_id = $1
		  AND consumed_at IS NULL
		  AND invalidated_at IS NULL
		  AND id <> $3`
	markEmailVerifiedQuery = `
		UPDATE users
		SET email_verified = true,
		    updated_at = $2
		WHERE id = $1
		  AND email_verified = false
		RETURNING id::text, email, email_verified, status, created_at, updated_at`
	findUserByIDQuery = `
		SELECT id::text, email, email_verified, status, created_at, updated_at
		FROM users
		WHERE id = $1`
)

type VerificationRepository struct {
	pool *pgxpool.Pool
}

func NewVerificationRepository(pool *pgxpool.Pool) *VerificationRepository {
	return &VerificationRepository{pool: pool}
}

func (r *VerificationRepository) CreateChallenge(
	ctx context.Context,
	userID, codeHash string,
	now, expiresAt time.Time,
	resendCooldown time.Duration,
) (identity.VerificationChallenge, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return identity.VerificationChallenge{}, fmt.Errorf("begin verification challenge transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		lockedUserID  string
		emailVerified bool
	)
	if err := tx.QueryRow(ctx, lockUserQuery, userID).Scan(&lockedUserID, &emailVerified); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.VerificationChallenge{}, identity.ErrUserNotFound
		}
		return identity.VerificationChallenge{}, fmt.Errorf("lock user: %w", err)
	}
	if emailVerified {
		return identity.VerificationChallenge{}, identity.ErrEmailAlreadyVerified
	}

	var lastCreatedAt time.Time
	err = tx.QueryRow(ctx, lastChallengeQuery, userID).Scan(&lastCreatedAt)
	switch {
	case err == nil:
		if now.Sub(lastCreatedAt) < resendCooldown {
			return identity.VerificationChallenge{}, identity.ErrResendTooSoon
		}
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return identity.VerificationChallenge{}, fmt.Errorf("find last verification challenge: %w", err)
	}

	if _, err := tx.Exec(ctx, invalidateActiveChallengesQuery, userID, now); err != nil {
		return identity.VerificationChallenge{}, fmt.Errorf("invalidate active verification challenges: %w", err)
	}

	challenge := identity.VerificationChallenge{
		UserID:    userID,
		CodeHash:  codeHash,
		ExpiresAt: expiresAt,
	}
	if err := tx.QueryRow(ctx, createChallengeQuery, userID, codeHash, now, expiresAt).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
	); err != nil {
		return identity.VerificationChallenge{}, fmt.Errorf("insert verification challenge: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return identity.VerificationChallenge{}, fmt.Errorf("commit verification challenge: %w", err)
	}
	return challenge, nil
}

func (r *VerificationRepository) DeleteChallenge(ctx context.Context, challengeID string) error {
	if _, err := r.pool.Exec(ctx, deleteChallengeQuery, challengeID); err != nil {
		return fmt.Errorf("delete verification challenge: %w", err)
	}
	return nil
}

func (r *VerificationRepository) FindActiveChallengeByEmail(
	ctx context.Context,
	email string,
	now time.Time,
	maxAttempts int,
) (identity.VerificationChallenge, error) {
	var challenge identity.VerificationChallenge
	err := r.pool.QueryRow(ctx, findActiveChallengeQuery, email, now, maxAttempts).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.Email,
		&challenge.CodeHash,
		&challenge.Attempts,
		&challenge.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.VerificationChallenge{}, identity.ErrChallengeNotFound
		}
		return identity.VerificationChallenge{}, fmt.Errorf("find active verification challenge: %w", err)
	}
	return challenge, nil
}

func (r *VerificationRepository) RecordFailedAttempt(
	ctx context.Context,
	challengeID string,
	now time.Time,
	maxAttempts int,
) error {
	tag, err := r.pool.Exec(ctx, recordFailedAttemptQuery, challengeID, now, maxAttempts)
	if err != nil {
		return fmt.Errorf("record failed verification attempt: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrChallengeInactive
	}
	return nil
}

func (r *VerificationRepository) ConsumeAndVerify(
	ctx context.Context,
	challengeID string,
	now time.Time,
	maxAttempts int,
) (identity.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return identity.User{}, fmt.Errorf("begin verification transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	if err := tx.QueryRow(ctx, consumeChallengeQuery, challengeID, now, maxAttempts).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.User{}, identity.ErrChallengeInactive
		}
		return identity.User{}, fmt.Errorf("consume verification challenge: %w", err)
	}

	user, err := scanUser(tx.QueryRow(ctx, markEmailVerifiedQuery, userID, now))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return identity.User{}, fmt.Errorf("mark email verified: %w", err)
		}
		user, err = scanUser(tx.QueryRow(ctx, findUserByIDQuery, userID))
		if err != nil {
			return identity.User{}, fmt.Errorf("find user after verification: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, invalidateOtherChallengesQuery, userID, now, challengeID); err != nil {
		return identity.User{}, fmt.Errorf("invalidate other verification challenges: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return identity.User{}, fmt.Errorf("commit email verification: %w", err)
	}
	return user, nil
}

var (
	_ identity.EmailVerificationRepository = (*VerificationRepository)(nil)
	_ identity.UserRepository              = (*Repository)(nil)
)
