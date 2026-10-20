package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

const (
	createUserQuery = `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id::text, email, email_verified, status, created_at, updated_at`
	findUserByEmailQuery = `
		SELECT id::text, email, email_verified, status, created_at, updated_at
		FROM users
		WHERE email = $1`
	uniqueViolationCode   = "23505"
	emailUniqueConstraint = "users_email_key"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Create(ctx context.Context, newUser identity.NewUser) (identity.User, error) {
	row := r.pool.QueryRow(ctx, createUserQuery, newUser.Email, newUser.PasswordHash)
	user, err := scanUser(row)
	if err != nil {
		if isEmailUniqueViolation(err) {
			return identity.User{}, identity.ErrEmailAlreadyExists
		}
		return identity.User{}, fmt.Errorf("insert user: %w", err)
	}
	return user, nil
}

func (r *Repository) FindByEmail(ctx context.Context, email string) (identity.User, error) {
	user, err := scanUser(r.pool.QueryRow(ctx, findUserByEmailQuery, email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.User{}, identity.ErrUserNotFound
		}
		return identity.User{}, fmt.Errorf("find user by email: %w", err)
	}
	return user, nil
}

func scanUser(row pgx.Row) (identity.User, error) {
	var (
		user   identity.User
		status string
	)
	if err := row.Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&status,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return identity.User{}, err
	}
	user.Status = identity.Status(status)
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()
	return user, nil
}

func isEmailUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		pgErr.Code == uniqueViolationCode &&
		pgErr.ConstraintName == emailUniqueConstraint
}
