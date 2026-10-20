package identity

import (
	"context"
	"fmt"
)

const DefaultMaxConcurrentHashes = 2

type RegisterUser struct {
	users        UserRepository
	hasher       PasswordHasher
	verification EmailVerificationIssuer
	hashLimiter  HashLimiter
}

type RegisterUserResult struct {
	User                      User
	VerificationDeliveryError error
}

func NewRegisterUser(users UserRepository, hasher PasswordHasher, verification EmailVerificationIssuer) *RegisterUser {
	return NewRegisterUserWithLimiter(users, hasher, verification, NewHashLimiter(DefaultMaxConcurrentHashes))
}

func NewRegisterUserWithLimit(users UserRepository, hasher PasswordHasher, verification EmailVerificationIssuer, maxConcurrentHashes int) *RegisterUser {
	return NewRegisterUserWithLimiter(users, hasher, verification, NewHashLimiter(maxConcurrentHashes))
}

func NewRegisterUserWithLimiter(users UserRepository, hasher PasswordHasher, verification EmailVerificationIssuer, limiter HashLimiter) *RegisterUser {
	if limiter == nil {
		limiter = NewHashLimiter(DefaultMaxConcurrentHashes)
	}
	return &RegisterUser{
		users:        users,
		hasher:       hasher,
		verification: verification,
		hashLimiter:  limiter,
	}
}

func (r *RegisterUser) Execute(ctx context.Context, input RegisterUserInput) (RegisterUserResult, error) {
	email := NormalizeEmail(input.Email)
	if err := validateRegistration(email, input.Password); err != nil {
		return RegisterUserResult{}, err
	}

	passwordHash, err := r.hashPassword(input.Password)
	if err != nil {
		return RegisterUserResult{}, err
	}

	var prepared *PreparedEmailVerification
	if r.verification != nil {
		value, err := r.verification.Prepare(ctx)
		if err != nil {
			return RegisterUserResult{}, err
		}
		prepared = &value
	}

	user, err := r.users.Create(ctx, NewUser{
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return RegisterUserResult{}, fmt.Errorf("create user: %w", err)
	}

	result := RegisterUserResult{User: user}
	if prepared != nil {
		result.VerificationDeliveryError = r.verification.Issue(ctx, user, *prepared)
	}
	return result, nil
}

func (r *RegisterUser) hashPassword(password string) (string, error) {
	if !r.hashLimiter.TryAcquire() {
		return "", ErrRegistrationBusy
	}
	defer r.hashLimiter.Release()

	passwordHash, err := r.hasher.Hash(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return passwordHash, nil
}
