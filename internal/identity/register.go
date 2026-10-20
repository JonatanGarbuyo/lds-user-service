package identity

import (
	"context"
	"fmt"
)

const defaultMaxConcurrentHashes = 2

type RegisterUser struct {
	users        UserRepository
	hasher       PasswordHasher
	verification EmailVerificationIssuer
	hashSlots    chan struct{}
}

type RegisterUserResult struct {
	User                      User
	VerificationDeliveryError error
}

func NewRegisterUser(users UserRepository, hasher PasswordHasher, verification EmailVerificationIssuer) *RegisterUser {
	return NewRegisterUserWithLimit(users, hasher, verification, defaultMaxConcurrentHashes)
}

func NewRegisterUserWithLimit(users UserRepository, hasher PasswordHasher, verification EmailVerificationIssuer, maxConcurrentHashes int) *RegisterUser {
	if maxConcurrentHashes < 1 {
		maxConcurrentHashes = 1
	}
	return &RegisterUser{
		users:        users,
		hasher:       hasher,
		verification: verification,
		hashSlots:    make(chan struct{}, maxConcurrentHashes),
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

	user, err := r.users.Create(ctx, NewUser{
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return RegisterUserResult{}, fmt.Errorf("create user: %w", err)
	}

	result := RegisterUserResult{User: user}
	if r.verification != nil {
		result.VerificationDeliveryError = r.verification.IssueForUser(ctx, user)
	}
	return result, nil
}

func (r *RegisterUser) hashPassword(password string) (string, error) {
	select {
	case r.hashSlots <- struct{}{}:
	default:
		return "", ErrRegistrationBusy
	}
	defer func() { <-r.hashSlots }()

	passwordHash, err := r.hasher.Hash(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return passwordHash, nil
}
