package identity

import (
	"context"
	"fmt"
)

const defaultMaxConcurrentHashes = 2

type RegisterUser struct {
	users     UserRepository
	hasher    PasswordHasher
	hashSlots chan struct{}
}

func NewRegisterUser(users UserRepository, hasher PasswordHasher) *RegisterUser {
	return NewRegisterUserWithLimit(users, hasher, defaultMaxConcurrentHashes)
}

func NewRegisterUserWithLimit(users UserRepository, hasher PasswordHasher, maxConcurrentHashes int) *RegisterUser {
	if maxConcurrentHashes < 1 {
		maxConcurrentHashes = 1
	}
	return &RegisterUser{
		users:     users,
		hasher:    hasher,
		hashSlots: make(chan struct{}, maxConcurrentHashes),
	}
}

func (r *RegisterUser) Execute(ctx context.Context, input RegisterUserInput) (User, error) {
	email := NormalizeEmail(input.Email)
	if err := validateRegistration(email, input.Password); err != nil {
		return User{}, err
	}

	passwordHash, err := r.hashPassword(input.Password)
	if err != nil {
		return User{}, err
	}

	user, err := r.users.Create(ctx, NewUser{
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
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
