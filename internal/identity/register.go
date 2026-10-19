package identity

import (
	"context"
	"fmt"
)

type RegisterUser struct {
	users  UserRepository
	hasher PasswordHasher
}

func NewRegisterUser(users UserRepository, hasher PasswordHasher) *RegisterUser {
	return &RegisterUser{users: users, hasher: hasher}
}

func (r *RegisterUser) Execute(ctx context.Context, input RegisterUserInput) (User, error) {
	email := NormalizeEmail(input.Email)
	if err := validateRegistration(email, input.Password); err != nil {
		return User{}, err
	}

	passwordHash, err := r.hasher.Hash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
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
