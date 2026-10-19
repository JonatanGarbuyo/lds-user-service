package identity

import "context"

type UserRepository interface {
	Create(ctx context.Context, newUser NewUser) (User, error)
	FindByEmail(ctx context.Context, email string) (User, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}
