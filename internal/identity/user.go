package identity

import "time"

type Status string

const (
	StatusActive            Status = "active"
	StatusSuspended         Status = "suspended"
	StatusDeletionRequested Status = "deletion_requested"
)

type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Status        Status
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type NewUser struct {
	Email        string
	PasswordHash string
}

type RegisterUserInput struct {
	Email    string
	Password string
}
