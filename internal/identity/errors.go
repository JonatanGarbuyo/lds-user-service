package identity

import "errors"

var (
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrRegistrationBusy   = errors.New("registration capacity exhausted")
)

type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	return "validation failed"
}
