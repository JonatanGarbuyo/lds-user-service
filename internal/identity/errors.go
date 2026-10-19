package identity

import "errors"

var ErrEmailAlreadyExists = errors.New("email already exists")

type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	return "validation failed"
}
