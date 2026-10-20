package identity

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrEmailAlreadyExists      = errors.New("email already exists")
	ErrRegistrationBusy        = errors.New("registration capacity exhausted")
	ErrHashingBusy             = errors.New("hashing capacity exhausted")
	ErrUserNotFound            = errors.New("user not found")
	ErrChallengeNotFound       = errors.New("verification challenge not found")
	ErrChallengeInactive       = errors.New("verification challenge is no longer active")
	ErrResendTooSoon           = errors.New("verification code was sent too recently")
	ErrEmailAlreadyVerified    = errors.New("email is already verified")
	ErrInvalidVerificationCode = errors.New("invalid verification code")
	ErrRateLimited             = errors.New("rate limited")
	ErrVerificationDelivery    = errors.New("verification email delivery failed")
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrEmailNotVerified        = errors.New("email is not verified")
	ErrAccountSuspended        = errors.New("account cannot sign in")
	ErrWebSessionInvalid       = errors.New("web session is invalid")
)

type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	return "validation failed"
}

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited; retry after %s", e.RetryAfter)
}

func (e *RateLimitError) Is(target error) bool {
	return target == ErrRateLimited
}

type VerificationDeliveryError struct {
	Err error
}

func (e *VerificationDeliveryError) Error() string {
	return ErrVerificationDelivery.Error()
}

func (e *VerificationDeliveryError) Unwrap() error {
	return e.Err
}

func (e *VerificationDeliveryError) Is(target error) bool {
	return target == ErrVerificationDelivery
}
