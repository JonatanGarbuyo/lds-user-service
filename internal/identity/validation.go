package identity

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

const (
	maxEmailLength    = 254
	maxEmailLocalPart = 64
	minPasswordLength = 12
	maxPasswordLength = 256
)

func NormalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func validateRegistration(email, password string) error {
	fields := make(map[string]string)

	if email == "" {
		fields["email"] = "is required"
	} else if message := validateEmail(email); message != "" {
		fields["email"] = message
	}

	if password == "" {
		fields["password"] = "is required"
	} else if message := validatePassword(password); message != "" {
		fields["password"] = message
	}

	if len(fields) > 0 {
		return &ValidationError{Fields: fields}
	}
	return nil
}

func validateEmailOnly(email string) error {
	if email == "" {
		return &ValidationError{Fields: map[string]string{"email": "is required"}}
	}
	if message := validateEmail(email); message != "" {
		return &ValidationError{Fields: map[string]string{"email": message}}
	}
	return nil
}

func validateVerificationCode(code string) error {
	if len(code) != verificationCodeDigits {
		return &ValidationError{Fields: map[string]string{"code": "must be exactly 6 digits"}}
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return &ValidationError{Fields: map[string]string{"code": "must be exactly 6 digits"}}
		}
	}
	return nil
}

func validateEmail(email string) string {
	if len(email) > maxEmailLength {
		return "must be at most 254 characters"
	}
	if strings.ContainsAny(email, " \t\r\n") {
		return "must be a valid email address"
	}

	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "must be a valid email address"
	}

	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || len(local) > maxEmailLocalPart {
		return "must be a valid email address"
	}
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "must be a valid email address"
	}
	return ""
}

func validatePassword(password string) string {
	if !utf8.ValidString(password) {
		return "must be valid UTF-8"
	}
	if strings.TrimSpace(password) == "" {
		return "must not contain only whitespace"
	}
	length := utf8.RuneCountInString(password)
	if length < minPasswordLength {
		return "must be at least 12 characters"
	}
	if length > maxPasswordLength {
		return "must be at most 256 characters"
	}
	return ""
}
