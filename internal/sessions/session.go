package sessions

import "time"

type Kind string

const (
	KindWeb    Kind = "web"
	KindBearer Kind = "bearer"
)

type Session struct {
	ID                string
	UserID            string
	Kind              Kind
	CreatedAt         time.Time
	LastActivityAt    time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

type NewSession struct {
	UserID            string
	Kind              Kind
	SecretHash        []byte
	CreatedAt         time.Time
	LastActivityAt    time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
}

type Issued struct {
	Session Session
	Secret  string
}
