package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
)

type WebSessionAuthenticator interface {
	AuthenticateWebSession(ctx context.Context, secret string) (sessions.Session, error)
}

type CurrentUser struct {
	users    UserRepository
	sessions WebSessionAuthenticator
}

func NewCurrentUser(users UserRepository, authenticator WebSessionAuthenticator) *CurrentUser {
	return &CurrentUser{users: users, sessions: authenticator}
}

func (c *CurrentUser) Execute(ctx context.Context, sessionSecret string) (User, error) {
	if sessionSecret == "" {
		return User{}, ErrWebSessionInvalid
	}

	session, err := c.sessions.AuthenticateWebSession(ctx, sessionSecret)
	if err != nil {
		if errors.Is(err, sessions.ErrInvalidSession) {
			return User{}, ErrWebSessionInvalid
		}
		return User{}, fmt.Errorf("authenticate web session: %w", err)
	}

	user, err := c.users.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return User{}, ErrWebSessionInvalid
		}
		return User{}, fmt.Errorf("find current user: %w", err)
	}
	if user.Status != StatusActive {
		return User{}, ErrWebSessionInvalid
	}
	return user, nil
}
