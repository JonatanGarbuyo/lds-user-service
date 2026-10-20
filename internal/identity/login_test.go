package identity_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
)

type loginUserRepository struct {
	credentials identity.UserCredentials
	err         error
}

func (r loginUserRepository) Create(context.Context, identity.NewUser) (identity.User, error) {
	return identity.User{}, errors.New("not implemented")
}

func (r loginUserRepository) FindByEmail(context.Context, string) (identity.User, error) {
	return r.credentials.User, r.err
}

func (r loginUserRepository) FindCredentialsByEmail(context.Context, string) (identity.UserCredentials, error) {
	return r.credentials, r.err
}

func (r loginUserRepository) FindByID(context.Context, string) (identity.User, error) {
	return r.credentials.User, r.err
}

type fakeVerifier struct {
	valid   bool
	err     error
	checked []string
}

func (v *fakeVerifier) Verify(password, encoded string) (bool, error) {
	v.checked = append(v.checked, encoded)
	return v.valid, v.err
}

type fakeSessions struct {
	userID string
	err    error
}

func (s *fakeSessions) CreateWebSession(_ context.Context, userID string) (sessions.Issued, error) {
	s.userID = userID
	if s.err != nil {
		return sessions.Issued{}, s.err
	}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	return sessions.Issued{
		Session: sessions.Session{
			ID:             "session-1",
			UserID:         userID,
			Kind:           sessions.KindWeb,
			CreatedAt:      now,
			LastActivityAt: now,
			ExpiresAt:      now.Add(30 * 24 * time.Hour),
		},
		Secret: "opaque-secret",
	}, nil
}

type fakeReaderState struct {
	err error
}

func (r fakeReaderState) Issue(userID string, emailVerified bool, status string) (readerstate.Snapshot, error) {
	if r.err != nil {
		return readerstate.Snapshot{}, r.err
	}
	return readerstate.Snapshot{SignedSnapshot: "signed." + userID, ExpiresAt: time.Now().Add(30 * time.Minute)}, nil
}

func newLoginUser(t *testing.T, repository loginUserRepository, verifier *fakeVerifier, sessionIssuer *fakeSessions, required bool) *identity.LoginUser {
	t.Helper()
	login, err := identity.NewLoginUser(identity.LoginDependencies{
		Users:                repository,
		Passwords:            verifier,
		Sessions:             sessionIssuer,
		ReaderState:          fakeReaderState{},
		HashLimiter:          identity.NewHashLimiter(4),
		VerificationRequired: required,
		Now:                  func() time.Time { return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewLoginUser() error = %v", err)
	}
	return login
}

func activeUser() identity.User {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	return identity.User{
		ID:            "user-1",
		Email:         "person@example.com",
		EmailVerified: true,
		Status:        identity.StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestLoginReturnsUserSessionAndSignedReaderState(t *testing.T) {
	verifier := &fakeVerifier{valid: true}
	sessionIssuer := &fakeSessions{}
	login := newLoginUser(t, loginUserRepository{credentials: identity.UserCredentials{
		User:         activeUser(),
		PasswordHash: "$argon2id$stored",
	}}, verifier, sessionIssuer, true)

	result, err := login.Execute(context.Background(), identity.LoginInput{
		Email:    " Person@Example.com ",
		Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.User.ID != "user-1" {
		t.Errorf("user.id = %q, want user-1", result.User.ID)
	}
	if result.Session.Secret != "opaque-secret" {
		t.Errorf("session secret = %q, want opaque-secret", result.Session.Secret)
	}
	if result.ReaderState.SignedSnapshot != "signed.user-1" {
		t.Errorf("signedSnapshot = %q", result.ReaderState.SignedSnapshot)
	}
	if sessionIssuer.userID != "user-1" {
		t.Errorf("session issuer userID = %q, want user-1", sessionIssuer.userID)
	}
	if len(verifier.checked) != 1 || verifier.checked[0] != "$argon2id$stored" {
		t.Errorf("verified hashes = %v, want the stored hash", verifier.checked)
	}
}

func TestLoginRejectsWrongUnknownAndMalformedCredentials(t *testing.T) {
	tests := []struct {
		name       string
		input      identity.LoginInput
		repository loginUserRepository
		verifier   *fakeVerifier
		want       error
		wantCode   string
	}{
		{
			name:       "wrong password",
			input:      identity.LoginInput{Email: "person@example.com", Password: "wrong password"},
			repository: loginUserRepository{credentials: identity.UserCredentials{User: activeUser()}},
			verifier:   &fakeVerifier{valid: false},
			wantCode:   "credentials",
		},
		{
			name:       "unknown email",
			input:      identity.LoginInput{Email: "missing@example.com", Password: "wrong password"},
			repository: loginUserRepository{err: identity.ErrUserNotFound},
			verifier:   &fakeVerifier{valid: false},
			wantCode:   "credentials",
		},
		{
			name:       "malformed email",
			input:      identity.LoginInput{Email: "not-an-email", Password: "correct horse battery"},
			repository: loginUserRepository{},
			verifier:   &fakeVerifier{valid: true},
			wantCode:   "validation",
		},
		{
			name:       "missing password",
			input:      identity.LoginInput{Email: "person@example.com"},
			repository: loginUserRepository{},
			verifier:   &fakeVerifier{valid: true},
			wantCode:   "validation",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			login := newLoginUser(t, test.repository, test.verifier, &fakeSessions{}, true)
			_, err := login.Execute(context.Background(), test.input)
			if err == nil {
				t.Fatal("Execute() error = nil, want error")
			}
			switch test.wantCode {
			case "credentials":
				if !errors.Is(err, identity.ErrInvalidCredentials) {
					t.Errorf("error = %v, want ErrInvalidCredentials", err)
				}
			case "validation":
				var validationErr *identity.ValidationError
				if !errors.As(err, &validationErr) {
					t.Errorf("error = %v, want ValidationError", err)
				}
			}
		})
	}
}

func TestLoginEnforcesAccountStateAndEmailVerificationPolicy(t *testing.T) {
	suspended := activeUser()
	suspended.Status = identity.StatusSuspended
	unverified := activeUser()
	unverified.EmailVerified = false

	tests := []struct {
		name     string
		user     identity.User
		required bool
		want     error
	}{
		{name: "suspended", user: suspended, required: true, want: identity.ErrAccountSuspended},
		{name: "deletion requested", user: func() identity.User {
			user := activeUser()
			user.Status = identity.StatusDeletionRequested
			return user
		}(), required: true, want: identity.ErrAccountSuspended},
		{name: "unverified required", user: unverified, required: true, want: identity.ErrEmailNotVerified},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			login := newLoginUser(t, loginUserRepository{credentials: identity.UserCredentials{
				User: test.user, PasswordHash: "$argon2id$stored",
			}}, &fakeVerifier{valid: true}, &fakeSessions{}, test.required)
			_, err := login.Execute(context.Background(), identity.LoginInput{
				Email: "person@example.com", Password: "correct horse battery",
			})
			if !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}
		})
	}

	login := newLoginUser(t, loginUserRepository{credentials: identity.UserCredentials{
		User: unverified, PasswordHash: "$argon2id$stored",
	}}, &fakeVerifier{valid: true}, &fakeSessions{}, false)
	if _, err := login.Execute(context.Background(), identity.LoginInput{
		Email: "person@example.com", Password: "correct horse battery",
	}); err != nil {
		t.Errorf("unverified login with policy disabled error = %v", err)
	}
}

func TestLoginDoesNotIssueSessionWhenPasswordIsWrong(t *testing.T) {
	sessionIssuer := &fakeSessions{}
	login := newLoginUser(t, loginUserRepository{credentials: identity.UserCredentials{
		User: activeUser(), PasswordHash: "$argon2id$stored",
	}}, &fakeVerifier{valid: false}, sessionIssuer, true)

	_, err := login.Execute(context.Background(), identity.LoginInput{
		Email: "person@example.com", Password: "wrong password",
	})
	if !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
	if sessionIssuer.userID != "" {
		t.Error("a session was issued for invalid credentials")
	}
}

func TestLoginReturnsBusyWhenHashingCapacityIsExhausted(t *testing.T) {
	limiter := identity.NewHashLimiter(1)
	if !limiter.TryAcquire() {
		t.Fatal("could not acquire limiter")
	}
	defer limiter.Release()

	login, err := identity.NewLoginUser(identity.LoginDependencies{
		Users: loginUserRepository{credentials: identity.UserCredentials{
			User: activeUser(), PasswordHash: "$argon2id$stored",
		}},
		Passwords:            &fakeVerifier{valid: true},
		Sessions:             &fakeSessions{},
		ReaderState:          fakeReaderState{},
		HashLimiter:          limiter,
		VerificationRequired: true,
	})
	if err != nil {
		t.Fatalf("NewLoginUser() error = %v", err)
	}

	_, err = login.Execute(context.Background(), identity.LoginInput{
		Email: "person@example.com", Password: "correct horse battery",
	})
	if !errors.Is(err, identity.ErrHashingBusy) {
		t.Errorf("error = %v, want ErrHashingBusy", err)
	}
}

func TestLoginDoesNotLeakWhetherAnEmailExists(t *testing.T) {
	unknownVerifier := &fakeVerifier{valid: false}
	login := newLoginUser(t, loginUserRepository{err: identity.ErrUserNotFound}, unknownVerifier, &fakeSessions{}, true)

	_, err := login.Execute(context.Background(), identity.LoginInput{
		Email: "missing@example.com", Password: "wrong password",
	})
	if !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
	if len(unknownVerifier.checked) != 1 || !strings.Contains(unknownVerifier.checked[0], "argon2id") {
		t.Errorf("dummy hash was not verified for an unknown email: %v", unknownVerifier.checked)
	}
}
