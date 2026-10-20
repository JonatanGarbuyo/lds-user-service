package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
)

const dummyLoginPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$zU8H+Ra9Sm7/VlELsd7h2Q$qrSjaO/K/qXs6ECKq+xOPzbUIy4hKZXFjeJiqZBTe+I"

type LoginInput struct {
	Email    string
	Password string
}

type LoginResult struct {
	User        User
	Session     sessions.Issued
	ReaderState readerstate.Snapshot
}

type SessionIssuer interface {
	CreateWebSession(ctx context.Context, userID string) (sessions.Issued, error)
}

type ReaderStateIssuer interface {
	Issue(userID string, emailVerified bool, status string) (readerstate.Snapshot, error)
}

type LoginDependencies struct {
	Users                UserRepository
	Passwords            PasswordVerifier
	Sessions             SessionIssuer
	ReaderState          ReaderStateIssuer
	HashLimiter          HashLimiter
	VerificationRequired bool
	Now                  func() time.Time
}

type LoginUser struct {
	users                UserRepository
	passwords            PasswordVerifier
	sessions             SessionIssuer
	readerState          ReaderStateIssuer
	hashLimiter          HashLimiter
	verificationRequired bool
	now                  func() time.Time
}

func NewLoginUser(dependencies LoginDependencies) (*LoginUser, error) {
	if dependencies.Users == nil || dependencies.Passwords == nil {
		return nil, errors.New("login requires user repository and password verifier")
	}
	if dependencies.Sessions == nil || dependencies.ReaderState == nil {
		return nil, errors.New("login requires session and reader state issuers")
	}
	if dependencies.HashLimiter == nil {
		dependencies.HashLimiter = NewHashLimiter(DefaultMaxConcurrentHashes)
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return &LoginUser{
		users:                dependencies.Users,
		passwords:            dependencies.Passwords,
		sessions:             dependencies.Sessions,
		readerState:          dependencies.ReaderState,
		hashLimiter:          dependencies.HashLimiter,
		verificationRequired: dependencies.VerificationRequired,
		now:                  dependencies.Now,
	}, nil
}

func (l *LoginUser) Execute(ctx context.Context, input LoginInput) (LoginResult, error) {
	email := NormalizeEmail(input.Email)
	if err := validateLogin(email, input.Password); err != nil {
		return LoginResult{}, err
	}

	credentials, err := l.users.FindCredentialsByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			if _, err := l.verifyPassword(input.Password, dummyLoginPasswordHash); err != nil {
				return LoginResult{}, err
			}
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, fmt.Errorf("find user credentials: %w", err)
	}

	valid, err := l.verifyPassword(input.Password, credentials.PasswordHash)
	if err != nil {
		return LoginResult{}, err
	}
	if !valid {
		return LoginResult{}, ErrInvalidCredentials
	}

	user := credentials.User
	if user.Status != StatusActive {
		return LoginResult{}, ErrAccountSuspended
	}
	if l.verificationRequired && !user.EmailVerified {
		return LoginResult{}, ErrEmailNotVerified
	}

	snapshot, err := l.readerState.Issue(user.ID, user.EmailVerified, string(user.Status))
	if err != nil {
		return LoginResult{}, fmt.Errorf("issue reader state: %w", err)
	}

	issuedSession, err := l.sessions.CreateWebSession(ctx, user.ID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("create web session: %w", err)
	}

	return LoginResult{
		User:        user,
		Session:     issuedSession,
		ReaderState: snapshot,
	}, nil
}

func (l *LoginUser) verifyPassword(password, encoded string) (bool, error) {
	if !l.hashLimiter.TryAcquire() {
		return false, ErrHashingBusy
	}
	defer l.hashLimiter.Release()

	valid, err := l.passwords.Verify(password, encoded)
	if err != nil {
		return false, fmt.Errorf("verify password: %w", err)
	}
	return valid, nil
}

func validateLogin(email, password string) error {
	fields := make(map[string]string)
	if email == "" {
		fields["email"] = "is required"
	} else if message := validateEmail(email); message != "" {
		fields["email"] = message
	}
	if password == "" {
		fields["password"] = "is required"
	} else if len(password) > maxPasswordLength {
		fields["password"] = "must be at most 256 characters"
	}
	if len(fields) > 0 {
		return &ValidationError{Fields: fields}
	}
	return nil
}
