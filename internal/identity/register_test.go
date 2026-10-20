package identity_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

var fixedNow = time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)

type memoryRepository struct {
	mu          sync.Mutex
	users       map[string]identity.User
	passwords   map[string]string
	createCalls int
	createErr   error
	nextID      int
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		users:     make(map[string]identity.User),
		passwords: make(map[string]string),
	}
}

func (r *memoryRepository) FindByEmail(_ context.Context, email string) (identity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	user, exists := r.users[email]
	if !exists {
		return identity.User{}, identity.ErrUserNotFound
	}
	return user, nil
}

func (r *memoryRepository) Create(_ context.Context, newUser identity.NewUser) (identity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.createCalls++
	if r.createErr != nil {
		return identity.User{}, r.createErr
	}
	if _, exists := r.users[newUser.Email]; exists {
		return identity.User{}, identity.ErrEmailAlreadyExists
	}

	r.nextID++
	user := identity.User{
		ID:            fmt.Sprintf("user-%d", r.nextID),
		Email:         newUser.Email,
		EmailVerified: false,
		Status:        identity.StatusActive,
		CreatedAt:     fixedNow,
		UpdatedAt:     fixedNow,
	}
	r.users[newUser.Email] = user
	r.passwords[newUser.Email] = newUser.PasswordHash
	return user, nil
}

type blockingHasher struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func newBlockingHasher() *blockingHasher {
	return &blockingHasher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (h *blockingHasher) Hash(password string) (string, error) {
	h.calls.Add(1)
	h.once.Do(func() { close(h.started) })
	if password == "blocking password" {
		<-h.release
	}
	return "hashed:" + password, nil
}

type stubHasher struct {
	hashCalls int
	err       error
}

func (h *stubHasher) Hash(password string) (string, error) {
	h.hashCalls++
	if h.err != nil {
		return "", h.err
	}
	return "hashed:" + password, nil
}

func TestRegisterUserCreatesActiveUnverifiedUser(t *testing.T) {
	repository := newMemoryRepository()
	hasher := &stubHasher{}
	register := identity.NewRegisterUser(repository, hasher, nil)

	result, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "  Person@Example.COM ",
		Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	user := result.User

	if user.ID == "" {
		t.Error("user.ID is empty")
	}
	if user.ID == user.Email {
		t.Error("user.ID must be independent from the email")
	}
	if user.Email != "person@example.com" {
		t.Errorf("user.Email = %q, want %q", user.Email, "person@example.com")
	}
	if user.EmailVerified {
		t.Error("user.EmailVerified = true, want false at registration")
	}
	if user.Status != identity.StatusActive {
		t.Errorf("user.Status = %q, want %q", user.Status, identity.StatusActive)
	}
	if !user.CreatedAt.Equal(fixedNow) || !user.UpdatedAt.Equal(fixedNow) {
		t.Errorf("timestamps = %v/%v, want %v", user.CreatedAt, user.UpdatedAt, fixedNow)
	}
	if got := repository.passwords["person@example.com"]; got != "hashed:correct horse battery" {
		t.Errorf("stored password = %q, want the hasher output", got)
	}
	if got := repository.passwords["person@example.com"]; got == "correct horse battery" {
		t.Error("password was stored in plaintext")
	}
	if hasher.hashCalls != 1 {
		t.Errorf("hash calls = %d, want 1", hasher.hashCalls)
	}
}

func TestRegisterUserValidatesInput(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		password       string
		wantField      string
		wantRepository bool
	}{
		{name: "empty email", email: "", password: "correct horse battery", wantField: "email"},
		{name: "invalid email", email: "not-an-email", password: "correct horse battery", wantField: "email"},
		{name: "email without domain", email: "person@localhost", password: "correct horse battery", wantField: "email"},
		{name: "email too long", email: strings.Repeat("a", 250) + "@example.com", password: "correct horse battery", wantField: "email"},
		{name: "empty password", email: "person@example.com", password: "", wantField: "password"},
		{name: "whitespace password", email: "person@example.com", password: "            ", wantField: "password"},
		{name: "short password", email: "person@example.com", password: "short", wantField: "password"},
		{name: "long password", email: "person@example.com", password: strings.Repeat("a", 257), wantField: "password"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newMemoryRepository()
			register := identity.NewRegisterUser(repository, &stubHasher{}, nil)

			_, err := register.Execute(context.Background(), identity.RegisterUserInput{
				Email:    test.email,
				Password: test.password,
			})
			if err == nil {
				t.Fatal("Execute() error = nil, want validation error")
			}

			var validationErr *identity.ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("Execute() error = %T %v, want *identity.ValidationError", err, err)
			}
			if validationErr.Fields[test.wantField] == "" {
				t.Errorf("validation fields = %v, want an error for %q", validationErr.Fields, test.wantField)
			}
			if repository.createCalls != 0 {
				t.Errorf("repository create calls = %d, want 0", repository.createCalls)
			}
		})
	}
}

func TestRegisterUserAcceptsTwelveCharacterPassword(t *testing.T) {
	register := identity.NewRegisterUser(newMemoryRepository(), &stubHasher{}, nil)

	if _, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "twelve chars",
	}); err != nil {
		t.Fatalf("Execute() error = %v, want nil", err)
	}
}

func TestRegisterUserRejectsDuplicateEmail(t *testing.T) {
	register := identity.NewRegisterUser(newMemoryRepository(), &stubHasher{}, nil)

	if _, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "correct horse battery",
	}); err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}

	_, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    " PERSON@Example.com ",
		Password: "another strong password",
	})
	if !errors.Is(err, identity.ErrEmailAlreadyExists) {
		t.Fatalf("second Execute() error = %v, want ErrEmailAlreadyExists", err)
	}
}

func TestRegisterUserPropagatesHasherFailure(t *testing.T) {
	repository := newMemoryRepository()
	hasherErr := errors.New("hash failure")
	register := identity.NewRegisterUser(repository, &stubHasher{err: hasherErr}, nil)

	_, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "correct horse battery",
	})
	if !errors.Is(err, hasherErr) {
		t.Fatalf("Execute() error = %v, want %v", err, hasherErr)
	}
	if repository.createCalls != 0 {
		t.Errorf("repository create calls = %d, want 0", repository.createCalls)
	}
}

func TestRegisterUserPropagatesRepositoryFailure(t *testing.T) {
	repositoryErr := errors.New("database unavailable")
	repository := newMemoryRepository()
	repository.createErr = repositoryErr
	register := identity.NewRegisterUser(repository, &stubHasher{}, nil)

	_, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "correct horse battery",
	})
	if !errors.Is(err, repositoryErr) {
		t.Fatalf("Execute() error = %v, want %v", err, repositoryErr)
	}
}

func TestRegisterUserRejectsWhenHashingCapacityIsFull(t *testing.T) {
	repository := newMemoryRepository()
	hasher := newBlockingHasher()
	register := identity.NewRegisterUserWithLimit(repository, hasher, nil, 1)

	firstDone := make(chan error, 1)
	go func() {
		_, err := register.Execute(context.Background(), identity.RegisterUserInput{
			Email:    "first@example.com",
			Password: "blocking password",
		})
		firstDone <- err
	}()

	<-hasher.started

	_, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "second@example.com",
		Password: "another strong password",
	})
	if !errors.Is(err, identity.ErrRegistrationBusy) {
		t.Fatalf("Execute() while full error = %v, want ErrRegistrationBusy", err)
	}
	if calls := hasher.calls.Load(); calls != 1 {
		t.Errorf("hash calls while full = %d, want 1", calls)
	}

	released := false
	defer func() {
		if !released {
			close(hasher.release)
		}
	}()

	close(hasher.release)
	released = true

	if err := <-firstDone; err != nil {
		t.Fatalf("first Execute() error = %v", err)
	}

	if _, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "third@example.com",
		Password: "third strong password",
	}); err != nil {
		t.Fatalf("Execute() after capacity freed error = %v", err)
	}
	if calls := hasher.calls.Load(); calls != 2 {
		t.Errorf("hash calls after capacity freed = %d, want 2", calls)
	}
}

type recordingVerificationIssuer struct {
	users      []identity.User
	err        error
	prepareErr error
}

func (i *recordingVerificationIssuer) Prepare(context.Context) (identity.PreparedEmailVerification, error) {
	if i.prepareErr != nil {
		return identity.PreparedEmailVerification{}, i.prepareErr
	}
	return identity.PreparedEmailVerification{Code: "012345", CodeHash: "hash:012345"}, nil
}

func (i *recordingVerificationIssuer) Issue(_ context.Context, user identity.User, _ identity.PreparedEmailVerification) error {
	i.users = append(i.users, user)
	return i.err
}

func TestRegisterUserIssuesEmailVerification(t *testing.T) {
	repository := newMemoryRepository()
	issuer := &recordingVerificationIssuer{}
	register := identity.NewRegisterUser(repository, &stubHasher{}, issuer)

	result, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.VerificationDeliveryError != nil {
		t.Errorf("VerificationDeliveryError = %v, want nil", result.VerificationDeliveryError)
	}
	if len(issuer.users) != 1 {
		t.Fatalf("issued verifications = %d, want 1", len(issuer.users))
	}
	if issuer.users[0].ID != result.User.ID || issuer.users[0].Email != result.User.Email {
		t.Errorf("issued user = %+v, want %+v", issuer.users[0], result.User)
	}
}

func TestRegisterUserSucceedsWhenVerificationDeliveryFails(t *testing.T) {
	repository := newMemoryRepository()
	deliveryErr := errors.New("mail transport unavailable")
	issuer := &recordingVerificationIssuer{err: deliveryErr}
	register := identity.NewRegisterUser(repository, &stubHasher{}, issuer)

	result, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.User.ID == "" {
		t.Error("user was not created")
	}
	if !errors.Is(result.VerificationDeliveryError, deliveryErr) {
		t.Errorf("VerificationDeliveryError = %v, want %v", result.VerificationDeliveryError, deliveryErr)
	}
	if _, exists := repository.users["person@example.com"]; !exists {
		t.Error("user was not persisted despite successful registration")
	}
}

func TestRegisterUserReturnsHashingBusyWithoutPersistingUser(t *testing.T) {
	repository := newMemoryRepository()
	issuer := &recordingVerificationIssuer{prepareErr: identity.ErrHashingBusy}
	register := identity.NewRegisterUser(repository, &stubHasher{}, issuer)

	_, err := register.Execute(context.Background(), identity.RegisterUserInput{
		Email:    "person@example.com",
		Password: "correct horse battery",
	})
	if !errors.Is(err, identity.ErrHashingBusy) {
		t.Fatalf("Execute() error = %v, want ErrHashingBusy", err)
	}
	if len(repository.users) != 0 {
		t.Errorf("persisted users = %d, want 0", len(repository.users))
	}
	if len(issuer.users) != 0 {
		t.Errorf("issued verifications = %d, want 0", len(issuer.users))
	}
}
