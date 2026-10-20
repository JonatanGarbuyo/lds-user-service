package identity_test

import (
	"bytes"
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

type verificationRecord struct {
	challenge   identity.VerificationChallenge
	consumed    bool
	invalidated bool
}

type verificationFixture struct {
	now        time.Time
	users      map[string]identity.User
	usersByID  map[string]identity.User
	challenges []*verificationRecord
	nextUserID int
	createErr  error
	deleteErr  error
}

func newVerificationFixture() *verificationFixture {
	return &verificationFixture{
		now:       time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC),
		users:     make(map[string]identity.User),
		usersByID: make(map[string]identity.User),
	}
}

func (f *verificationFixture) addUser(email string, verified bool) identity.User {
	f.nextUserID++
	user := identity.User{
		ID:            fmt.Sprintf("user-%d", f.nextUserID),
		Email:         email,
		EmailVerified: verified,
		Status:        identity.StatusActive,
		CreatedAt:     f.now,
		UpdatedAt:     f.now,
	}
	f.users[email] = user
	f.usersByID[user.ID] = user
	return user
}

func (f *verificationFixture) Create(_ context.Context, newUser identity.NewUser) (identity.User, error) {
	if f.createErr != nil {
		return identity.User{}, f.createErr
	}
	if _, exists := f.users[newUser.Email]; exists {
		return identity.User{}, identity.ErrEmailAlreadyExists
	}
	user := f.addUser(newUser.Email, false)
	return user, nil
}

func (f *verificationFixture) FindByEmail(_ context.Context, email string) (identity.User, error) {
	user, exists := f.users[email]
	if !exists {
		return identity.User{}, identity.ErrUserNotFound
	}
	return user, nil
}

func (f *verificationFixture) CreateChallenge(
	_ context.Context,
	userID, codeHash string,
	now, expiresAt time.Time,
	resendCooldown time.Duration,
) (identity.VerificationChallenge, error) {
	if f.createErr != nil {
		return identity.VerificationChallenge{}, f.createErr
	}

	lastCreatedAt := time.Time{}
	for _, record := range f.challenges {
		if record.challenge.UserID == userID && record.challenge.CreatedAt.After(lastCreatedAt) {
			lastCreatedAt = record.challenge.CreatedAt
		}
	}
	if !lastCreatedAt.IsZero() && now.Sub(lastCreatedAt) < resendCooldown {
		return identity.VerificationChallenge{}, identity.ErrResendTooSoon
	}

	for _, record := range f.challenges {
		if record.challenge.UserID == userID && !record.consumed && !record.invalidated {
			record.invalidated = true
		}
	}

	challenge := identity.VerificationChallenge{
		ID:        fmt.Sprintf("challenge-%d", len(f.challenges)+1),
		UserID:    userID,
		CodeHash:  codeHash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	f.challenges = append(f.challenges, &verificationRecord{challenge: challenge})
	return challenge, nil
}

func (f *verificationFixture) DeleteChallenge(_ context.Context, challengeID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for index, record := range f.challenges {
		if record.challenge.ID == challengeID {
			f.challenges = append(f.challenges[:index], f.challenges[index+1:]...)
			return nil
		}
	}
	return nil
}

func (f *verificationFixture) FindActiveChallengeByEmail(
	_ context.Context,
	email string,
	now time.Time,
	maxAttempts int,
) (identity.VerificationChallenge, error) {
	user, exists := f.users[email]
	if !exists {
		return identity.VerificationChallenge{}, identity.ErrChallengeNotFound
	}
	for index := len(f.challenges) - 1; index >= 0; index-- {
		record := f.challenges[index]
		if record.challenge.UserID != user.ID || record.consumed || record.invalidated {
			continue
		}
		if !record.challenge.ExpiresAt.After(now) || record.challenge.Attempts >= maxAttempts {
			continue
		}
		record.challenge.Email = email
		return record.challenge, nil
	}
	return identity.VerificationChallenge{}, identity.ErrChallengeNotFound
}

func (f *verificationFixture) RecordFailedAttempt(_ context.Context, challengeID string, now time.Time, maxAttempts int) error {
	record := f.findChallenge(challengeID)
	if record == nil || record.consumed || record.invalidated || !record.challenge.ExpiresAt.After(now) || record.challenge.Attempts >= maxAttempts {
		return identity.ErrChallengeInactive
	}
	record.challenge.Attempts++
	if record.challenge.Attempts >= maxAttempts {
		record.invalidated = true
	}
	return nil
}

func (f *verificationFixture) ConsumeAndVerify(_ context.Context, challengeID string, now time.Time, maxAttempts int) (identity.User, error) {
	record := f.findChallenge(challengeID)
	if record == nil || record.consumed || record.invalidated || !record.challenge.ExpiresAt.After(now) || record.challenge.Attempts >= maxAttempts {
		return identity.User{}, identity.ErrChallengeInactive
	}
	record.consumed = true

	user, exists := f.usersByID[record.challenge.UserID]
	if !exists {
		return identity.User{}, identity.ErrUserNotFound
	}
	if !user.EmailVerified {
		user.EmailVerified = true
		user.UpdatedAt = now
		f.users[user.Email] = user
		f.usersByID[user.ID] = user
	}
	return user, nil
}

func (f *verificationFixture) findChallenge(challengeID string) *verificationRecord {
	for _, record := range f.challenges {
		if record.challenge.ID == challengeID {
			return record
		}
	}
	return nil
}

type fixedCodeGenerator struct {
	codes []string
	index int
	err   error
}

func (g *fixedCodeGenerator) Generate() (string, error) {
	if g.err != nil {
		return "", g.err
	}
	if len(g.codes) == 0 {
		return "", errors.New("no codes configured")
	}
	code := g.codes[g.index%len(g.codes)]
	g.index++
	return code, nil
}

type testSecretHasher struct{}

func (testSecretHasher) Hash(secret string) (string, error) {
	return "hash:" + secret, nil
}

func (testSecretHasher) Verify(secret, encoded string) (bool, error) {
	return encoded == "hash:"+secret, nil
}

type recordingVerificationSender struct {
	messages []identity.VerificationEmail
	err      error
}

func (s *recordingVerificationSender) SendVerificationCode(_ context.Context, message identity.VerificationEmail) error {
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, message)
	return nil
}

type allowAllLimiter struct{}

func (allowAllLimiter) Allow(string) (bool, time.Duration) {
	return true, 0
}

type denyLimiter struct {
	retryAfter time.Duration
}

func (l denyLimiter) Allow(string) (bool, time.Duration) {
	return false, l.retryAfter
}

func newVerificationService(t *testing.T, fixture *verificationFixture, sender *recordingVerificationSender, codes ...string) *identity.EmailVerificationService {
	t.Helper()

	return identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          fixture,
		Challenges:     fixture,
		Hasher:         testSecretHasher{},
		Sender:         sender,
		RequestLimiter: allowAllLimiter{},
		ConfirmLimiter: allowAllLimiter{},
		Now:            func() time.Time { return fixture.now },
		CodeGenerator:  &fixedCodeGenerator{codes: codes},
	})
}

func TestIssueForUserPersistsHashedChallengeAndSendsCode(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	sender := &recordingVerificationSender{}
	service := newVerificationService(t, fixture, sender, "012345")

	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("IssueForUser() error = %v", err)
	}

	if len(sender.messages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(sender.messages))
	}
	message := sender.messages[0]
	if message.To != user.Email {
		t.Errorf("message.To = %q, want %q", message.To, user.Email)
	}
	if message.Code != "012345" {
		t.Errorf("message.Code = %q, want 012345", message.Code)
	}
	if want := fixture.now.Add(10 * time.Minute); !message.ExpiresAt.Equal(want) {
		t.Errorf("message.ExpiresAt = %v, want %v", message.ExpiresAt, want)
	}

	if len(fixture.challenges) != 1 {
		t.Fatalf("challenges = %d, want 1", len(fixture.challenges))
	}
	stored := fixture.challenges[0].challenge
	if stored.CodeHash == "012345" {
		t.Error("verification code was persisted in plaintext")
	}
	if stored.CodeHash != "hash:012345" {
		t.Errorf("stored code hash = %q, want the hasher output", stored.CodeHash)
	}
	if !stored.ExpiresAt.Equal(fixture.now.Add(10 * time.Minute)) {
		t.Errorf("stored expiresAt = %v, want 10 minutes after issuance", stored.ExpiresAt)
	}
	if fixture.users[user.Email].EmailVerified {
		t.Error("email was verified before confirmation")
	}
}

func TestRequestIsSilentForUnknownEmails(t *testing.T) {
	fixture := newVerificationFixture()
	sender := &recordingVerificationSender{}
	service := newVerificationService(t, fixture, sender, "012345")

	err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
		Email:    "unknown@example.com",
		ClientIP: "203.0.113.1",
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if len(sender.messages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(sender.messages))
	}
	if len(fixture.challenges) != 0 {
		t.Errorf("challenges = %d, want 0", len(fixture.challenges))
	}
}

func TestRequestSendsCodeForUnverifiedUserAndSkipsVerifiedUser(t *testing.T) {
	fixture := newVerificationFixture()
	unverified := fixture.addUser("person@example.com", false)
	verified := fixture.addUser("verified@example.com", true)
	sender := &recordingVerificationSender{}
	service := newVerificationService(t, fixture, sender, "012345")

	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
		Email:    unverified.Email,
		ClientIP: "203.0.113.1",
	}); err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if len(sender.messages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(sender.messages))
	}

	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
		Email:    verified.Email,
		ClientIP: "203.0.113.1",
	}); err != nil {
		t.Fatalf("Request() for verified user error = %v", err)
	}
	if len(sender.messages) != 1 {
		t.Errorf("sent messages after verified request = %d, want 1", len(sender.messages))
	}
}

func TestRequestIgnoresAlreadyVerifiedRace(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	fixture.createErr = identity.ErrEmailAlreadyVerified
	sender := &recordingVerificationSender{}
	service := newVerificationService(t, fixture, sender, "012345")

	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{Email: user.Email}); err != nil {
		t.Fatalf("Request() error = %v, want nil when the email was verified concurrently", err)
	}
	if len(sender.messages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(sender.messages))
	}
}

func TestRequestRespectsResendCooldown(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	sender := &recordingVerificationSender{}
	service := newVerificationService(t, fixture, sender, "111111", "222222")

	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{Email: user.Email}); err != nil {
		t.Fatalf("first Request() error = %v", err)
	}

	fixture.now = fixture.now.Add(59 * time.Second)
	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{Email: user.Email}); err != nil {
		t.Fatalf("Request() during cooldown error = %v", err)
	}
	if len(sender.messages) != 1 {
		t.Errorf("sent messages during cooldown = %d, want 1", len(sender.messages))
	}

	fixture.now = fixture.now.Add(time.Second)
	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{Email: user.Email}); err != nil {
		t.Fatalf("Request() after cooldown error = %v", err)
	}
	if len(sender.messages) != 2 {
		t.Errorf("sent messages after cooldown = %d, want 2", len(sender.messages))
	}
	if len(fixture.challenges) != 2 {
		t.Errorf("challenges = %d, want 2", len(fixture.challenges))
	}
	if !fixture.challenges[0].invalidated {
		t.Error("previous challenge was not invalidated")
	}
}

func TestIssueForUserDiscardsChallengeWhenDeliveryFails(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	sender := &recordingVerificationSender{err: errors.New("mail transport unavailable")}
	service := newVerificationService(t, fixture, sender, "012345")

	err := service.IssueForUser(context.Background(), user)
	if !errors.Is(err, identity.ErrVerificationDelivery) {
		t.Fatalf("IssueForUser() error = %v, want ErrVerificationDelivery", err)
	}
	if strings.Contains(err.Error(), "012345") {
		t.Errorf("delivery error exposed the verification code: %v", err)
	}
	if len(fixture.challenges) != 0 {
		t.Errorf("challenges = %d, want 0 after delivery failure", len(fixture.challenges))
	}
}

func TestConfirmVerifiesEmailWithoutChangingStatus(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	sender := &recordingVerificationSender{}
	service := newVerificationService(t, fixture, sender, "012345")

	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("IssueForUser() error = %v", err)
	}

	fixture.now = fixture.now.Add(2 * time.Minute)
	confirmed, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "012345",
	})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !confirmed.EmailVerified {
		t.Error("confirmed.EmailVerified = false, want true")
	}
	if confirmed.Status != identity.StatusActive {
		t.Errorf("confirmed.Status = %q, want active", confirmed.Status)
	}
	if !confirmed.UpdatedAt.Equal(fixture.now) {
		t.Errorf("confirmed.UpdatedAt = %v, want %v", confirmed.UpdatedAt, fixture.now)
	}
	if !fixture.challenges[0].consumed {
		t.Error("challenge was not consumed")
	}
	if len(sender.messages) != 1 {
		t.Errorf("confirmation sent %d emails, want 0 additional", len(sender.messages)-1)
	}

	_, err = service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "012345",
	})
	if !errors.Is(err, identity.ErrInvalidVerificationCode) {
		t.Fatalf("second Confirm() error = %v, want ErrInvalidVerificationCode", err)
	}
}

func TestConfirmRejectsWrongCodeAndCountsAttempts(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	service := newVerificationService(t, fixture, &recordingVerificationSender{}, "012345")

	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("IssueForUser() error = %v", err)
	}

	_, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "999999",
	})
	if !errors.Is(err, identity.ErrInvalidVerificationCode) {
		t.Fatalf("Confirm() error = %v, want ErrInvalidVerificationCode", err)
	}
	if fixture.challenges[0].challenge.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", fixture.challenges[0].challenge.Attempts)
	}
	if fixture.users[user.Email].EmailVerified {
		t.Error("email was verified after a wrong code")
	}

	if _, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "012345",
	}); err != nil {
		t.Fatalf("Confirm() with correct code after one failure error = %v", err)
	}
}

func TestConfirmLocksChallengeAfterMaximumAttempts(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	service := newVerificationService(t, fixture, &recordingVerificationSender{}, "012345")

	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("IssueForUser() error = %v", err)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		_, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
			Email: user.Email,
			Code:  "999999",
		})
		if !errors.Is(err, identity.ErrInvalidVerificationCode) {
			t.Fatalf("attempt %d error = %v, want ErrInvalidVerificationCode", attempt, err)
		}
	}

	if fixture.challenges[0].challenge.Attempts != 5 {
		t.Errorf("attempts = %d, want 5", fixture.challenges[0].challenge.Attempts)
	}
	if !fixture.challenges[0].invalidated {
		t.Error("challenge was not invalidated after five failed attempts")
	}

	_, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "012345",
	})
	if !errors.Is(err, identity.ErrInvalidVerificationCode) {
		t.Fatalf("Confirm() after maximum attempts error = %v, want ErrInvalidVerificationCode", err)
	}
}

func TestConfirmRejectsExpiredChallenge(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	service := newVerificationService(t, fixture, &recordingVerificationSender{}, "012345")

	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("IssueForUser() error = %v", err)
	}

	fixture.now = fixture.now.Add(10*time.Minute + time.Second)
	_, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "012345",
	})
	if !errors.Is(err, identity.ErrInvalidVerificationCode) {
		t.Fatalf("Confirm() error = %v, want ErrInvalidVerificationCode", err)
	}
	if fixture.users[user.Email].EmailVerified {
		t.Error("expired challenge verified the email")
	}
}

func TestNewChallengeInvalidatesPreviousCode(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	service := newVerificationService(t, fixture, &recordingVerificationSender{}, "111111", "222222")

	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("first IssueForUser() error = %v", err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	if err := service.IssueForUser(context.Background(), user); err != nil {
		t.Fatalf("second IssueForUser() error = %v", err)
	}

	_, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "111111",
	})
	if !errors.Is(err, identity.ErrInvalidVerificationCode) {
		t.Fatalf("Confirm() with previous code error = %v, want ErrInvalidVerificationCode", err)
	}

	if _, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "222222",
	}); err != nil {
		t.Fatalf("Confirm() with current code error = %v", err)
	}
}

func TestConfirmValidatesEmailAndCodeFormat(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		code      string
		wantField string
	}{
		{name: "invalid email", email: "not-an-email", code: "012345", wantField: "email"},
		{name: "short code", email: "person@example.com", code: "12345", wantField: "code"},
		{name: "non numeric code", email: "person@example.com", code: "abcdef", wantField: "code"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture()
			service := newVerificationService(t, fixture, &recordingVerificationSender{}, "012345")

			_, err := service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
				Email: test.email,
				Code:  test.code,
			})
			var validationErr *identity.ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("Confirm() error = %T %v, want *identity.ValidationError", err, err)
			}
			if validationErr.Fields[test.wantField] == "" {
				t.Errorf("fields = %v, want an entry for %q", validationErr.Fields, test.wantField)
			}
		})
	}
}

func TestRequestAndConfirmApplyRateLimits(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	sender := &recordingVerificationSender{}

	service := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          fixture,
		Challenges:     fixture,
		Hasher:         testSecretHasher{},
		Sender:         sender,
		RequestLimiter: denyLimiter{retryAfter: 30 * time.Second},
		ConfirmLimiter: denyLimiter{retryAfter: 45 * time.Second},
		Now:            func() time.Time { return fixture.now },
		CodeGenerator:  &fixedCodeGenerator{codes: []string{"012345"}},
	})

	err := service.Request(context.Background(), identity.RequestEmailVerificationInput{Email: user.Email})
	if !errors.Is(err, identity.ErrRateLimited) {
		t.Fatalf("Request() error = %v, want ErrRateLimited", err)
	}
	var rateLimitErr *identity.RateLimitError
	if !errors.As(err, &rateLimitErr) || rateLimitErr.RetryAfter != 30*time.Second {
		t.Errorf("Request() retry after = %v, want 30s", rateLimitErr)
	}
	if len(sender.messages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(sender.messages))
	}

	_, err = service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email: user.Email,
		Code:  "012345",
	})
	if !errors.Is(err, identity.ErrRateLimited) {
		t.Fatalf("Confirm() error = %v, want ErrRateLimited", err)
	}
}

func TestGenerateVerificationCodeIsSixDigits(t *testing.T) {
	generator := identity.NewVerificationCodeGeneratorWithReader(bytes.NewReader(make([]byte, 60)))

	for range 20 {
		code, err := generator.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("code = %q, want 6 digits", code)
		}
		if code != "000000" {
			t.Errorf("code = %q, want 000000 for a zero-valued random source", code)
		}
	}
}

func TestGenerateVerificationCodePropagatesRandomFailure(t *testing.T) {
	generator := identity.NewVerificationCodeGeneratorWithReader(bytes.NewReader(nil))

	if _, err := generator.Generate(); err == nil {
		t.Fatal("Generate() error = nil, want an error")
	}
}

type denyHashLimiter struct{}

func (denyHashLimiter) TryAcquire() bool { return false }
func (denyHashLimiter) Release()         {}

type countingSecretHasher struct {
	hashCalls   atomic.Int32
	verifyCalls atomic.Int32
}

func (h *countingSecretHasher) Hash(secret string) (string, error) {
	h.hashCalls.Add(1)
	return "hash:" + secret, nil
}

func (h *countingSecretHasher) Verify(secret, encoded string) (bool, error) {
	h.verifyCalls.Add(1)
	return encoded == "hash:"+secret, nil
}

type gatedSecretHasher struct {
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	hashCalls   atomic.Int32
	verifyCalls atomic.Int32
}

func newGatedSecretHasher() *gatedSecretHasher {
	return &gatedSecretHasher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (h *gatedSecretHasher) Hash(secret string) (string, error) {
	h.hashCalls.Add(1)
	h.startOnce.Do(func() { close(h.started) })
	<-h.release
	return "hash:" + secret, nil
}

func (h *gatedSecretHasher) Verify(secret, encoded string) (bool, error) {
	h.verifyCalls.Add(1)
	return encoded == "hash:"+secret, nil
}

type eventRecordingHasher struct {
	events *[]string
	mutex  *sync.Mutex
}

func (h eventRecordingHasher) Hash(secret string) (string, error) {
	h.mutex.Lock()
	*h.events = append(*h.events, "hash")
	h.mutex.Unlock()
	return "hash:" + secret, nil
}

func (h eventRecordingHasher) Verify(secret, encoded string) (bool, error) {
	return encoded == "hash:"+secret, nil
}

func TestRequestPerformsHashingBeforeUserLookup(t *testing.T) {
	fixture := newVerificationFixture()
	events := []string{}
	mutex := &sync.Mutex{}
	hasher := eventRecordingHasher{events: &events, mutex: mutex}
	users := &eventRecordingUserRepository{
		UserRepository: fixture,
		events:         &events,
		mutex:          mutex,
	}
	service := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          users,
		Challenges:     fixture,
		Hasher:         hasher,
		HashLimiter:    identity.NewHashLimiter(2),
		Sender:         &recordingVerificationSender{},
		RequestLimiter: allowAllLimiter{},
		ConfirmLimiter: allowAllLimiter{},
		Now:            func() time.Time { return fixture.now },
		CodeGenerator:  &fixedCodeGenerator{codes: []string{"012345"}},
	})

	if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
		Email:    "missing@example.com",
		ClientIP: "203.0.113.10",
	}); err != nil {
		t.Fatalf("Request() error = %v", err)
	}

	mutex.Lock()
	defer mutex.Unlock()
	if got := strings.Join(events, ","); got != "hash,lookup" {
		t.Errorf("event order = %q, want hash,lookup", got)
	}
}

type eventRecordingUserRepository struct {
	identity.UserRepository
	events *[]string
	mutex  *sync.Mutex
}

func (r *eventRecordingUserRepository) FindByEmail(ctx context.Context, email string) (identity.User, error) {
	r.mutex.Lock()
	*r.events = append(*r.events, "lookup")
	r.mutex.Unlock()
	return r.UserRepository.FindByEmail(ctx, email)
}

func TestRequestHashesForUnknownAccountsToo(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		wantMessages int
	}{
		{name: "unknown account", email: "missing@example.com", wantMessages: 0},
		{name: "existing account", email: "person@example.com", wantMessages: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerificationFixture()
			fixture.addUser("person@example.com", false)
			sender := &recordingVerificationSender{}
			hasher := &countingSecretHasher{}
			service := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
				Users:          fixture,
				Challenges:     fixture,
				Hasher:         hasher,
				HashLimiter:    identity.NewHashLimiter(2),
				Sender:         sender,
				RequestLimiter: allowAllLimiter{},
				ConfirmLimiter: allowAllLimiter{},
				Now:            func() time.Time { return fixture.now },
				CodeGenerator:  &fixedCodeGenerator{codes: []string{"012345"}},
			})

			if err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
				Email:    test.email,
				ClientIP: "203.0.113.10",
			}); err != nil {
				t.Fatalf("Request() error = %v", err)
			}
			if calls := hasher.hashCalls.Load(); calls != 1 {
				t.Errorf("hash calls = %d, want 1", calls)
			}
			if messages := len(sender.messages); messages != test.wantMessages {
				t.Errorf("sent messages = %d, want %d", messages, test.wantMessages)
			}
		})
	}
}

func TestIssueForUserRejectsWhenHashingIsSaturated(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	sender := &recordingVerificationSender{}
	hasher := &countingSecretHasher{}
	service := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          fixture,
		Challenges:     fixture,
		Hasher:         hasher,
		HashLimiter:    denyHashLimiter{},
		Sender:         sender,
		RequestLimiter: allowAllLimiter{},
		ConfirmLimiter: allowAllLimiter{},
		Now:            func() time.Time { return fixture.now },
		CodeGenerator:  &fixedCodeGenerator{codes: []string{"012345"}},
	})

	if err := service.IssueForUser(context.Background(), user); !errors.Is(err, identity.ErrHashingBusy) {
		t.Fatalf("IssueForUser() error = %v, want ErrHashingBusy", err)
	}
	if calls := hasher.hashCalls.Load(); calls != 0 {
		t.Errorf("hash calls = %d, want 0", calls)
	}
	if len(sender.messages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(sender.messages))
	}
	if len(fixture.challenges) != 0 {
		t.Errorf("challenges = %d, want 0", len(fixture.challenges))
	}
}

func TestRequestAndConfirmRejectWhenHashingIsSaturated(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	fixture.challenges = append(fixture.challenges, &verificationRecord{challenge: identity.VerificationChallenge{
		ID:        "challenge-1",
		UserID:    user.ID,
		CodeHash:  "hash:012345",
		CreatedAt: fixture.now,
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}})
	sender := &recordingVerificationSender{}
	hasher := &countingSecretHasher{}
	service := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          fixture,
		Challenges:     fixture,
		Hasher:         hasher,
		HashLimiter:    denyHashLimiter{},
		Sender:         sender,
		RequestLimiter: allowAllLimiter{},
		ConfirmLimiter: allowAllLimiter{},
		Now:            func() time.Time { return fixture.now },
		CodeGenerator:  &fixedCodeGenerator{codes: []string{"012345"}},
	})

	err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
		Email:    user.Email,
		ClientIP: "203.0.113.10",
	})
	if !errors.Is(err, identity.ErrHashingBusy) {
		t.Fatalf("Request() error = %v, want ErrHashingBusy", err)
	}

	_, err = service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email:    user.Email,
		Code:     "012345",
		ClientIP: "203.0.113.10",
	})
	if !errors.Is(err, identity.ErrHashingBusy) {
		t.Fatalf("Confirm() error = %v, want ErrHashingBusy", err)
	}

	if calls := hasher.hashCalls.Load(); calls != 0 {
		t.Errorf("hash calls = %d, want 0", calls)
	}
	if calls := hasher.verifyCalls.Load(); calls != 0 {
		t.Errorf("verify calls = %d, want 0", calls)
	}
	if attempts := fixture.challenges[0].challenge.Attempts; attempts != 0 {
		t.Errorf("attempts = %d, want 0", attempts)
	}
	if fixture.challenges[0].consumed {
		t.Error("challenge was consumed while hashing was saturated")
	}
	if len(sender.messages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(sender.messages))
	}
}

func TestRegistrationAndVerificationShareHashLimit(t *testing.T) {
	fixture := newVerificationFixture()
	user := fixture.addUser("person@example.com", false)
	fixture.challenges = append(fixture.challenges, &verificationRecord{challenge: identity.VerificationChallenge{
		ID:        "challenge-1",
		UserID:    user.ID,
		CodeHash:  "hash:012345",
		CreatedAt: fixture.now,
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}})
	hasher := newGatedSecretHasher()
	limiter := identity.NewHashLimiter(1)
	service := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          fixture,
		Challenges:     fixture,
		Hasher:         hasher,
		HashLimiter:    limiter,
		Sender:         &recordingVerificationSender{},
		RequestLimiter: allowAllLimiter{},
		ConfirmLimiter: allowAllLimiter{},
		Now:            func() time.Time { return fixture.now },
		CodeGenerator:  &fixedCodeGenerator{codes: []string{"012345"}},
	})
	register := identity.NewRegisterUserWithLimiter(fixture, hasher, nil, limiter)

	registerDone := make(chan error, 1)
	go func() {
		_, err := register.Execute(context.Background(), identity.RegisterUserInput{
			Email:    "new@example.com",
			Password: "correct horse battery",
		})
		registerDone <- err
	}()

	<-hasher.started

	err := service.Request(context.Background(), identity.RequestEmailVerificationInput{
		Email:    user.Email,
		ClientIP: "203.0.113.10",
	})
	if !errors.Is(err, identity.ErrHashingBusy) {
		t.Fatalf("Request() while registration hashes error = %v, want ErrHashingBusy", err)
	}

	_, err = service.Confirm(context.Background(), identity.ConfirmEmailVerificationInput{
		Email:    user.Email,
		Code:     "012345",
		ClientIP: "203.0.113.10",
	})
	if !errors.Is(err, identity.ErrHashingBusy) {
		t.Fatalf("Confirm() while registration hashes error = %v, want ErrHashingBusy", err)
	}
	if attempts := fixture.challenges[0].challenge.Attempts; attempts != 0 {
		t.Errorf("attempts = %d, want 0", attempts)
	}
	if calls := hasher.verifyCalls.Load(); calls != 0 {
		t.Errorf("verify calls = %d, want 0", calls)
	}

	close(hasher.release)
	if err := <-registerDone; err != nil {
		t.Fatalf("registration error = %v", err)
	}
}
