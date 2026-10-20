//go:build integration

package httpapi_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/password"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testmail"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testpg"
	platformpostgres "github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/ratelimit"
)

type sequenceCodeGenerator struct {
	mu   sync.Mutex
	next int
}

func (g *sequenceCodeGenerator) Generate() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	return fmt.Sprintf("%06d", g.next), nil
}

type verificationIntegrationServer struct {
	url       string
	db        *platformpostgres.DB
	server    *httptest.Server
	sender    *testmail.Sender
	logs      *bytes.Buffer
	closeOnce sync.Once
}

func newVerificationIntegrationServer(t *testing.T) *verificationIntegrationServer {
	t.Helper()
	return newVerificationIntegrationServerWith(t, nil, 1000, 1000)
}

func newVerificationIntegrationServerWith(t *testing.T, sender *testmail.Sender, requestLimit, confirmLimit int) *verificationIntegrationServer {
	t.Helper()

	db := testpg.OpenDatabase(t)
	if sender == nil {
		sender = testmail.New()
	}

	users := identitypostgres.NewRepository(db.Pool)
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	verification := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          users,
		Challenges:     identitypostgres.NewVerificationRepository(db.Pool),
		Hasher:         password.New(),
		Sender:         sender,
		RequestLimiter: ratelimit.New(requestLimit, time.Minute),
		ConfirmLimiter: ratelimit.New(confirmLimit, time.Minute),
		Now:            time.Now,
		CodeGenerator:  &sequenceCodeGenerator{},
	})
	register := identity.NewRegisterUser(users, password.New(), verification)

	mux := http.NewServeMux()
	httpapi.New(register, logger).Register(mux)
	httpapi.NewEmailVerification(verification, logger).Register(mux)
	server := httptest.NewServer(mux)

	result := &verificationIntegrationServer{
		url:    server.URL,
		db:     db,
		server: server,
		sender: sender,
		logs:   logs,
	}
	t.Cleanup(result.Close)
	return result
}

func (s *verificationIntegrationServer) Close() {
	s.closeOnce.Do(func() {
		s.server.Close()
		s.db.Close()
	})
}

func registerUserForVerification(t *testing.T, server *verificationIntegrationServer, email string) userJSON {
	t.Helper()

	status, headers, body := postPath(t, server.url, "/v1/users",
		fmt.Sprintf(`{"email":%q,"password":"correct horse battery"}`, email), jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("register status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	if headers.Get("Set-Cookie") != "" || headers.Get("Authorization") != "" {
		t.Errorf("registration exposed credentials")
	}
	return decodeUser(t, body)
}

func requestVerificationCode(t *testing.T, server *verificationIntegrationServer, email string) (int, http.Header, []byte) {
	t.Helper()
	return postPath(t, server.url, "/v1/auth/email-verification/request",
		fmt.Sprintf(`{"email":%q}`, email), jsonHeaders())
}

func confirmVerificationCode(t *testing.T, server *verificationIntegrationServer, email, code string) (int, http.Header, []byte) {
	t.Helper()
	return postPath(t, server.url, "/v1/auth/email-verification/confirm",
		fmt.Sprintf(`{"email":%q,"code":%q}`, email, code), jsonHeaders())
}

func ageChallenges(t *testing.T, server *verificationIntegrationServer, email string, age time.Duration) {
	t.Helper()
	_, err := server.db.Pool.Exec(
		context.Background(),
		`UPDATE email_verification_challenges
		 SET created_at = now() - ($2 * interval '1 second')
		 WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
		email,
		age.Seconds(),
	)
	if err != nil {
		t.Fatalf("age verification challenges: %v", err)
	}
}

func expireChallenges(t *testing.T, server *verificationIntegrationServer, email string) {
	t.Helper()
	_, err := server.db.Pool.Exec(
		context.Background(),
		`UPDATE email_verification_challenges
		 SET created_at = now() - interval '11 minutes',
		     expires_at = now() - interval '1 minute'
		 WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
		email,
	)
	if err != nil {
		t.Fatalf("expire verification challenges: %v", err)
	}
}

func challengeStats(t *testing.T, server *verificationIntegrationServer, email string) (total, active int, codeHash string) {
	t.Helper()
	err := server.db.Pool.QueryRow(
		context.Background(),
		`SELECT count(*),
		        count(*) FILTER (WHERE c.consumed_at IS NULL AND c.invalidated_at IS NULL),
		        coalesce(max(c.code_hash) FILTER (WHERE c.created_at = (SELECT max(created_at) FROM email_verification_challenges WHERE user_id = u.id)), '')
		 FROM email_verification_challenges c
		 JOIN users u ON u.id = c.user_id
		 WHERE u.email = $1`,
		email,
	).Scan(&total, &active, &codeHash)
	if err != nil {
		t.Fatalf("query challenge stats: %v", err)
	}
	return total, active, codeHash
}

func storedUserState(t *testing.T, server *verificationIntegrationServer, email string) (verified bool, status string) {
	t.Helper()
	err := server.db.Pool.QueryRow(
		context.Background(),
		`SELECT email_verified, status FROM users WHERE email = $1`,
		email,
	).Scan(&verified, &status)
	if err != nil {
		t.Fatalf("query stored user: %v", err)
	}
	return verified, status
}

func TestRegisterSendsVerificationAndConfirmationVerifiesEmail(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	email := uniqueIntegrationEmail(t)

	user := registerUserForVerification(t, server, email)
	if user.EmailVerified {
		t.Error("user.emailVerified = true before confirmation")
	}
	if user.Status != "active" {
		t.Errorf("user.status = %q, want active", user.Status)
	}

	if server.sender.Count() != 1 {
		t.Fatalf("sent emails = %d, want 1", server.sender.Count())
	}
	message, ok := server.sender.Last()
	if !ok {
		t.Fatal("no verification email was sent")
	}
	if message.To != email {
		t.Errorf("message.To = %q, want %q", message.To, email)
	}
	if len(message.Code) != 6 {
		t.Errorf("code = %q, want 6 digits", message.Code)
	}
	total, active, codeHash := challengeStats(t, server, email)
	if total != 1 || active != 1 {
		t.Errorf("total/active challenges = %d/%d, want 1/1", total, active)
	}
	if codeHash == message.Code || strings.Contains(codeHash, message.Code) {
		t.Error("verification code was stored in plaintext")
	}
	if !strings.HasPrefix(codeHash, "$argon2id$") {
		t.Errorf("code hash = %q, want an Argon2id PHC string", codeHash)
	}

	verified, status := storedUserState(t, server, email)
	if verified {
		t.Error("stored email_verified = true before confirmation")
	}
	if status != "active" {
		t.Errorf("stored status = %q, want active", status)
	}

	statusCode, headers, body := confirmVerificationCode(t, server, email, message.Code)
	if statusCode != http.StatusOK {
		t.Fatalf("confirm status = %d, want %d; body = %s", statusCode, http.StatusOK, body)
	}
	if headers.Get("Set-Cookie") != "" || headers.Get("Authorization") != "" {
		t.Errorf("confirmation exposed credentials: cookie=%q authorization=%q", headers.Get("Set-Cookie"), headers.Get("Authorization"))
	}
	confirmed := decodeUser(t, body)
	if !confirmed.EmailVerified {
		t.Error("confirmed.emailVerified = false, want true")
	}
	if confirmed.Status != "active" {
		t.Errorf("confirmed.status = %q, want active", confirmed.Status)
	}

	verified, status = storedUserState(t, server, email)
	if !verified {
		t.Error("stored email_verified = false after confirmation")
	}
	if status != "active" {
		t.Errorf("stored status = %q, want active", status)
	}
	_, active, _ = challengeStats(t, server, email)
	if active != 0 {
		t.Errorf("active challenges after confirmation = %d, want 0", active)
	}

	statusCode, _, body = confirmVerificationCode(t, server, email, message.Code)
	if statusCode != http.StatusBadRequest {
		t.Fatalf("second confirm status = %d, want %d; body = %s", statusCode, http.StatusBadRequest, body)
	}
	if response := decodeError(t, body); response.Error.Code != "INVALID_VERIFICATION_CODE" {
		t.Errorf("second confirm error.code = %q, want INVALID_VERIFICATION_CODE", response.Error.Code)
	}
}

func TestVerificationRequestIsGenericAndRespectsCooldown(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	existingEmail := uniqueIntegrationEmail(t)
	unknownEmail := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, existingEmail)

	status, _, body := requestVerificationCode(t, server, existingEmail)
	if status != http.StatusAccepted {
		t.Fatalf("existing request status = %d, want %d; body = %s", status, http.StatusAccepted, body)
	}
	if server.sender.Count() != 1 {
		t.Errorf("sent emails during cooldown = %d, want 1", server.sender.Count())
	}

	status, _, unknownBody := requestVerificationCode(t, server, unknownEmail)
	if status != http.StatusAccepted {
		t.Fatalf("unknown request status = %d, want %d; body = %s", status, http.StatusAccepted, unknownBody)
	}
	if !bytes.Equal(body, unknownBody) {
		t.Errorf("responses differ for known and unknown emails: %s vs %s", body, unknownBody)
	}

	ageChallenges(t, server, existingEmail, 61*time.Second)
	status, _, _ = requestVerificationCode(t, server, existingEmail)
	if status != http.StatusAccepted {
		t.Fatalf("request after cooldown status = %d, want %d", status, http.StatusAccepted)
	}
	if server.sender.Count() != 2 {
		t.Fatalf("sent emails after cooldown = %d, want 2", server.sender.Count())
	}
	total, active, _ := challengeStats(t, server, existingEmail)
	if total != 2 || active != 1 {
		t.Errorf("total/active challenges = %d/%d, want 2/1", total, active)
	}
}

func TestNewChallengeInvalidatesPreviousCode(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, email)

	first, ok := server.sender.Last()
	if !ok {
		t.Fatal("registration did not send a code")
	}

	ageChallenges(t, server, email, 61*time.Second)
	if status, _, body := requestVerificationCode(t, server, email); status != http.StatusAccepted {
		t.Fatalf("request status = %d, want %d; body = %s", status, http.StatusAccepted, body)
	}
	second, ok := server.sender.Last()
	if !ok || second.Code == first.Code {
		t.Fatal("resend did not issue a new code")
	}

	status, _, body := confirmVerificationCode(t, server, email, first.Code)
	if status != http.StatusBadRequest {
		t.Fatalf("confirm with previous code status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
	}
	if response := decodeError(t, body); response.Error.Code != "INVALID_VERIFICATION_CODE" {
		t.Errorf("error.code = %q, want INVALID_VERIFICATION_CODE", response.Error.Code)
	}

	status, _, body = confirmVerificationCode(t, server, email, second.Code)
	if status != http.StatusOK {
		t.Fatalf("confirm with current code status = %d, want %d; body = %s", status, http.StatusOK, body)
	}
}

func TestConfirmRejectsExpiredConsumedAndExhaustedCodes(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		server := newVerificationIntegrationServer(t)
		email := uniqueIntegrationEmail(t)
		registerUserForVerification(t, server, email)
		message, _ := server.sender.Last()

		expireChallenges(t, server, email)
		status, _, body := confirmVerificationCode(t, server, email, message.Code)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
		}
		if response := decodeError(t, body); response.Error.Code != "INVALID_VERIFICATION_CODE" {
			t.Errorf("error.code = %q, want INVALID_VERIFICATION_CODE", response.Error.Code)
		}
	})

	t.Run("maximum attempts", func(t *testing.T) {
		server := newVerificationIntegrationServer(t)
		email := uniqueIntegrationEmail(t)
		registerUserForVerification(t, server, email)
		message, _ := server.sender.Last()

		wrongCode := "999999"
		if message.Code == wrongCode {
			wrongCode = "888888"
		}
		for attempt := 1; attempt <= 5; attempt++ {
			status, _, body := confirmVerificationCode(t, server, email, wrongCode)
			if status != http.StatusBadRequest {
				t.Fatalf("attempt %d status = %d, want %d; body = %s", attempt, status, http.StatusBadRequest, body)
			}
		}

		status, _, body := confirmVerificationCode(t, server, email, message.Code)
		if status != http.StatusBadRequest {
			t.Fatalf("confirm after maximum attempts status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
		}

		var attempts int
		var invalidated bool
		if err := server.db.Pool.QueryRow(
			context.Background(),
			`SELECT c.attempts, c.invalidated_at IS NOT NULL
			 FROM email_verification_challenges c
			 JOIN users u ON u.id = c.user_id
			 WHERE u.email = $1
			 ORDER BY c.created_at DESC LIMIT 1`,
			email,
		).Scan(&attempts, &invalidated); err != nil {
			t.Fatalf("query attempts: %v", err)
		}
		if attempts != 5 {
			t.Errorf("attempts = %d, want 5", attempts)
		}
		if !invalidated {
			t.Error("challenge was not invalidated after maximum attempts")
		}
	})
}

func TestVerificationDoesNotRevealAccountExistence(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	existingEmail := uniqueIntegrationEmail(t)
	unknownEmail := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, existingEmail)
	message, _ := server.sender.Last()

	status, _, existingBody := confirmVerificationCode(t, server, existingEmail, "000000")
	if status != http.StatusBadRequest {
		t.Fatalf("existing confirm status = %d, want %d; body = %s", status, http.StatusBadRequest, existingBody)
	}
	existingResponse := decodeError(t, existingBody)

	status, _, unknownBody := confirmVerificationCode(t, server, unknownEmail, "000000")
	if status != http.StatusBadRequest {
		t.Fatalf("unknown confirm status = %d, want %d; body = %s", status, http.StatusBadRequest, unknownBody)
	}
	unknownResponse := decodeError(t, unknownBody)

	if existingResponse.Error.Code != unknownResponse.Error.Code || existingResponse.Error.Message != unknownResponse.Error.Message {
		t.Errorf("confirm responses reveal account existence: %+v vs %+v", existingResponse.Error, unknownResponse.Error)
	}

	status, _, body := confirmVerificationCode(t, server, existingEmail, message.Code)
	if status != http.StatusOK {
		t.Fatalf("correct confirm status = %d, want %d; body = %s", status, http.StatusOK, body)
	}
}

func TestConcurrentConfirmationSucceedsOnce(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, email)
	message, _ := server.sender.Last()

	const workers = 4
	type result struct {
		status int
		body   []byte
	}
	results := make(chan result, workers)
	start := make(chan struct{})

	for range workers {
		go func() {
			<-start
			status, _, body := confirmVerificationCode(t, server, email, message.Code)
			results <- result{status: status, body: body}
		}()
	}
	close(start)

	var confirmed, rejected, busy int
	for range workers {
		res := <-results
		switch res.status {
		case http.StatusOK:
			confirmed++
		case http.StatusBadRequest:
			rejected++
		case http.StatusServiceUnavailable:
			busy++
		default:
			t.Errorf("unexpected status = %d; body = %s", res.status, res.body)
		}
	}
	if confirmed != 1 || rejected+busy != workers-1 {
		t.Errorf("confirmed = %d, rejected = %d, busy = %d, want 1 and %d", confirmed, rejected, busy, workers-1)
	}

	verified, _ := storedUserState(t, server, email)
	if !verified {
		t.Error("user email was not verified")
	}
}

func TestConcurrentResendLeavesOneActiveChallenge(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, email)
	ageChallenges(t, server, email, 61*time.Second)

	const workers = 4
	statuses := make(chan int, workers)
	start := make(chan struct{})
	for range workers {
		go func() {
			<-start
			status, _, _ := requestVerificationCode(t, server, email)
			statuses <- status
		}()
	}
	close(start)

	for range workers {
		switch status := <-statuses; status {
		case http.StatusAccepted, http.StatusServiceUnavailable:
		default:
			t.Errorf("request status = %d, want %d or %d", status, http.StatusAccepted, http.StatusServiceUnavailable)
		}
	}

	if server.sender.Count() != 2 {
		t.Errorf("sent emails = %d, want 2 (registration plus one resend)", server.sender.Count())
	}
	total, active, _ := challengeStats(t, server, email)
	if total != 2 || active != 1 {
		t.Errorf("total/active challenges = %d/%d, want 2/1", total, active)
	}
}

func TestVerificationDeliveryFailureIsLoggedWithoutClaimingOrLeakingSecrets(t *testing.T) {
	sender := testmail.New()
	sender.Fail(errors.New("mail transport unavailable"))
	server := newVerificationIntegrationServerWith(t, sender, 1000, 1000)
	email := uniqueIntegrationEmail(t)

	status, _, body := postPath(t, server.url, "/v1/users",
		fmt.Sprintf(`{"email":%q,"password":"correct horse battery"}`, email), jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("register status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	user := decodeUser(t, body)
	if user.EmailVerified {
		t.Error("user.emailVerified = true, want false")
	}
	if strings.Contains(strings.ToLower(string(body)), "sent") {
		t.Errorf("response claims delivery: %s", body)
	}
	if sender.Count() != 0 {
		t.Errorf("sent emails = %d, want 0", sender.Count())
	}
	if total, _, _ := challengeStats(t, server, email); total != 0 {
		t.Errorf("challenges = %d, want 0 after delivery failure", total)
	}
	if !strings.Contains(server.logs.String(), "email verification dispatch failed") {
		t.Errorf("logs do not record registration delivery failure: %s", server.logs.String())
	}

	status, _, body = requestVerificationCode(t, server, email)
	if status != http.StatusAccepted {
		t.Fatalf("request status = %d, want %d; body = %s", status, http.StatusAccepted, body)
	}
	if !strings.Contains(server.logs.String(), "email verification dispatch failed") {
		t.Errorf("logs do not record request delivery failure: %s", server.logs.String())
	}
}

func TestVerificationRateLimitsPerIP(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		server := newVerificationIntegrationServerWith(t, nil, 1, 1000)
		email := uniqueIntegrationEmail(t)

		if status, _, _ := requestVerificationCode(t, server, email); status != http.StatusAccepted {
			t.Fatalf("first request status = %d, want %d", status, http.StatusAccepted)
		}
		status, headers, body := requestVerificationCode(t, server, email)
		if status != http.StatusTooManyRequests {
			t.Fatalf("second request status = %d, want %d; body = %s", status, http.StatusTooManyRequests, body)
		}
		if headers.Get("Retry-After") == "" {
			t.Error("Retry-After is empty")
		}
		if response := decodeError(t, body); response.Error.Code != "RATE_LIMITED" {
			t.Errorf("error.code = %q, want RATE_LIMITED", response.Error.Code)
		}
	})

	t.Run("confirm", func(t *testing.T) {
		server := newVerificationIntegrationServerWith(t, nil, 1000, 1)
		email := uniqueIntegrationEmail(t)
		registerUserForVerification(t, server, email)

		if status, _, _ := confirmVerificationCode(t, server, email, "000000"); status != http.StatusBadRequest {
			t.Fatalf("first confirm status = %d, want %d", status, http.StatusBadRequest)
		}
		status, headers, body := confirmVerificationCode(t, server, email, "000000")
		if status != http.StatusTooManyRequests {
			t.Fatalf("second confirm status = %d, want %d; body = %s", status, http.StatusTooManyRequests, body)
		}
		if headers.Get("Retry-After") == "" {
			t.Error("Retry-After is empty")
		}
		if response := decodeError(t, body); response.Error.Code != "RATE_LIMITED" {
			t.Errorf("error.code = %q, want RATE_LIMITED", response.Error.Code)
		}
	})
}

func TestVerificationRateLimitsMatchConfiguredThresholds(t *testing.T) {
	server := newVerificationIntegrationServerWith(t, nil, 10, 20)
	email := uniqueIntegrationEmail(t)

	for attempt := 1; attempt <= 10; attempt++ {
		if status, _, body := requestVerificationCode(t, server, email); status != http.StatusAccepted {
			t.Fatalf("request %d status = %d, want %d; body = %s", attempt, status, http.StatusAccepted, body)
		}
	}
	status, headers, body := requestVerificationCode(t, server, email)
	if status != http.StatusTooManyRequests {
		t.Fatalf("request 11 status = %d, want %d; body = %s", status, http.StatusTooManyRequests, body)
	}
	if headers.Get("Retry-After") == "" {
		t.Error("request Retry-After is empty")
	}
	if response := decodeError(t, body); response.Error.Code != "RATE_LIMITED" {
		t.Errorf("request error.code = %q, want RATE_LIMITED", response.Error.Code)
	}

	for attempt := 1; attempt <= 20; attempt++ {
		if status, _, body := confirmVerificationCode(t, server, email, "000000"); status != http.StatusBadRequest {
			t.Fatalf("confirm %d status = %d, want %d; body = %s", attempt, status, http.StatusBadRequest, body)
		}
	}
	status, headers, body = confirmVerificationCode(t, server, email, "000000")
	if status != http.StatusTooManyRequests {
		t.Fatalf("confirm 21 status = %d, want %d; body = %s", status, http.StatusTooManyRequests, body)
	}
	if headers.Get("Retry-After") == "" {
		t.Error("confirm Retry-After is empty")
	}
	if response := decodeError(t, body); response.Error.Code != "RATE_LIMITED" {
		t.Errorf("confirm error.code = %q, want RATE_LIMITED", response.Error.Code)
	}
}

func TestVerificationResponsesAreNotCacheable(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, email)

	status, headers, _ := requestVerificationCode(t, server, email)
	if status != http.StatusAccepted {
		t.Fatalf("request status = %d, want %d", status, http.StatusAccepted)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}

	status, headers, _ = confirmVerificationCode(t, server, email, "000000")
	if status != http.StatusBadRequest {
		t.Fatalf("confirm status = %d, want %d", status, http.StatusBadRequest)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}
}

func TestVerificationConfirmationDoesNotCreateSession(t *testing.T) {
	server := newVerificationIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	registerUserForVerification(t, server, email)
	message, _ := server.sender.Last()

	status, headers, body := confirmVerificationCode(t, server, email, message.Code)
	if status != http.StatusOK {
		t.Fatalf("confirm status = %d, want %d; body = %s", status, http.StatusOK, body)
	}
	if headers.Get("Set-Cookie") != "" {
		t.Errorf("Set-Cookie = %q, want no session cookie", headers.Get("Set-Cookie"))
	}
	if headers.Get("Authorization") != "" {
		t.Errorf("Authorization = %q, want no bearer", headers.Get("Authorization"))
	}

	var sessionTable bool
	if err := server.db.Pool.QueryRow(
		context.Background(),
		`SELECT to_regclass('public.sessions') IS NOT NULL`,
	).Scan(&sessionTable); err != nil {
		t.Fatalf("check sessions table: %v", err)
	}
	if sessionTable {
		t.Error("confirmation created or required a sessions table")
	}
}
