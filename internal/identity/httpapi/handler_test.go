package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
)

type memoryRepository struct {
	mu        sync.Mutex
	users     map[string]identity.User
	passwords map[string]string
	createErr error
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

	if r.createErr != nil {
		return identity.User{}, r.createErr
	}
	if _, exists := r.users[newUser.Email]; exists {
		return identity.User{}, identity.ErrEmailAlreadyExists
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	user := identity.User{
		ID:            fmt.Sprintf("user-%d", len(r.users)+1),
		Email:         newUser.Email,
		EmailVerified: false,
		Status:        identity.StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	r.users[newUser.Email] = user
	r.passwords[newUser.Email] = newUser.PasswordHash
	return user, nil
}

type prefixHasher struct{}

func (prefixHasher) Hash(password string) (string, error) {
	return "hash:" + password, nil
}

type busyRegistrar struct{}

func (busyRegistrar) Execute(context.Context, identity.RegisterUserInput) (identity.RegisterUserResult, error) {
	return identity.RegisterUserResult{}, identity.ErrRegistrationBusy
}

type hashingBusyRegistrar struct{}

func (hashingBusyRegistrar) Execute(context.Context, identity.RegisterUserInput) (identity.RegisterUserResult, error) {
	return identity.RegisterUserResult{}, identity.ErrHashingBusy
}

type failingVerificationIssuer struct {
	err error
}

func (i failingVerificationIssuer) Prepare(context.Context) (identity.PreparedEmailVerification, error) {
	return identity.PreparedEmailVerification{Code: "012345", CodeHash: "hash:012345"}, nil
}

func (i failingVerificationIssuer) Issue(context.Context, identity.User, identity.PreparedEmailVerification) error {
	return i.err
}

type testServer struct {
	url        string
	repository *memoryRepository
	logs       *bytes.Buffer
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	return newTestServerWithIssuer(t, nil)
}

func newTestServerWithIssuer(t *testing.T, issuer identity.EmailVerificationIssuer) *testServer {
	t.Helper()

	repository := newMemoryRepository()
	register := identity.NewRegisterUser(repository, prefixHasher{}, issuer)
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	handler := httpapi.New(register, logger)

	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &testServer{url: server.URL, repository: repository, logs: logs}
}

func post(t *testing.T, url, body string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/v1/users", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /v1/users: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return response.StatusCode, response.Header, responseBody
}

func jsonHeaders() map[string]string {
	return map[string]string{"Content-Type": "application/json"}
}

type userJSON struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type errorJSON struct {
	Error struct {
		Code      string            `json:"code"`
		Message   string            `json:"message"`
		RequestID string            `json:"requestId"`
		Fields    map[string]string `json:"fields"`
	} `json:"error"`
}

func decodeUser(t *testing.T, body []byte) userJSON {
	t.Helper()

	var user userJSON
	if err := json.Unmarshal(body, &user); err != nil {
		t.Fatalf("decode user response %q: %v", body, err)
	}
	return user
}

func decodeError(t *testing.T, body []byte) errorJSON {
	t.Helper()

	var response errorJSON
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode error response %q: %v", body, err)
	}
	return response
}

func TestRegisterEndpointCreatesUserWithoutCredentials(t *testing.T) {
	server := newTestServer(t)

	status, headers, body := post(t, server.url, `{"email":"  Person@Example.COM ","password":"correct horse battery"}`, jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	if contentType := headers.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if headers.Get("Set-Cookie") != "" {
		t.Errorf("Set-Cookie = %q, want no session cookie", headers.Get("Set-Cookie"))
	}
	if headers.Get("Authorization") != "" {
		t.Errorf("Authorization = %q, want no credentials", headers.Get("Authorization"))
	}
	if headers.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id is empty")
	}
	if cacheControl := headers.Get("Cache-Control"); cacheControl != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cacheControl)
	}

	user := decodeUser(t, body)
	if user.ID == "" {
		t.Error("user.id is empty")
	}
	if user.ID == user.Email {
		t.Error("user.id must be independent from the email")
	}
	if user.Email != "person@example.com" {
		t.Errorf("user.email = %q, want %q", user.Email, "person@example.com")
	}
	if user.EmailVerified {
		t.Error("user.emailVerified = true, want false")
	}
	if user.Status != "active" {
		t.Errorf("user.status = %q, want active", user.Status)
	}
	if user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
		t.Error("timestamps are zero")
	}

	if strings.Contains(string(body), "correct horse battery") || strings.Contains(string(body), "hash:") {
		t.Errorf("response exposed a secret: %s", body)
	}
	if got := server.repository.passwords["person@example.com"]; got != "hash:correct horse battery" {
		t.Errorf("stored password = %q, want the hasher output", got)
	}
}

func TestRegisterEndpointHidesVerificationDeliveryFailures(t *testing.T) {
	issuer := failingVerificationIssuer{err: &identity.VerificationDeliveryError{Err: errors.New("smtp unavailable for 012345")}}
	server := newTestServerWithIssuer(t, issuer)

	status, _, body := post(t, server.url, `{"email":"person@example.com","password":"correct horse battery"}`, jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	if strings.Contains(string(body), "012345") || strings.Contains(string(body), "smtp") {
		t.Errorf("response exposed delivery internals: %s", body)
	}
	if !strings.Contains(server.logs.String(), "email verification dispatch failed") {
		t.Errorf("logs do not record the delivery failure: %s", server.logs.String())
	}
	if strings.Contains(server.logs.String(), "012345") {
		t.Errorf("logs exposed the verification code: %s", server.logs.String())
	}

	user := decodeUser(t, body)
	if user.EmailVerified {
		t.Error("user.emailVerified = true, want false when delivery fails")
	}
}

func TestRegisterEndpointRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantField  string
		wantStatus int
		wantCode   string
	}{
		{name: "empty body", body: ``, wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "malformed JSON", body: `{`, wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "JSON array", body: `[]`, wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "unknown field", body: `{"email":"person@example.com","password":"correct horse battery","role":"admin"}`, wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "invalid email", body: `{"email":"not-an-email","password":"correct horse battery"}`, wantField: "email", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "missing email", body: `{"password":"correct horse battery"}`, wantField: "email", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "short password", body: `{"email":"person@example.com","password":"short"}`, wantField: "password", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "missing password", body: `{"email":"person@example.com"}`, wantField: "password", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "wrong type", body: `{"email":42,"password":"correct horse battery"}`, wantField: "email", wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "wrong content type", body: `{"email":"person@example.com","password":"correct horse battery"}`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "UNSUPPORTED_MEDIA_TYPE"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t)
			headers := jsonHeaders()
			if test.name == "wrong content type" {
				headers["Content-Type"] = "text/plain"
			}

			status, responseHeaders, body := post(t, server.url, test.body, headers)
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", status, test.wantStatus, body)
			}

			response := decodeError(t, body)
			if response.Error.Code != test.wantCode {
				t.Errorf("error.code = %q, want %q", response.Error.Code, test.wantCode)
			}
			if response.Error.Message == "" {
				t.Error("error.message is empty")
			}
			if response.Error.RequestID == "" {
				t.Error("error.requestId is empty")
			}
			if response.Error.RequestID != responseHeaders.Get("X-Request-Id") {
				t.Errorf("error.requestId = %q, header = %q", response.Error.RequestID, responseHeaders.Get("X-Request-Id"))
			}
			if test.wantField != "" && response.Error.Fields[test.wantField] == "" {
				t.Errorf("error.fields = %v, want an entry for %q", response.Error.Fields, test.wantField)
			}
			if len(server.repository.users) != 0 {
				t.Errorf("repository contains %d users, want 0", len(server.repository.users))
			}
		})
	}
}

func TestRegisterEndpointReturnsConflictForDuplicateEmail(t *testing.T) {
	server := newTestServer(t)

	status, _, body := post(t, server.url, `{"email":"person@example.com","password":"correct horse battery"}`, jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("first status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}

	status, _, body = post(t, server.url, `{"email":" PERSON@Example.com ","password":"another strong password"}`, jsonHeaders())
	if status != http.StatusConflict {
		t.Fatalf("second status = %d, want %d; body = %s", status, http.StatusConflict, body)
	}

	response := decodeError(t, body)
	if response.Error.Code != "EMAIL_ALREADY_EXISTS" {
		t.Errorf("error.code = %q, want EMAIL_ALREADY_EXISTS", response.Error.Code)
	}
	if len(server.repository.users) != 1 {
		t.Errorf("repository contains %d users, want 1", len(server.repository.users))
	}
}

func TestRegisterEndpointRejectsOversizedBody(t *testing.T) {
	server := newTestServer(t)
	body := `{"email":"person@example.com","password":"correct horse battery","padding":"` + strings.Repeat("a", 2<<20) + `"}`

	status, _, responseBody := post(t, server.url, body, jsonHeaders())
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusRequestEntityTooLarge, responseBody)
	}

	response := decodeError(t, responseBody)
	if response.Error.Code != "PAYLOAD_TOO_LARGE" {
		t.Errorf("error.code = %q, want PAYLOAD_TOO_LARGE", response.Error.Code)
	}
}

func TestRegisterEndpointRejectsOversizedTrailingBody(t *testing.T) {
	server := newTestServer(t)
	body := `{"email":"person@example.com","password":"correct horse battery"}` + strings.Repeat(" ", 2<<20)

	status, _, responseBody := post(t, server.url, body, jsonHeaders())
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusRequestEntityTooLarge, responseBody)
	}

	response := decodeError(t, responseBody)
	if response.Error.Code != "PAYLOAD_TOO_LARGE" {
		t.Errorf("error.code = %q, want PAYLOAD_TOO_LARGE", response.Error.Code)
	}
}

func TestRegisterEndpointReturnsServiceUnavailableWhenCapacityIsExhausted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := httpapi.New(busyRegistrar{}, logger)

	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	status, headers, body := post(t, server.URL, `{"email":"person@example.com","password":"correct horse battery"}`, jsonHeaders())
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusServiceUnavailable, body)
	}
	if retryAfter := headers.Get("Retry-After"); retryAfter != "1" {
		t.Errorf("Retry-After = %q, want 1", retryAfter)
	}

	response := decodeError(t, body)
	if response.Error.Code != "SERVICE_UNAVAILABLE" {
		t.Errorf("error.code = %q, want SERVICE_UNAVAILABLE", response.Error.Code)
	}
}

func TestRegisterEndpointReturnsServiceUnavailableWhenHashingIsSaturated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := httpapi.New(hashingBusyRegistrar{}, logger)

	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	status, headers, body := post(t, server.URL, `{"email":"person@example.com","password":"correct horse battery"}`, jsonHeaders())
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusServiceUnavailable, body)
	}
	if retryAfter := headers.Get("Retry-After"); retryAfter != "1" {
		t.Errorf("Retry-After = %q, want 1", retryAfter)
	}

	response := decodeError(t, body)
	if response.Error.Code != "SERVICE_UNAVAILABLE" {
		t.Errorf("error.code = %q, want SERVICE_UNAVAILABLE", response.Error.Code)
	}
}

func TestRegisterEndpointDoesNotLeakInternalErrors(t *testing.T) {
	server := newTestServer(t)
	server.repository.createErr = errors.New("database exploded")

	status, _, body := post(t, server.url, `{"email":"person@example.com","password":"correct horse battery"}`, jsonHeaders())
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusInternalServerError, body)
	}

	response := decodeError(t, body)
	if response.Error.Code != "INTERNAL_ERROR" {
		t.Errorf("error.code = %q, want INTERNAL_ERROR", response.Error.Code)
	}
	if strings.Contains(string(body), "database exploded") {
		t.Errorf("response exposed an internal error: %s", body)
	}
	if strings.Contains(server.logs.String(), "correct horse battery") {
		t.Errorf("logs exposed the password: %s", server.logs.String())
	}
}

func TestRegisterEndpointRejectsOtherMethods(t *testing.T) {
	server := newTestServer(t)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.url+"/v1/users", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("GET /v1/users: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
	}
	if allow := response.Header.Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestRegisterEndpointUsesIncomingRequestID(t *testing.T) {
	server := newTestServer(t)
	headers := jsonHeaders()
	headers["X-Request-Id"] = "client-request-123"

	status, responseHeaders, body := post(t, server.url, `{"email":"not-an-email","password":"short"}`, headers)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
	}
	if responseHeaders.Get("X-Request-Id") != "client-request-123" {
		t.Errorf("X-Request-Id = %q, want client-request-123", responseHeaders.Get("X-Request-Id"))
	}
	if response := decodeError(t, body); response.Error.RequestID != "client-request-123" {
		t.Errorf("error.requestId = %q, want client-request-123", response.Error.RequestID)
	}
}
