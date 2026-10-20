package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
)

type stubEmailVerification struct {
	requestInputs []identity.RequestEmailVerificationInput
	confirmInputs []identity.ConfirmEmailVerificationInput
	requestErr    error
	confirmUser   identity.User
	confirmErr    error
	requestCalls  int
	confirmCalls  int
}

func (s *stubEmailVerification) Request(_ context.Context, input identity.RequestEmailVerificationInput) error {
	s.requestCalls++
	s.requestInputs = append(s.requestInputs, input)
	return s.requestErr
}

func (s *stubEmailVerification) Confirm(_ context.Context, input identity.ConfirmEmailVerificationInput) (identity.User, error) {
	s.confirmCalls++
	s.confirmInputs = append(s.confirmInputs, input)
	return s.confirmUser, s.confirmErr
}

type verificationTestServer struct {
	url          string
	verification *stubEmailVerification
	logs         *bytes.Buffer
}

func newVerificationTestServer(t *testing.T) *verificationTestServer {
	t.Helper()

	verification := &stubEmailVerification{}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	handler := httpapi.NewEmailVerification(verification, logger)

	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &verificationTestServer{url: server.URL, verification: verification, logs: logs}
}

func postPath(t *testing.T, url, path, body string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return response.StatusCode, response.Header, responseBody
}

func TestEmailVerificationRequestReturnsGenericAcceptedResponse(t *testing.T) {
	server := newVerificationTestServer(t)

	status, headers, body := postPath(t, server.url, "/v1/auth/email-verification/request",
		`{"email":"  Person@Example.COM "}`, jsonHeaders())
	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusAccepted, body)
	}
	if contentType := headers.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if headers.Get("Set-Cookie") != "" || headers.Get("Authorization") != "" {
		t.Errorf("response exposed credentials: cookie=%q authorization=%q", headers.Get("Set-Cookie"), headers.Get("Authorization"))
	}
	if cacheControl := headers.Get("Cache-Control"); cacheControl != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cacheControl)
	}
	if headers.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id is empty")
	}

	var response struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode response %q: %v", body, err)
	}
	if response.Status != "accepted" {
		t.Errorf("status = %q, want accepted", response.Status)
	}
	if strings.Contains(strings.ToLower(string(body)), "sent") {
		t.Errorf("response claims delivery: %s", body)
	}

	if server.verification.requestCalls != 1 {
		t.Fatalf("request calls = %d, want 1", server.verification.requestCalls)
	}
	if server.verification.requestInputs[0].Email != "  Person@Example.COM " {
		t.Errorf("email = %q, want the raw request value", server.verification.requestInputs[0].Email)
	}
	if server.verification.requestInputs[0].ClientIP == "" {
		t.Error("client IP is empty")
	}
}

func TestEmailVerificationRequestHidesDeliveryFailures(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.requestErr = &identity.VerificationDeliveryError{Err: errors.New("smtp unavailable for 012345")}

	status, _, body := postPath(t, server.url, "/v1/auth/email-verification/request",
		`{"email":"person@example.com"}`, jsonHeaders())
	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusAccepted, body)
	}
	if strings.Contains(string(body), "smtp") || strings.Contains(string(body), "012345") {
		t.Errorf("response exposed delivery internals: %s", body)
	}
	if !strings.Contains(server.logs.String(), "email verification dispatch failed") {
		t.Errorf("logs do not record the delivery failure: %s", server.logs.String())
	}
	if strings.Contains(server.logs.String(), "012345") {
		t.Errorf("logs exposed the verification code: %s", server.logs.String())
	}
}

func TestEmailVerificationRequestRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		headers    map[string]string
		wantStatus int
		wantCode   string
		wantField  string
		requestErr error
		wantCalls  int
	}{
		{name: "empty body", body: ``, headers: jsonHeaders(), wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "malformed JSON", body: `{`, headers: jsonHeaders(), wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "unknown field", body: `{"email":"person@example.com","code":"012345"}`, headers: jsonHeaders(), wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR"},
		{name: "missing email", body: `{}`, headers: jsonHeaders(), wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR", wantField: "email", requestErr: &identity.ValidationError{Fields: map[string]string{"email": "is required"}}, wantCalls: 1},
		{name: "wrong type", body: `{"email":42}`, headers: jsonHeaders(), wantStatus: http.StatusBadRequest, wantCode: "VALIDATION_ERROR", wantField: "email"},
		{name: "wrong content type", body: `{"email":"person@example.com"}`, headers: map[string]string{"Content-Type": "text/plain"}, wantStatus: http.StatusUnsupportedMediaType, wantCode: "UNSUPPORTED_MEDIA_TYPE"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newVerificationTestServer(t)
			server.verification.requestErr = test.requestErr
			status, _, body := postPath(t, server.url, "/v1/auth/email-verification/request", test.body, test.headers)
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", status, test.wantStatus, body)
			}
			response := decodeError(t, body)
			if response.Error.Code != test.wantCode {
				t.Errorf("error.code = %q, want %q", response.Error.Code, test.wantCode)
			}
			if test.wantField != "" && response.Error.Fields[test.wantField] == "" {
				t.Errorf("error.fields = %v, want an entry for %q", response.Error.Fields, test.wantField)
			}
			if server.verification.requestCalls != test.wantCalls {
				t.Errorf("request calls = %d, want %d", server.verification.requestCalls, test.wantCalls)
			}
		})
	}
}

func TestEmailVerificationRequestReturnsValidationFieldsFromUseCase(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.requestErr = &identity.ValidationError{Fields: map[string]string{"email": "must be a valid email address"}}

	status, _, body := postPath(t, server.url, "/v1/auth/email-verification/request",
		`{"email":"person@example.com"}`, jsonHeaders())
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
	}
	response := decodeError(t, body)
	if response.Error.Fields["email"] == "" {
		t.Errorf("error.fields = %v, want an email message", response.Error.Fields)
	}
}

func TestEmailVerificationRequestRateLimitSetsRetryAfter(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.requestErr = &identity.RateLimitError{RetryAfter: 30 * time.Second}

	status, headers, body := postPath(t, server.url, "/v1/auth/email-verification/request",
		`{"email":"person@example.com"}`, jsonHeaders())
	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusTooManyRequests, body)
	}
	if retryAfter := headers.Get("Retry-After"); retryAfter != "30" {
		t.Errorf("Retry-After = %q, want 30", retryAfter)
	}
	if response := decodeError(t, body); response.Error.Code != "RATE_LIMITED" {
		t.Errorf("error.code = %q, want RATE_LIMITED", response.Error.Code)
	}
}

func TestEmailVerificationRequestDoesNotLeakInternalErrors(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.requestErr = errors.New("database exploded")

	status, _, body := postPath(t, server.url, "/v1/auth/email-verification/request",
		`{"email":"person@example.com"}`, jsonHeaders())
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusInternalServerError, body)
	}
	if strings.Contains(string(body), "database exploded") {
		t.Errorf("response exposed an internal error: %s", body)
	}
}

func TestEmailVerificationConfirmReturnsVerifiedUserWithoutCredentials(t *testing.T) {
	server := newVerificationTestServer(t)
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	server.verification.confirmUser = identity.User{
		ID:            "user-1",
		Email:         "person@example.com",
		EmailVerified: true,
		Status:        identity.StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	status, headers, body := postPath(t, server.url, "/v1/auth/email-verification/confirm",
		`{"email":"person@example.com","code":"012345"}`, jsonHeaders())
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusOK, body)
	}
	if headers.Get("Set-Cookie") != "" || headers.Get("Authorization") != "" {
		t.Errorf("response exposed credentials: cookie=%q authorization=%q", headers.Get("Set-Cookie"), headers.Get("Authorization"))
	}
	if cacheControl := headers.Get("Cache-Control"); cacheControl != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cacheControl)
	}

	user := decodeUser(t, body)
	if !user.EmailVerified {
		t.Error("user.emailVerified = false, want true")
	}
	if user.Status != "active" {
		t.Errorf("user.status = %q, want active", user.Status)
	}
	if server.verification.confirmCalls != 1 {
		t.Fatalf("confirm calls = %d, want 1", server.verification.confirmCalls)
	}
	if server.verification.confirmInputs[0].Code != "012345" {
		t.Errorf("code = %q, want 012345", server.verification.confirmInputs[0].Code)
	}
}

func TestEmailVerificationConfirmReturnsGenericInvalidCode(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.confirmErr = identity.ErrInvalidVerificationCode

	status, _, body := postPath(t, server.url, "/v1/auth/email-verification/confirm",
		`{"email":"person@example.com","code":"999999"}`, jsonHeaders())
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
	}
	response := decodeError(t, body)
	if response.Error.Code != "INVALID_VERIFICATION_CODE" {
		t.Errorf("error.code = %q, want INVALID_VERIFICATION_CODE", response.Error.Code)
	}
	if strings.Contains(strings.ToLower(response.Error.Message), "user") {
		t.Errorf("error.message reveals account existence: %q", response.Error.Message)
	}
}

func TestEmailVerificationRequestReportsHashingSaturation(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.requestErr = identity.ErrHashingBusy

	status, headers, body := postPath(t, server.url, "/v1/auth/email-verification/request",
		`{"email":"person@example.com"}`, jsonHeaders())
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusServiceUnavailable, body)
	}
	if retryAfter := headers.Get("Retry-After"); retryAfter != "1" {
		t.Errorf("Retry-After = %q, want 1", retryAfter)
	}
	if response := decodeError(t, body); response.Error.Code != "SERVICE_UNAVAILABLE" {
		t.Errorf("error.code = %q, want SERVICE_UNAVAILABLE", response.Error.Code)
	}
}

func TestEmailVerificationConfirmReportsHashingSaturation(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.confirmErr = identity.ErrHashingBusy

	status, headers, body := postPath(t, server.url, "/v1/auth/email-verification/confirm",
		`{"email":"person@example.com","code":"012345"}`, jsonHeaders())
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusServiceUnavailable, body)
	}
	if retryAfter := headers.Get("Retry-After"); retryAfter != "1" {
		t.Errorf("Retry-After = %q, want 1", retryAfter)
	}
	if response := decodeError(t, body); response.Error.Code != "SERVICE_UNAVAILABLE" {
		t.Errorf("error.code = %q, want SERVICE_UNAVAILABLE", response.Error.Code)
	}
}

func TestEmailVerificationConfirmValidatesInput(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{name: "missing email", body: `{"code":"012345"}`, wantField: "email"},
		{name: "missing code", body: `{"email":"person@example.com"}`, wantField: "code"},
		{name: "short code", body: `{"email":"person@example.com","code":"12345"}`, wantField: "code"},
		{name: "unknown field", body: `{"email":"person@example.com","code":"012345","token":"x"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newVerificationTestServer(t)
			server.verification.confirmErr = &identity.ValidationError{Fields: map[string]string{"email": "is required", "code": "must be exactly 6 digits"}}

			status, _, body := postPath(t, server.url, "/v1/auth/email-verification/confirm", test.body, jsonHeaders())
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", status, http.StatusBadRequest, body)
			}
			response := decodeError(t, body)
			if response.Error.Code != "VALIDATION_ERROR" {
				t.Errorf("error.code = %q, want VALIDATION_ERROR", response.Error.Code)
			}
			if test.wantField != "" && response.Error.Fields[test.wantField] == "" {
				t.Errorf("error.fields = %v, want an entry for %q", response.Error.Fields, test.wantField)
			}
		})
	}
}

func TestEmailVerificationConfirmRateLimitSetsRetryAfter(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.confirmErr = &identity.RateLimitError{RetryAfter: 45 * time.Second}

	status, headers, body := postPath(t, server.url, "/v1/auth/email-verification/confirm",
		`{"email":"person@example.com","code":"012345"}`, jsonHeaders())
	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusTooManyRequests, body)
	}
	if retryAfter := headers.Get("Retry-After"); retryAfter != "45" {
		t.Errorf("Retry-After = %q, want 45", retryAfter)
	}
	if response := decodeError(t, body); response.Error.Code != "RATE_LIMITED" {
		t.Errorf("error.code = %q, want RATE_LIMITED", response.Error.Code)
	}
}

func TestEmailVerificationConfirmDoesNotLeakInternalErrors(t *testing.T) {
	server := newVerificationTestServer(t)
	server.verification.confirmErr = errors.New("database exploded")

	status, _, body := postPath(t, server.url, "/v1/auth/email-verification/confirm",
		`{"email":"person@example.com","code":"012345"}`, jsonHeaders())
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusInternalServerError, body)
	}
	if strings.Contains(string(body), "database exploded") {
		t.Errorf("response exposed an internal error: %s", body)
	}
}
