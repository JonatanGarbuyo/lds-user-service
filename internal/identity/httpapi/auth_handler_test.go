package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
)

type fakeLoginExecutor struct {
	result identity.LoginResult
	err    error
	input  identity.LoginInput
}

func (f *fakeLoginExecutor) Execute(_ context.Context, input identity.LoginInput) (identity.LoginResult, error) {
	f.input = input
	return f.result, f.err
}

type fakeCurrentUser struct {
	user   identity.User
	err    error
	secret string
}

func (f *fakeCurrentUser) Execute(_ context.Context, secret string) (identity.User, error) {
	f.secret = secret
	return f.user, f.err
}

type fakeCSRF struct {
	token string
	err   error
}

func (f fakeCSRF) Issue(http.ResponseWriter) (string, error) {
	return f.token, f.err
}

type authTestServer struct {
	url     string
	login   *fakeLoginExecutor
	current *fakeCurrentUser
}

func newAuthTestServer(t *testing.T, login *fakeLoginExecutor, current *fakeCurrentUser) *authTestServer {
	t.Helper()
	handler := httpapi.NewAuth(
		login,
		current,
		sessions.Cookie{Secure: true, SameSite: http.SameSiteLaxMode},
		fakeCSRF{token: "csrf-token"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)
	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &authTestServer{url: server.URL, login: login, current: current}
}

func successfulLoginResult() identity.LoginResult {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	return identity.LoginResult{
		User: identity.User{
			ID:            "user-1",
			Email:         "person@example.com",
			EmailVerified: true,
			Status:        identity.StatusActive,
			CreatedAt:     now,
			UpdatedAt:     now,
		},
		Session: sessions.Issued{
			Session: sessions.Session{
				ID:                "session-1",
				UserID:            "user-1",
				Kind:              sessions.KindWeb,
				CreatedAt:         now,
				LastActivityAt:    now,
				ExpiresAt:         now.Add(30 * 24 * time.Hour),
				AbsoluteExpiresAt: now.Add(90 * 24 * time.Hour),
			},
			Secret: "opaque-session-secret",
		},
		ReaderState: readerstate.Snapshot{
			SignedSnapshot: "header.payload.signature",
			ExpiresAt:      now.Add(30 * time.Minute),
		},
	}
}

func authRequest(t *testing.T, baseURL, method, path, body string, headers map[string]string, cookies ...*http.Cookie) (int, http.Header, []byte) {
	t.Helper()

	request, err := http.NewRequestWithContext(context.Background(), method, baseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return response.StatusCode, response.Header, responseBody
}

func TestLoginSetsHostOnlySessionCookieWithoutExposingTheSecret(t *testing.T) {
	login := &fakeLoginExecutor{result: successfulLoginResult()}
	server := newAuthTestServer(t, login, &fakeCurrentUser{})

	status, headers, body := authRequest(t, server.url, http.MethodPost, "/v1/auth/login",
		`{"email":" Person@Example.com ","password":"correct horse battery"}`,
		map[string]string{"Content-Type": "application/json", "Origin": server.url})

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", status, body)
	}
	if login.input.Email != " Person@Example.com " {
		t.Errorf("login input email = %q, want the raw request value", login.input.Email)
	}
	if strings.Contains(string(body), "opaque-session-secret") {
		t.Error("response body exposes the session secret")
	}
	if headers.Get("Authorization") != "" {
		t.Error("response contains an Authorization header")
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}

	cookies := headers.Values("Set-Cookie")
	var sessionCookie *http.Cookie
	for _, header := range cookies {
		cookie, err := http.ParseSetCookie(header)
		if err != nil {
			t.Fatalf("parse Set-Cookie: %v", err)
		}
		if cookie.Name == sessions.DefaultCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie was not set")
	}
	if sessionCookie.Value != "opaque-session-secret" {
		t.Errorf("cookie value = %q", sessionCookie.Value)
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure {
		t.Errorf("cookie flags HttpOnly=%t Secure=%t, want both true", sessionCookie.HttpOnly, sessionCookie.Secure)
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", sessionCookie.SameSite)
	}
	if sessionCookie.Domain != "" {
		t.Errorf("Domain = %q, want host-only", sessionCookie.Domain)
	}
	absoluteExpiry := login.result.Session.Session.AbsoluteExpiresAt
	if !sessionCookie.Expires.Equal(absoluteExpiry) {
		t.Errorf("cookie Expires = %s, want the absolute session limit %s",
			sessionCookie.Expires, absoluteExpiry)
	}

	var response struct {
		User        userJSON `json:"user"`
		ReaderState struct {
			SignedSnapshot string    `json:"signedSnapshot"`
			ExpiresAt      time.Time `json:"expiresAt"`
		} `json:"readerState"`
		Session struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"session"`
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if response.User.ID != "user-1" {
		t.Errorf("user.id = %q, want user-1", response.User.ID)
	}
	if response.ReaderState.SignedSnapshot != "header.payload.signature" {
		t.Errorf("readerState.signedSnapshot = %q", response.ReaderState.SignedSnapshot)
	}
	if response.Session.ID != "session-1" || response.Session.Kind != "web" {
		t.Errorf("session = %+v", response.Session)
	}
	if response.CSRFToken != "csrf-token" {
		t.Errorf("csrfToken = %q, want csrf-token", response.CSRFToken)
	}
}

func TestLoginRejectsInvalidPasswordUnverifiedEmailAndSuspendedAccounts(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "invalid password", err: identity.ErrInvalidCredentials, wantStatus: http.StatusUnauthorized, wantCode: "INVALID_CREDENTIALS"},
		{name: "unverified email", err: identity.ErrEmailNotVerified, wantStatus: http.StatusForbidden, wantCode: "EMAIL_NOT_VERIFIED"},
		{name: "suspended", err: identity.ErrAccountSuspended, wantStatus: http.StatusForbidden, wantCode: "ACCOUNT_SUSPENDED"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAuthTestServer(t, &fakeLoginExecutor{err: test.err}, &fakeCurrentUser{})
			status, headers, body := authRequest(t, server.url, http.MethodPost, "/v1/auth/login",
				`{"email":"person@example.com","password":"wrong password"}`,
				map[string]string{"Content-Type": "application/json"})

			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", status, test.wantStatus, body)
			}
			if headers.Values("Set-Cookie") != nil {
				t.Errorf("Set-Cookie = %v, want no cookie", headers.Values("Set-Cookie"))
			}
			if response := decodeError(t, body); response.Error.Code != test.wantCode {
				t.Errorf("error.code = %q, want %q", response.Error.Code, test.wantCode)
			}
		})
	}
}

func TestLoginReturnsValidationErrorsAndServiceUnavailable(t *testing.T) {
	server := newAuthTestServer(t, &fakeLoginExecutor{err: &identity.ValidationError{
		Fields: map[string]string{"email": "must be a valid email address"},
	}}, &fakeCurrentUser{})
	status, _, body := authRequest(t, server.url, http.MethodPost, "/v1/auth/login",
		`{"email":"not-an-email","password":"correct horse battery"}`,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusBadRequest {
		t.Fatalf("validation status = %d, want 400; body = %s", status, body)
	}
	if response := decodeError(t, body); response.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("validation error.code = %q", response.Error.Code)
	}

	server = newAuthTestServer(t, &fakeLoginExecutor{err: identity.ErrHashingBusy}, &fakeCurrentUser{})
	status, headers, body := authRequest(t, server.url, http.MethodPost, "/v1/auth/login",
		`{"email":"person@example.com","password":"correct horse battery"}`,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("busy status = %d, want 503; body = %s", status, body)
	}
	if headers.Get("Retry-After") == "" {
		t.Error("Retry-After is empty")
	}
}

func TestCurrentUserRequiresAValidOpaqueSession(t *testing.T) {
	user := successfulLoginResult().User
	server := newAuthTestServer(t, &fakeLoginExecutor{}, &fakeCurrentUser{user: user})

	status, _, body := authRequest(t, server.url, http.MethodGet, "/v1/users/me", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("missing cookie status = %d, want 401; body = %s", status, body)
	}
	if response := decodeError(t, body); response.Error.Code != "INVALID_SESSION" {
		t.Errorf("error.code = %q, want INVALID_SESSION", response.Error.Code)
	}

	server.current.err = identity.ErrWebSessionInvalid
	status, _, body = authRequest(t, server.url, http.MethodGet, "/v1/users/me", "",
		nil, &http.Cookie{Name: sessions.DefaultCookieName, Value: "header.payload.signature"})
	if status != http.StatusUnauthorized {
		t.Fatalf("reader state as session status = %d, want 401; body = %s", status, body)
	}
	if response := decodeError(t, body); response.Error.Code != "INVALID_SESSION" {
		t.Errorf("error.code = %q, want INVALID_SESSION", response.Error.Code)
	}

	server.current.err = nil
	status, headers, body := authRequest(t, server.url, http.MethodGet, "/v1/users/me", "",
		nil, &http.Cookie{Name: sessions.DefaultCookieName, Value: "opaque-session-secret"})
	if status != http.StatusOK {
		t.Fatalf("valid cookie status = %d, want 200; body = %s", status, body)
	}
	if server.current.secret != "opaque-session-secret" {
		t.Errorf("authenticator received secret %q", server.current.secret)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}
	if response := decodeUser(t, body); response.ID != user.ID {
		t.Errorf("user.id = %q, want %q", response.ID, user.ID)
	}
}

func TestReaderStateAndAuthorizationHeadersDoNotAuthenticateCurrentUser(t *testing.T) {
	server := newAuthTestServer(t, &fakeLoginExecutor{}, &fakeCurrentUser{err: identity.ErrWebSessionInvalid})

	for _, header := range []map[string]string{
		{"Authorization": "Bearer header.payload.signature"},
		{"X-Reader-State": "header.payload.signature"},
	} {
		status, _, body := authRequest(t, server.url, http.MethodGet, "/v1/users/me", "", header)
		if status != http.StatusUnauthorized {
			t.Errorf("headers %v: status = %d, want 401; body = %s", header, status, body)
		}
		if response := decodeError(t, body); response.Error.Code != "INVALID_SESSION" {
			t.Errorf("headers %v: error.code = %q, want INVALID_SESSION", header, response.Error.Code)
		}
	}
}

func TestLoginRejectsMalformedJSON(t *testing.T) {
	server := newAuthTestServer(t, &fakeLoginExecutor{}, &fakeCurrentUser{})
	status, _, body := authRequest(t, server.url, http.MethodPost, "/v1/auth/login", `{"email":`,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", status, body)
	}
	if response := decodeError(t, body); response.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("error.code = %q, want VALIDATION_ERROR", response.Error.Code)
	}
}

func TestLoginIncludesSessionExpiration(t *testing.T) {
	result := successfulLoginResult()
	server := newAuthTestServer(t, &fakeLoginExecutor{result: result}, &fakeCurrentUser{})

	_, _, body := authRequest(t, server.url, http.MethodPost, "/v1/auth/login",
		`{"email":"person@example.com","password":"correct horse battery"}`,
		map[string]string{"Content-Type": "application/json"})
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	session, ok := response["session"].(map[string]any)
	if !ok {
		t.Fatalf("session is not an object: %s", body)
	}
	if _, exists := session["expiresAt"]; !exists {
		t.Errorf("session.expiresAt is missing: %v", session)
	}
	if _, exists := session["secret"]; exists {
		t.Errorf("session.secret is present: %v", session)
	}
}
