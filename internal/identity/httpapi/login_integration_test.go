//go:build integration

package httpapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/password"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testpg"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/httpserver"
	platformpostgres "github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
	readerstatehttp "github.com/JonatanGarbuyo/lds-user-service/internal/readerstate/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
	sessionspostgres "github.com/JonatanGarbuyo/lds-user-service/internal/sessions/postgres"
)

const loginTestOrigin = "https://app.example.com"

type loginIntegrationServer struct {
	url    string
	db     *platformpostgres.DB
	signer *readerstate.Signer
	server *httptest.Server
}

func newLoginIntegrationServer(t *testing.T) *loginIntegrationServer {
	t.Helper()

	db := testpg.OpenDatabase(t)
	users := identitypostgres.NewRepository(db.Pool)
	sessionService := sessions.NewService(sessionspostgres.NewRepository(db.Pool), sessions.Options{
		IdleTTL:     30 * 24 * time.Hour,
		AbsoluteTTL: 90 * 24 * time.Hour,
	})
	signer, _, err := readerstate.LoadSigner(readerstate.SignerConfig{
		Issuer:            "lds-user-service",
		Audience:          "lds-web",
		TTL:               30 * time.Minute,
		GenerateIfMissing: true,
	})
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}
	login, err := identity.NewLoginUser(identity.LoginDependencies{
		Users:                users,
		Passwords:            password.New(),
		Sessions:             sessionService,
		ReaderState:          signer,
		VerificationRequired: true,
	})
	if err != nil {
		t.Fatalf("NewLoginUser() error = %v", err)
	}
	currentUser := identity.NewCurrentUser(users, sessionService)
	cookie := sessions.Cookie{Secure: true, SameSite: http.SameSiteLaxMode}
	authHandler := httpapi.NewAuth(
		login,
		currentUser,
		cookie,
		httpserver.NewCSRF([]string{loginTestOrigin}, sessions.DefaultCookieName),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)

	mux := http.NewServeMux()
	authHandler.Register(mux)
	readerstatehttp.New(signer).Register(mux)
	cors := httpserver.NewCORS([]string{loginTestOrigin})
	csrf := httpserver.NewCSRF([]string{loginTestOrigin}, sessions.DefaultCookieName)
	server := httptest.NewServer(cors.Middleware(csrf.Middleware(mux)))
	t.Cleanup(server.Close)
	t.Cleanup(db.Close)

	return &loginIntegrationServer{url: server.URL, db: db, signer: signer, server: server}
}

func (s *loginIntegrationServer) createUser(t *testing.T, email, plainPassword string, verified bool, status string) identity.User {
	t.Helper()
	hash, err := password.New().Hash(plainPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	var (
		id        string
		createdAt time.Time
		updatedAt time.Time
	)
	if err := s.db.Pool.QueryRow(
		context.Background(),
		`INSERT INTO users (email, password_hash, email_verified, status)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id::text, created_at, updated_at`,
		email, hash, verified, status,
	).Scan(&id, &createdAt, &updatedAt); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return identity.User{
		ID:            id,
		Email:         email,
		EmailVerified: verified,
		Status:        identity.Status(status),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

func loginRequest(t *testing.T, baseURL, email, plainPassword string, extraHeaders map[string]string) (int, http.Header, []byte) {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, plainPassword)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new login request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", loginTestOrigin)
	for key, value := range extraHeaders {
		request.Header.Set(key, value)
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("POST /v1/auth/login: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read login response: %v", err)
	}
	return response.StatusCode, response.Header, responseBody
}

func getWithCookie(t *testing.T, baseURL, path, cookieValue string) (int, http.Header, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatalf("new GET request: %v", err)
	}
	if cookieValue != "" {
		request.AddCookie(&http.Cookie{Name: sessions.DefaultCookieName, Value: cookieValue})
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response.StatusCode, response.Header, responseBody
}

func sessionCookie(t *testing.T, headers http.Header) *http.Cookie {
	t.Helper()
	for _, header := range headers.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(header)
		if err != nil {
			t.Fatalf("parse Set-Cookie: %v", err)
		}
		if cookie.Name == sessions.DefaultCookieName {
			return cookie
		}
	}
	t.Fatal("session cookie not found")
	return nil
}

type loginSuccessJSON struct {
	User struct {
		ID            string `json:"id"`
		EmailVerified bool   `json:"emailVerified"`
	} `json:"user"`
	Session struct {
		ID        string    `json:"id"`
		Kind      string    `json:"kind"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"session"`
	ReaderState struct {
		SignedSnapshot string    `json:"signedSnapshot"`
		ExpiresAt      time.Time `json:"expiresAt"`
	} `json:"readerState"`
	CSRFToken string `json:"csrfToken"`
}

func TestWebLoginPersistsOpaqueSessionAndAuthenticatesCurrentUser(t *testing.T) {
	server := newLoginIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	user := server.createUser(t, email, "correct horse battery", true, "active")

	status, headers, body := loginRequest(t, server.url, email, "correct horse battery", nil)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body = %s", status, body)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}
	cookie := sessionCookie(t, headers)
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags = %+v, want HttpOnly, Secure, SameSite=Lax", cookie)
	}
	if cookie.Domain != "" {
		t.Errorf("cookie Domain = %q, want host-only", cookie.Domain)
	}
	if strings.Contains(string(body), cookie.Value) {
		t.Error("login JSON exposes the session secret")
	}

	var decoded loginSuccessJSON
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if decoded.User.ID != user.ID {
		t.Errorf("user.id = %q, want %q", decoded.User.ID, user.ID)
	}
	if !decoded.User.EmailVerified {
		t.Error("user.emailVerified = false, want true")
	}
	if decoded.Session.Kind != "web" || decoded.Session.ID == "" {
		t.Errorf("session = %+v", decoded.Session)
	}
	if decoded.Session.ExpiresAt.IsZero() {
		t.Error("session.expiresAt is zero")
	}
	if decoded.CSRFToken == "" {
		t.Error("csrfToken is empty")
	}
	if decoded.ReaderState.SignedSnapshot == "" {
		t.Fatal("readerState.signedSnapshot is empty")
	}

	claims, err := server.signer.Verify(decoded.ReaderState.SignedSnapshot)
	if err != nil {
		t.Fatalf("verify reader state: %v", err)
	}
	if claims.Subject != user.ID {
		t.Errorf("reader state subject = %q, want %q", claims.Subject, user.ID)
	}
	if !claims.EmailVerified {
		t.Error("reader state emailVerified = false, want true")
	}

	var storedHash []byte
	var kind string
	if err := server.db.Pool.QueryRow(
		context.Background(),
		`SELECT kind, secret_hash FROM sessions WHERE id = $1`,
		decoded.Session.ID,
	).Scan(&kind, &storedHash); err != nil {
		t.Fatalf("query stored session: %v", err)
	}
	if kind != "web" {
		t.Errorf("stored session kind = %q, want web", kind)
	}
	expectedHash := sha256.Sum256([]byte(cookie.Value))
	if string(storedHash) != string(expectedHash[:]) {
		t.Error("stored secret_hash does not match SHA-256(cookie secret)")
	}

	status, headers, body = getWithCookie(t, server.url, "/v1/users/me", cookie.Value)
	if status != http.StatusOK {
		t.Fatalf("GET /v1/users/me status = %d, want 200; body = %s", status, body)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("GET /v1/users/me Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}
	if me := decodeUser(t, body); me.ID != user.ID {
		t.Errorf("GET /v1/users/me id = %q, want %q", me.ID, user.ID)
	}
}

func TestWebLoginRejectsInvalidPasswordUnverifiedAndSuspendedUsers(t *testing.T) {
	server := newLoginIntegrationServer(t)
	validEmail := uniqueIntegrationEmail(t)
	server.createUser(t, validEmail, "correct horse battery", true, "active")
	unverifiedEmail := uniqueIntegrationEmail(t)
	server.createUser(t, unverifiedEmail, "correct horse battery", false, "active")
	suspendedEmail := uniqueIntegrationEmail(t)
	server.createUser(t, suspendedEmail, "correct horse battery", true, "suspended")

	tests := []struct {
		name       string
		email      string
		password   string
		wantStatus int
		wantCode   string
	}{
		{name: "wrong password", email: validEmail, password: "wrong password", wantStatus: http.StatusUnauthorized, wantCode: "INVALID_CREDENTIALS"},
		{name: "unknown email", email: uniqueIntegrationEmail(t), password: "correct horse battery", wantStatus: http.StatusUnauthorized, wantCode: "INVALID_CREDENTIALS"},
		{name: "unverified email", email: unverifiedEmail, password: "correct horse battery", wantStatus: http.StatusForbidden, wantCode: "EMAIL_NOT_VERIFIED"},
		{name: "suspended", email: suspendedEmail, password: "correct horse battery", wantStatus: http.StatusForbidden, wantCode: "ACCOUNT_SUSPENDED"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, headers, body := loginRequest(t, server.url, test.email, test.password, nil)
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", status, test.wantStatus, body)
			}
			if headers.Values("Set-Cookie") != nil {
				t.Errorf("Set-Cookie = %v, want none", headers.Values("Set-Cookie"))
			}
			if response := decodeError(t, body); response.Error.Code != test.wantCode {
				t.Errorf("error.code = %q, want %q", response.Error.Code, test.wantCode)
			}
		})
	}
}

func TestSessionSurvivesServiceRestartAndReaderStateNeverAuthenticates(t *testing.T) {
	server := newLoginIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	user := server.createUser(t, email, "correct horse battery", true, "active")

	status, headers, body := loginRequest(t, server.url, email, "correct horse battery", nil)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body = %s", status, body)
	}
	var decoded loginSuccessJSON
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	cookie := sessionCookie(t, headers)

	sessionService := sessions.NewService(sessionspostgres.NewRepository(server.db.Pool), sessions.Options{
		IdleTTL:     30 * 24 * time.Hour,
		AbsoluteTTL: 90 * 24 * time.Hour,
	})
	users := identitypostgres.NewRepository(server.db.Pool)
	login, err := identity.NewLoginUser(identity.LoginDependencies{
		Users:                users,
		Passwords:            password.New(),
		Sessions:             sessionService,
		ReaderState:          server.signer,
		VerificationRequired: true,
	})
	if err != nil {
		t.Fatalf("NewLoginUser() error = %v", err)
	}
	restartedMux := http.NewServeMux()
	httpapi.NewAuth(
		login,
		identity.NewCurrentUser(users, sessionService),
		sessions.Cookie{Secure: true, SameSite: http.SameSiteLaxMode},
		httpserver.NewCSRF([]string{loginTestOrigin}, sessions.DefaultCookieName),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	).Register(restartedMux)
	restarted := httptest.NewServer(restartedMux)
	t.Cleanup(restarted.Close)

	status, _, body = getWithCookie(t, restarted.URL, "/v1/users/me", cookie.Value)
	if status != http.StatusOK {
		t.Fatalf("GET /v1/users/me after restart = %d, want 200; body = %s", status, body)
	}
	if me := decodeUser(t, body); me.ID != user.ID {
		t.Errorf("restarted /me id = %q, want %q", me.ID, user.ID)
	}

	status, _, body = getWithCookie(t, server.url, "/v1/users/me", decoded.ReaderState.SignedSnapshot)
	if status != http.StatusUnauthorized {
		t.Fatalf("reader state as cookie status = %d, want 401; body = %s", status, body)
	}
	if response := decodeError(t, body); response.Error.Code != "INVALID_SESSION" {
		t.Errorf("error.code = %q, want INVALID_SESSION", response.Error.Code)
	}
}

func TestJWKSPublishesTheKeyThatVerifiesTheSignedSnapshot(t *testing.T) {
	server := newLoginIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	server.createUser(t, email, "correct horse battery", true, "active")

	status, _, body := loginRequest(t, server.url, email, "correct horse battery", nil)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body = %s", status, body)
	}
	var decoded loginSuccessJSON
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode login response: %v", err)
	}

	status, headers, jwksBody := getWithCookie(t, server.url, "/v1/jwks", "")
	if status != http.StatusOK {
		t.Fatalf("GET /v1/jwks status = %d, want 200; body = %s", status, jwksBody)
	}
	if headers.Get("Cache-Control") == "" || headers.Get("ETag") == "" {
		t.Error("JWKS response is missing cache headers")
	}

	var jwks readerstate.JWKS
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	parts := strings.Split(decoded.ReaderState.SignedSnapshot, ".")
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("decode JWT header JSON: %v", err)
	}
	if header.Alg != "ES256" {
		t.Errorf("JWT alg = %q, want ES256", header.Alg)
	}
	var publicKey *ecdsa.PublicKey
	for _, key := range jwks.Keys {
		if key.KID != header.KID {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			t.Fatalf("decode JWK x: %v", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			t.Fatalf("decode JWK y: %v", err)
		}
		publicKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	}
	if publicKey == nil {
		t.Fatalf("JWKS does not contain kid %q", header.KID)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(publicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Error("snapshot signature does not verify with the public JWKS key")
	}
}

func TestCORSAndCSRFProtectTheWebLoginSurface(t *testing.T) {
	server := newLoginIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	server.createUser(t, email, "correct horse battery", true, "active")

	preflight, err := http.NewRequestWithContext(context.Background(), http.MethodOptions, server.url+"/v1/auth/login", nil)
	if err != nil {
		t.Fatalf("new preflight request: %v", err)
	}
	preflight.Header.Set("Origin", loginTestOrigin)
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", "content-type")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(preflight)
	if err != nil {
		t.Fatalf("preflight request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", response.StatusCode)
	}
	if got := response.Header.Get("Access-Control-Allow-Origin"); got != loginTestOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, loginTestOrigin)
	}
	if got := response.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}

	status, headers, body := loginRequest(t, server.url, email, "correct horse battery", map[string]string{"Origin": "https://evil.example.com"})
	if status != http.StatusForbidden {
		t.Fatalf("cross-origin login status = %d, want 403; body = %s", status, body)
	}
	if headers.Values("Set-Cookie") != nil {
		t.Errorf("cross-origin login set cookies: %v", headers.Values("Set-Cookie"))
	}

	var sessions int
	if err := server.db.Pool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
		email,
	).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("rejected login created %d sessions, want 0", sessions)
	}
}

func TestCurrentUserWithoutSessionIsNotCacheable(t *testing.T) {
	server := newLoginIntegrationServer(t)
	status, headers, body := getWithCookie(t, server.url, "/v1/users/me", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("GET /v1/users/me status = %d, want 401; body = %s", status, body)
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", headers.Get("Cache-Control"))
	}
}
