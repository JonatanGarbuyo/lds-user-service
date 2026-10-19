//go:build integration

package httpapi_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/password"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/testpg"
	platformpostgres "github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
)

type integrationServer struct {
	url       string
	db        *platformpostgres.DB
	server    *httptest.Server
	closeOnce sync.Once
}

func newIntegrationServer(t *testing.T) *integrationServer {
	t.Helper()

	db := testpg.OpenDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	register := identity.NewRegisterUser(repository, password.New())
	handler := httpapi.New(register, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)

	result := &integrationServer{
		url:    server.URL,
		db:     db,
		server: server,
	}
	t.Cleanup(result.Close)
	return result
}

func (s *integrationServer) Close() {
	s.closeOnce.Do(func() {
		s.server.Close()
		s.db.Close()
	})
}

func uniqueIntegrationEmail(t *testing.T) string {
	t.Helper()

	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("generate unique email: %v", err)
	}
	return fmt.Sprintf("http-%s@example.com", hex.EncodeToString(suffix[:]))
}

func TestRegisterEndpointPersistsUserInPostgres(t *testing.T) {
	server := newIntegrationServer(t)
	email := uniqueIntegrationEmail(t)
	passwordValue := "correct horse battery"

	status, headers, body := post(t, server.url, fmt.Sprintf(`{"email":" %s ","password":%q}`, strings.ToUpper(email), passwordValue), jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	if headers.Get("Set-Cookie") != "" || headers.Get("Authorization") != "" {
		t.Errorf("response exposed credentials: cookie=%q authorization=%q", headers.Get("Set-Cookie"), headers.Get("Authorization"))
	}

	user := decodeUser(t, body)
	if user.Email != email {
		t.Errorf("user.email = %q, want %q", user.Email, email)
	}
	if user.EmailVerified {
		t.Error("user.emailVerified = true, want false")
	}
	if user.Status != "active" {
		t.Errorf("user.status = %q, want active", user.Status)
	}

	var (
		storedEmail   string
		passwordHash  string
		emailVerified bool
		storedStatus  string
	)
	err := server.db.Pool.QueryRow(
		context.Background(),
		`SELECT email, password_hash, email_verified, status FROM users WHERE id = $1`,
		user.ID,
	).Scan(&storedEmail, &passwordHash, &emailVerified, &storedStatus)
	if err != nil {
		t.Fatalf("query stored user: %v", err)
	}
	if storedEmail != email {
		t.Errorf("stored email = %q, want %q", storedEmail, email)
	}
	if storedEmail != strings.ToLower(storedEmail) {
		t.Errorf("stored email is not normalized: %q", storedEmail)
	}
	if emailVerified {
		t.Error("stored email_verified = true, want false")
	}
	if storedStatus != "active" {
		t.Errorf("stored status = %q, want active", storedStatus)
	}
	if passwordHash == passwordValue {
		t.Error("stored password hash is the plaintext password")
	}
	if !strings.HasPrefix(passwordHash, "$argon2id$") {
		t.Errorf("stored password hash = %q, want an Argon2id PHC string", passwordHash)
	}
	ok, err := password.New().Verify(passwordValue, passwordHash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("stored password hash does not match the password")
	}
}

func TestRegisterEndpointRejectsInvalidInputInPostgres(t *testing.T) {
	server := newIntegrationServer(t)

	tests := []struct {
		name        string
		email       string
		body        string
		contentType string
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "invalid email",
			email:       "not-an-email",
			body:        `{"email":"not-an-email","password":"correct horse battery"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "VALIDATION_ERROR",
		},
		{
			name:        "short password",
			body:        "",
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "VALIDATION_ERROR",
		},
		{
			name:        "malformed JSON",
			body:        `{`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "VALIDATION_ERROR",
		},
		{
			name:        "unknown field",
			body:        "",
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "VALIDATION_ERROR",
		},
		{
			name:        "wrong content type",
			body:        "",
			contentType: "text/plain",
			wantStatus:  http.StatusUnsupportedMediaType,
			wantCode:    "UNSUPPORTED_MEDIA_TYPE",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			email := test.email
			body := test.body
			if email == "" {
				email = uniqueIntegrationEmail(t)
			}
			if body == "" {
				body = fmt.Sprintf(`{"email":%q,"password":"short"}`, email)
			}
			if test.name == "unknown field" {
				body = fmt.Sprintf(`{"email":%q,"password":"correct horse battery","role":"admin"}`, email)
			}

			headers := map[string]string{"Content-Type": test.contentType}
			status, _, responseBody := post(t, server.url, body, headers)
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", status, test.wantStatus, responseBody)
			}
			if response := decodeError(t, responseBody); response.Error.Code != test.wantCode {
				t.Errorf("error.code = %q, want %q", response.Error.Code, test.wantCode)
			}

			if test.name == "malformed JSON" {
				return
			}
			var count int
			if err := server.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&count); err != nil {
				t.Fatalf("count users: %v", err)
			}
			if count != 0 {
				t.Errorf("users with email = %d, want 0", count)
			}
		})
	}
}

func TestRegisterEndpointPersistsUserAcrossServiceRestart(t *testing.T) {
	first := newIntegrationServer(t)
	email := uniqueIntegrationEmail(t)

	status, _, body := post(t, first.url, fmt.Sprintf(`{"email":%q,"password":"correct horse battery"}`, email), jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	user := decodeUser(t, body)

	first.Close()

	second := newIntegrationServer(t)
	status, _, body = post(t, second.url, fmt.Sprintf(`{"email":%q,"password":"another strong password"}`, email), jsonHeaders())
	if status != http.StatusConflict {
		t.Fatalf("status after restart = %d, want %d; body = %s", status, http.StatusConflict, body)
	}

	var storedID string
	if err := second.db.Pool.QueryRow(context.Background(), `SELECT id::text FROM users WHERE email = $1`, email).Scan(&storedID); err != nil {
		t.Fatalf("query stored user after restart: %v", err)
	}
	if storedID != user.ID {
		t.Errorf("stored ID after restart = %q, want %q", storedID, user.ID)
	}
}

func TestRegisterEndpointRejectsDuplicateEmailInPostgres(t *testing.T) {
	server := newIntegrationServer(t)
	email := uniqueIntegrationEmail(t)

	status, _, body := post(t, server.url, fmt.Sprintf(`{"email":%q,"password":"correct horse battery"}`, email), jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("first status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}

	status, _, body = post(t, server.url, fmt.Sprintf(`{"email":" %s ","password":"another strong password"}`, strings.ToUpper(email)), jsonHeaders())
	if status != http.StatusConflict {
		t.Fatalf("second status = %d, want %d; body = %s", status, http.StatusConflict, body)
	}
	if response := decodeError(t, body); response.Error.Code != "EMAIL_ALREADY_EXISTS" {
		t.Errorf("error.code = %q, want EMAIL_ALREADY_EXISTS", response.Error.Code)
	}

	var count int
	if err := server.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&count); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Errorf("users with email = %d, want 1", count)
	}
}

func TestRegisterEndpointHandlesConcurrentDuplicateRegistrations(t *testing.T) {
	server := newIntegrationServer(t)
	email := uniqueIntegrationEmail(t)

	const workers = 5
	variants := []string{
		email,
		strings.ToUpper(email),
		" " + email,
		email + " ",
		" " + strings.ToUpper(email) + " ",
	}

	statuses := make(chan int, workers)
	requestErrors := make(chan error, workers)
	start := make(chan struct{})

	for _, variant := range variants {
		go func(address string) {
			<-start

			payload, err := json.Marshal(map[string]string{
				"email":    address,
				"password": "correct horse battery",
			})
			if err != nil {
				requestErrors <- err
				return
			}

			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.url+"/v1/users", strings.NewReader(string(payload)))
			if err != nil {
				requestErrors <- err
				return
			}
			request.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 30 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				requestErrors <- err
				return
			}
			defer func() { _ = response.Body.Close() }()
			_, _ = io.Copy(io.Discard, response.Body)

			statuses <- response.StatusCode
		}(variant)
	}

	close(start)

	var created, conflicts int
	for range workers {
		select {
		case err := <-requestErrors:
			t.Fatalf("registration request error = %v", err)
		case status := <-statuses:
			switch status {
			case http.StatusCreated:
				created++
			case http.StatusConflict:
				conflicts++
			default:
				t.Errorf("status = %d, want 201 or 409", status)
			}
		}
	}

	if created != 1 || conflicts != workers-1 {
		t.Errorf("created = %d, conflicts = %d, want 1 and %d", created, conflicts, workers-1)
	}

	var count int
	if err := server.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&count); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Errorf("users with email = %d, want 1", count)
	}
}
