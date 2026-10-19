//go:build integration

package httpapi_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/password"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	platformpostgres "github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/migrations"
)

var (
	integrationMigrateOnce sync.Once
	integrationMigrateErr  error
)

type integrationServer struct {
	url        string
	db         *platformpostgres.DB
	repository *identitypostgres.Repository
}

func openIntegrationDatabase(t *testing.T) *platformpostgres.DB {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := platformpostgres.Open(ctx, databaseURL, 10)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(db.Close)

	integrationMigrateOnce.Do(func() {
		migrator, err := migrations.Open(databaseURL)
		if err != nil {
			integrationMigrateErr = err
			return
		}
		defer func() { _, _ = migrator.Close() }()

		if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			integrationMigrateErr = err
		}
	})
	if integrationMigrateErr != nil {
		t.Fatalf("apply migrations: %v", integrationMigrateErr)
	}

	return db
}

func newIntegrationServer(t *testing.T) *integrationServer {
	t.Helper()

	db := openIntegrationDatabase(t)
	repository := identitypostgres.NewRepository(db.Pool)
	register := identity.NewRegisterUser(repository, password.New())
	handler := httpapi.New(register, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &integrationServer{url: server.URL, db: db, repository: repository}
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

	found, err := server.repository.FindByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, user.ID)
	}

	var (
		storedEmail   string
		passwordHash  string
		emailVerified bool
		storedStatus  string
	)
	err = server.db.Pool.QueryRow(
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

func TestRegisterEndpointPersistsUserAcrossPoolReopen(t *testing.T) {
	server := newIntegrationServer(t)
	email := uniqueIntegrationEmail(t)

	status, _, body := post(t, server.url, fmt.Sprintf(`{"email":%q,"password":"correct horse battery"}`, email), jsonHeaders())
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", status, http.StatusCreated, body)
	}
	user := decodeUser(t, body)

	reopened := openIntegrationDatabase(t)
	found, err := identitypostgres.NewRepository(reopened.Pool).FindByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("FindByEmail() after reopen error = %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, user.ID)
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
