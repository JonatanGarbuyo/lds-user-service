package httpserver_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/httpserver"
)

type pingerFunc func(context.Context) error

func (f pingerFunc) Ping(ctx context.Context) error {
	return f(ctx)
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startServer(t *testing.T, pinger httpserver.Pinger) *httpserver.Server {
	t.Helper()

	srv := httpserver.New("127.0.0.1:0", pinger, newTestLogger())
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request error = %v", err)
	}

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s error = %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body error = %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestServerHealthAndReadiness(t *testing.T) {
	srv := startServer(t, pingerFunc(func(context.Context) error { return nil }))

	status, body := get(t, "http://"+srv.Addr()+"/healthz")
	if status != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", status, http.StatusOK)
	}
	if strings.TrimSpace(body) != `{"status":"ok"}` {
		t.Errorf("GET /healthz body = %q, want %q", body, `{"status":"ok"}`)
	}

	status, body = get(t, "http://"+srv.Addr()+"/readyz")
	if status != http.StatusOK {
		t.Errorf("GET /readyz status = %d, want %d", status, http.StatusOK)
	}
	if strings.TrimSpace(body) != `{"status":"ready"}` {
		t.Errorf("GET /readyz body = %q, want %q", body, `{"status":"ready"}`)
	}
}

func TestServerReadinessFailsWhenDatabaseIsUnavailable(t *testing.T) {
	srv := startServer(t, pingerFunc(func(context.Context) error {
		return errors.New("database is down")
	}))

	status, body := get(t, "http://"+srv.Addr()+"/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	if strings.TrimSpace(body) != `{"status":"unavailable"}` {
		t.Errorf("GET /readyz body = %q, want %q", body, `{"status":"unavailable"}`)
	}

	status, _ = get(t, "http://"+srv.Addr()+"/healthz")
	if status != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d", status, http.StatusOK)
	}
}

func TestServerShutdownStopsAcceptingConnections(t *testing.T) {
	srv := httpserver.New("127.0.0.1:0", pingerFunc(func(context.Context) error { return nil }), newTestLogger())
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	addr := srv.Addr()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	client := &http.Client{Timeout: 200 * time.Millisecond}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		t.Fatalf("new request error = %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("GET after Shutdown() succeeded, want connection error")
	}
}

func TestServerUnknownRouteReturnsNotFound(t *testing.T) {
	srv := startServer(t, pingerFunc(func(context.Context) error { return nil }))

	status, _ := get(t, "http://"+srv.Addr()+"/v1/users")
	if status != http.StatusNotFound {
		t.Errorf("GET /v1/users status = %d, want %d", status, http.StatusNotFound)
	}
}
