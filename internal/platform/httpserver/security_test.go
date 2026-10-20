package httpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/httpserver"
)

func TestCORSAllowsExplicitOriginsWithCredentials(t *testing.T) {
	middleware := httpserver.NewCORS([]string{"https://app.example.com"})
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/users/me", nil)
	request.Header.Set("Origin", "https://app.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}
	if got := recorder.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestCORSDoesNotAllowUnknownOriginsOrWildcards(t *testing.T) {
	middleware := httpserver.NewCORS([]string{"https://app.example.com"})
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/users/me", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("unknown origin received Access-Control-Allow-Origin")
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("unknown origin received credentials permission")
	}
}

func TestCORSRequiresExplicitConfigurationForSameHostOrigins(t *testing.T) {
	middleware := httpserver.NewCORS([]string{"https://app.example.com"})
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/users/me", nil)
	request.Header.Set("Origin", "https://service.example.com")
	request.Host = "service.example.com"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("same-host origin without explicit configuration received CORS permission")
	}
}

func TestCORSHandlesPreflightForAllowedOrigin(t *testing.T) {
	middleware := httpserver.NewCORS([]string{"https://app.example.com"})
	handler := middleware.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("preflight reached the application handler")
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/v1/auth/login", nil)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Access-Control-Request-Method", "POST")
	request.Header.Set("Access-Control-Request-Headers", "content-type, x-csrf-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods is empty")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("Access-Control-Allow-Headers is empty")
	}
	if got := recorder.Header().Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id is empty")
	}
}

func TestCORSRejectsForbiddenPreflightWithRequestID(t *testing.T) {
	middleware := httpserver.NewCORS([]string{"https://app.example.com"})
	handler := middleware.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("forbidden preflight reached the application handler")
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/v1/auth/login", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
	if recorder.Header().Get("X-Request-Id") == "" {
		t.Error("X-Request-Id is empty")
	}
}

func TestCSRFRejectsUnsafeRequestsFromUnknownOrigins(t *testing.T) {
	middleware := httpserver.NewCSRF([]string{"https://app.example.com"}, "lds_session")
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unsafe request from a foreign origin reached the handler")
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/auth/login", nil)
	request.Header.Set("Origin", "https://evil.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
}

func TestCSRFRejectsSessionMutationsWithoutOriginEvidence(t *testing.T) {
	middleware := httpserver.NewCSRF([]string{"https://app.example.com"}, "lds_session")
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("session mutation without browser-origin evidence reached the handler")
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/sessions/revoke-others", nil)
	request.AddCookie(&http.Cookie{Name: "lds_session", Value: "opaque-secret"})
	request.AddCookie(&http.Cookie{Name: "lds_csrf", Value: "csrf-token"})
	request.Header.Set("X-CSRF-Token", "csrf-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
}

func TestCSRFAllowsPublicMutationsWithoutOriginEvidence(t *testing.T) {
	middleware := httpserver.NewCSRF([]string{"https://app.example.com"}, "lds_session")
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/users", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", recorder.Code)
	}
}

func TestCSRFAllowsSafeRequestsWithoutOrigin(t *testing.T) {
	middleware := httpserver.NewCSRF(nil, "lds_session")
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/users/me", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", recorder.Code)
	}
}

func TestCSRFRequiresDoubleSubmitTokenForCookieAuthenticatedMutations(t *testing.T) {
	middleware := httpserver.NewCSRF([]string{"https://app.example.com"}, "lds_session")
	reached := 0
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))

	base := func() *http.Request {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/sessions/revoke-others", nil)
		request.Header.Set("Origin", "https://app.example.com")
		request.AddCookie(&http.Cookie{Name: "lds_session", Value: "opaque-secret"})
		return request
	}

	request := base()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("missing token status = %d, want 403", recorder.Code)
	}

	request = base()
	request.AddCookie(&http.Cookie{Name: "lds_csrf", Value: "csrf-token"})
	request.Header.Set("X-CSRF-Token", "csrf-token")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Errorf("matching token status = %d, want 204", recorder.Code)
	}
	if reached != 1 {
		t.Errorf("handler reached %d times, want 1", reached)
	}
}

func TestCSRFIssueSetsReadableTokenCookie(t *testing.T) {
	middleware := httpserver.NewCSRF(nil, "lds_session")
	recorder := httptest.NewRecorder()

	token, err := middleware.Issue(recorder)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "lds_csrf" {
		t.Errorf("cookie name = %q, want lds_csrf", cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("cookie value = %q, want token", cookie.Value)
	}
	if cookie.HttpOnly {
		t.Error("CSRF cookie must be readable by the SDK")
	}
	if !cookie.Secure {
		t.Error("CSRF cookie must be Secure")
	}
}

func TestCSRFRequiresExplicitBrowserOriginEvidence(t *testing.T) {
	csrf := httpserver.NewCSRF([]string{"https://app.example.com"}, "lds_session")

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/auth/login", nil)
	if csrf.AllowRequestOrigin(request) {
		t.Error("request without Origin or Referer was allowed")
	}

	request.Header.Set("Origin", "https://app.example.com")
	if !csrf.AllowRequestOrigin(request) {
		t.Error("configured Origin was rejected")
	}

	request.Header.Set("Origin", "https://evil.example.com")
	if csrf.AllowRequestOrigin(request) {
		t.Error("foreign Origin was allowed")
	}

	request.Header.Del("Origin")
	request.Header.Set("Referer", "https://app.example.com/login")
	if !csrf.AllowRequestOrigin(request) {
		t.Error("configured Referer was rejected")
	}
}
