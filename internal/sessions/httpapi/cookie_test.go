package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sessionshttp "github.com/JonatanGarbuyo/lds-user-service/internal/sessions/httpapi"
)

func TestWebSessionCookieIsHostOnlySecureHttpOnlyAndSameSite(t *testing.T) {
	recorder := httptest.NewRecorder()
	cookie := sessionshttp.Cookie{Secure: true, SameSite: http.SameSiteLaxMode}
	expiresAt := time.Now().Add(time.Hour)

	cookie.Set(recorder, "opaque-secret", expiresAt)

	response := recorder.Result()
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	value := cookies[0]
	if value.Name != sessionshttp.DefaultCookieName {
		t.Errorf("name = %q, want %q", value.Name, sessionshttp.DefaultCookieName)
	}
	if value.Value != "opaque-secret" {
		t.Errorf("value = %q", value.Value)
	}
	if !value.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if !value.Secure {
		t.Error("Secure = false, want true")
	}
	if value.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", value.SameSite)
	}
	if value.Domain != "" {
		t.Errorf("Domain = %q, want host-only cookie", value.Domain)
	}
	if value.Path != "/" {
		t.Errorf("Path = %q, want /", value.Path)
	}
}

func TestWebSessionCookieCanBeReadAndCleared(t *testing.T) {
	cookie := sessionshttp.Cookie{Secure: true, SameSite: http.SameSiteLaxMode}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/users/me", nil)
	request.AddCookie(&http.Cookie{Name: sessionshttp.DefaultCookieName, Value: "opaque-secret"})

	secret, ok := cookie.Read(request)
	if !ok || secret != "opaque-secret" {
		t.Fatalf("Read() = %q, %t; want opaque-secret, true", secret, ok)
	}

	recorder := httptest.NewRecorder()
	cookie.Clear(recorder)
	cleared := recorder.Result().Cookies()[0]
	if cleared.MaxAge >= 0 {
		t.Errorf("cleared MaxAge = %d, want negative", cleared.MaxAge)
	}
}
