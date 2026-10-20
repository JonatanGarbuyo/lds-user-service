package httpapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
	readerstatehttp "github.com/JonatanGarbuyo/lds-user-service/internal/readerstate/httpapi"
)

func newJWKSHandler(t *testing.T) (*readerstate.Signer, http.Handler) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := readerstate.NewSigner(key, nil, readerstate.Options{
		Issuer:   "https://users.example.com",
		Audience: "https://site.example.com",
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	mux := http.NewServeMux()
	readerstatehttp.New(signer).Register(mux)
	return signer, mux
}

func TestJWKSEndpointIsPublicCacheableAndExposesOnlyPublicKeys(t *testing.T) {
	signer, handler := newJWKSHandler(t)

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/jwks", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got == "" {
		t.Error("Cache-Control is empty")
	}
	etag := recorder.Header().Get("ETag")
	if etag == "" {
		t.Error("ETag is empty")
	}

	var jwks readerstate.JWKS
	if err := json.Unmarshal(recorder.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(jwks.Keys))
	}
	if jwks.Keys[0].KID != signer.ActiveKeyID() {
		t.Errorf("kid = %q, want %q", jwks.Keys[0].KID, signer.ActiveKeyID())
	}
	for _, forbidden := range []string{"private", "secret", "\"d\"", "\"p\"", "\"q\""} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Errorf("JWKS contains %q", forbidden)
		}
	}

	conditional := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/jwks", nil)
	conditional.Header.Set("If-None-Match", etag)
	conditionalRecorder := httptest.NewRecorder()
	handler.ServeHTTP(conditionalRecorder, conditional)
	if conditionalRecorder.Code != http.StatusNotModified {
		t.Errorf("conditional status = %d, want 304", conditionalRecorder.Code)
	}
}

func TestJWKSEndpointDoesNotRequireAuthentication(t *testing.T) {
	_, handler := newJWKSHandler(t)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/jwks", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusUnauthorized {
		t.Fatal("JWKS required authentication")
	}
	body, _ := io.ReadAll(response.Result().Body)
	if len(body) == 0 {
		t.Fatal("JWKS body is empty")
	}
}
