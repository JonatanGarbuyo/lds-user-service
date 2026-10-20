package httpserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

type CORS struct {
	allowed map[string]struct{}
}

func NewCORS(origins []string) *CORS {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}
	return &CORS{allowed: allowed}
}

func (c *CORS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && explicitOriginAllowed(origin, c.allowed) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id, Retry-After")
			if r.Method == http.MethodOptions {
				setSecurityRequestID(w, r)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Request-Id")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else if r.Method == http.MethodOptions {
			writeSecurityError(w, r, http.StatusForbidden, "FORBIDDEN", "Request origin is not allowed.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func explicitOriginAllowed(origin string, allowed map[string]struct{}) bool {
	_, exists := allowed[origin]
	return exists
}

func writeSecurityError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	requestID := setSecurityRequestID(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":      code,
			"message":   message,
			"requestId": requestID,
		},
	})
}

func setSecurityRequestID(w http.ResponseWriter, r *http.Request) string {
	return SetRequestID(w, r)
}

func SetRequestID(w http.ResponseWriter, r *http.Request) string {
	requestID := r.Header.Get("X-Request-Id")
	if !validRequestID(requestID) {
		requestID = newRequestID()
	}
	w.Header().Set("X-Request-Id", requestID)
	return requestID
}

func validRequestID(requestID string) bool {
	if requestID == "" || len(requestID) > 128 {
		return false
	}
	for _, character := range requestID {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-', character == '_', character == '.':
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err == nil {
		return hex.EncodeToString(buffer[:])
	}
	return "unknown"
}
