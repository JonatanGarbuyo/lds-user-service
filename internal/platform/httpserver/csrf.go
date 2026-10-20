package httpserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

const defaultCSRFCookieName = "lds_csrf"

type CSRF struct {
	allowed           map[string]struct{}
	cookieName        string
	sessionCookieName string
}

func NewCSRF(origins []string, sessionCookieName string) *CSRF {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}
	if sessionCookieName == "" {
		sessionCookieName = "lds_session"
	}
	return &CSRF{allowed: allowed, cookieName: defaultCSRFCookieName, sessionCookieName: sessionCookieName}
}

func (c *CSRF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		if !requestOriginAllowed(r, c.allowed) {
			writeSecurityError(w, r, http.StatusForbidden, "FORBIDDEN", "Request origin is not allowed.")
			return
		}

		if _, err := r.Cookie(c.sessionCookieName); err == nil {
			cookie, err := r.Cookie(c.cookieName)
			header := r.Header.Get("X-CSRF-Token")
			if err != nil || header == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
				writeSecurityError(w, r, http.StatusForbidden, "FORBIDDEN", "CSRF token is missing or invalid.")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (c *CSRF) AllowRequestOrigin(r *http.Request) bool {
	if r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" {
		return false
	}
	return requestOriginAllowed(r, c.allowed)
}

func (c *CSRF) Issue(w http.ResponseWriter) (string, error) {
	var buffer [32]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buffer[:])
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return token, nil
}

func requestOriginAllowed(r *http.Request, allowed map[string]struct{}) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			return false
		}
		if referer := r.Header.Get("Referer"); referer != "" {
			parsed, err := url.Parse(referer)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return false
			}
			origin = parsed.Scheme + "://" + parsed.Host
		} else {
			return true
		}
	}
	return originAllowed(r, origin, allowed)
}

func originAllowed(r *http.Request, origin string, allowed map[string]struct{}) bool {
	if origin == "null" {
		return false
	}
	if _, exists := allowed[origin]; exists {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if strings.TrimSuffix(parsed.Path, "/") != "" {
		return false
	}
	return parsed.Host == r.Host
}
