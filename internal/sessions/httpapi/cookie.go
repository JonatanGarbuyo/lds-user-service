package httpapi

import (
	"net/http"
	"time"
)

const DefaultCookieName = "lds_session"

type Cookie struct {
	Name     string
	Secure   bool
	SameSite http.SameSite
}

func (c Cookie) cookieName() string {
	if c.Name == "" {
		return DefaultCookieName
	}
	return c.Name
}

func (c Cookie) Set(w http.ResponseWriter, secret string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     c.cookieName(),
		Value:    secret,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	}
	if maxAge := int(time.Until(expiresAt).Seconds()); maxAge > 0 {
		cookie.MaxAge = maxAge
	}
	http.SetCookie(w, cookie)
}

func (c Cookie) Read(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(c.cookieName())
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (c Cookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName(),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	})
}
