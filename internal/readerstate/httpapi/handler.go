package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
)

type KeySource interface {
	JWKS() readerstate.JWKS
}

type Handler struct {
	keys KeySource
}

func New(keys KeySource) *Handler {
	return &Handler{keys: keys}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /v1/jwks", h)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setRequestID(w, r)
	body, err := json.Marshal(h.keys.JWKS())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func setRequestID(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" || len(requestID) > 128 {
		var buffer [16]byte
		if _, err := rand.Read(buffer[:]); err == nil {
			requestID = hex.EncodeToString(buffer[:])
		} else {
			requestID = "unknown"
		}
	}
	w.Header().Set("X-Request-Id", requestID)
}
