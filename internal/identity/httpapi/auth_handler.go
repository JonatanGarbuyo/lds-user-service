package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
	sessionshttp "github.com/JonatanGarbuyo/lds-user-service/internal/sessions/httpapi"
)

type LoginExecutor interface {
	Execute(ctx context.Context, input identity.LoginInput) (identity.LoginResult, error)
}

type CurrentUserExecutor interface {
	Execute(ctx context.Context, sessionSecret string) (identity.User, error)
}

type CSRFIssuer interface {
	Issue(w http.ResponseWriter) (string, error)
	AllowRequestOrigin(r *http.Request) bool
}

type AuthHandler struct {
	login        LoginExecutor
	currentUser  CurrentUserExecutor
	cookie       sessionshttp.Cookie
	csrf         CSRFIssuer
	logger       *slog.Logger
	loginLimiter identity.AbuseLimiter
}

func NewAuth(
	login LoginExecutor,
	currentUser CurrentUserExecutor,
	cookie sessionshttp.Cookie,
	csrf CSRFIssuer,
	logger *slog.Logger,
	loginLimiter identity.AbuseLimiter,
) *AuthHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthHandler{
		login:        login,
		currentUser:  currentUser,
		cookie:       cookie,
		csrf:         csrf,
		logger:       logger,
		loginLimiter: loginLimiter,
	}
}

func (h *AuthHandler) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/auth/login", http.HandlerFunc(h.loginHandler))
	mux.Handle("GET /v1/users/me", http.HandlerFunc(h.me))
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	User        userResponse        `json:"user"`
	Session     sessionResponse     `json:"session"`
	ReaderState readerStateResponse `json:"readerState"`
	CSRFToken   string              `json:"csrfToken"`
}

type sessionResponse struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Current        bool      `json:"current"`
	CreatedAt      time.Time `json:"createdAt"`
	LastActivityAt time.Time `json:"lastActivityAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type readerStateResponse struct {
	SignedSnapshot string    `json:"signedSnapshot"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

func (h *AuthHandler) loginHandler(w http.ResponseWriter, r *http.Request) {
	requestID := beginAPIResponse(w, r)

	if !h.csrf.AllowRequestOrigin(r) {
		writeError(w, requestID, &apiError{
			status:  http.StatusForbidden,
			code:    "FORBIDDEN",
			message: "Request origin is not allowed.",
		})
		return
	}

	if h.loginLimiter != nil {
		allowed, retryAfter := h.loginLimiter.Allow("login:" + clientIP(r))
		if !allowed {
			writeRateLimited(w, requestID, &identity.RateLimitError{RetryAfter: retryAfter})
			return
		}
	}

	var request loginRequest
	if failure := decodeJSONBody(w, r, &request); failure != nil {
		writeError(w, requestID, failure)
		return
	}

	result, err := h.login.Execute(r.Context(), identity.LoginInput{
		Email:    request.Email,
		Password: request.Password,
	})
	switch {
	case err == nil:
		csrfToken, err := h.csrf.Issue(w)
		if err != nil {
			h.logger.ErrorContext(r.Context(), "issue csrf token failed", "request_id", requestID, "error", err)
			writeError(w, requestID, &apiError{
				status:  http.StatusInternalServerError,
				code:    "INTERNAL_ERROR",
				message: "An unexpected error occurred.",
			})
			return
		}
		h.cookie.Set(w, result.Session.Secret, result.Session.Session.AbsoluteExpiresAt)
		writeJSON(w, http.StatusOK, loginResponse{
			User:        newUserResponse(result.User),
			Session:     newSessionResponse(result.Session.Session),
			ReaderState: readerStateResponse{SignedSnapshot: result.ReaderState.SignedSnapshot, ExpiresAt: result.ReaderState.ExpiresAt.UTC()},
			CSRFToken:   csrfToken,
		})
	case errors.Is(err, identity.ErrInvalidCredentials):
		writeError(w, requestID, &apiError{
			status:  http.StatusUnauthorized,
			code:    "INVALID_CREDENTIALS",
			message: "Email or password is incorrect.",
		})
	case errors.Is(err, identity.ErrEmailNotVerified):
		writeError(w, requestID, &apiError{
			status:  http.StatusForbidden,
			code:    "EMAIL_NOT_VERIFIED",
			message: "Verify your email before signing in.",
		})
	case errors.Is(err, identity.ErrAccountSuspended):
		writeError(w, requestID, &apiError{
			status:  http.StatusForbidden,
			code:    "ACCOUNT_SUSPENDED",
			message: "This account cannot sign in.",
		})
	case errors.Is(err, identity.ErrHashingBusy):
		writeServiceUnavailable(w, requestID, "Sign in is temporarily unavailable.")
	default:
		var validationErr *identity.ValidationError
		if errors.As(err, &validationErr) {
			writeError(w, requestID, &apiError{
				status:  http.StatusBadRequest,
				code:    "VALIDATION_ERROR",
				message: "The request contains invalid fields.",
				fields:  validationErr.Fields,
			})
			return
		}
		h.logger.ErrorContext(r.Context(), "login failed", "request_id", requestID, "error", err)
		writeError(w, requestID, &apiError{
			status:  http.StatusInternalServerError,
			code:    "INTERNAL_ERROR",
			message: "An unexpected error occurred.",
		})
	}
}

func (h *AuthHandler) me(w http.ResponseWriter, r *http.Request) {
	requestID := beginAPIResponse(w, r)

	secret, ok := h.cookie.Read(r)
	if !ok {
		writeInvalidSession(w, requestID)
		return
	}

	user, err := h.currentUser.Execute(r.Context(), secret)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, newUserResponse(user))
	case errors.Is(err, identity.ErrWebSessionInvalid):
		writeInvalidSession(w, requestID)
	default:
		h.logger.ErrorContext(r.Context(), "load current user failed", "request_id", requestID, "error", err)
		writeError(w, requestID, &apiError{
			status:  http.StatusInternalServerError,
			code:    "INTERNAL_ERROR",
			message: "An unexpected error occurred.",
		})
	}
}

func writeInvalidSession(w http.ResponseWriter, requestID string) {
	writeError(w, requestID, &apiError{
		status:  http.StatusUnauthorized,
		code:    "INVALID_SESSION",
		message: "A valid session is required.",
	})
}

func newSessionResponse(session sessions.Session) sessionResponse {
	return sessionResponse{
		ID:             session.ID,
		Kind:           string(session.Kind),
		Current:        true,
		CreatedAt:      session.CreatedAt.UTC(),
		LastActivityAt: session.LastActivityAt.UTC(),
		ExpiresAt:      session.ExpiresAt.UTC(),
	}
}
