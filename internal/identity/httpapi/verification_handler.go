package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

type EmailVerification interface {
	Request(ctx context.Context, input identity.RequestEmailVerificationInput) error
	Confirm(ctx context.Context, input identity.ConfirmEmailVerificationInput) (identity.User, error)
}

type EmailVerificationHandler struct {
	verification EmailVerification
	logger       *slog.Logger
}

func NewEmailVerification(verification EmailVerification, logger *slog.Logger) *EmailVerificationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &EmailVerificationHandler{verification: verification, logger: logger}
}

func (h *EmailVerificationHandler) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/auth/email-verification/request", http.HandlerFunc(h.request))
	mux.Handle("POST /v1/auth/email-verification/confirm", http.HandlerFunc(h.confirm))
}

type emailVerificationRequest struct {
	Email string `json:"email"`
}

type emailVerificationConfirmRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type acceptedResponse struct {
	Status string `json:"status"`
}

func (h *EmailVerificationHandler) request(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r)
	w.Header().Set(requestIDHeader, requestID)
	w.Header().Set("Cache-Control", "no-store")

	var request emailVerificationRequest
	if failure := decodeJSONBody(w, r, &request); failure != nil {
		writeError(w, requestID, failure)
		return
	}

	err := h.verification.Request(r.Context(), identity.RequestEmailVerificationInput{
		Email:    request.Email,
		ClientIP: clientIP(r),
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, acceptedResponse{Status: "accepted"})
	case errors.Is(err, identity.ErrRateLimited):
		writeRateLimited(w, requestID, err)
	case errors.Is(err, identity.ErrVerificationDelivery):
		h.logger.ErrorContext(r.Context(), "email verification dispatch failed",
			"request_id", requestID,
			"error", err,
		)
		writeJSON(w, http.StatusAccepted, acceptedResponse{Status: "accepted"})
	default:
		writeRequestError(w, r, h.logger, requestID, err, "request email verification failed")
	}
}

func (h *EmailVerificationHandler) confirm(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFrom(r)
	w.Header().Set(requestIDHeader, requestID)
	w.Header().Set("Cache-Control", "no-store")

	var request emailVerificationConfirmRequest
	if failure := decodeJSONBody(w, r, &request); failure != nil {
		writeError(w, requestID, failure)
		return
	}

	user, err := h.verification.Confirm(r.Context(), identity.ConfirmEmailVerificationInput{
		Email:    request.Email,
		Code:     request.Code,
		ClientIP: clientIP(r),
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, newUserResponse(user))
	case errors.Is(err, identity.ErrRateLimited):
		writeRateLimited(w, requestID, err)
	case errors.Is(err, identity.ErrInvalidVerificationCode):
		writeError(w, requestID, &apiError{
			status:  http.StatusBadRequest,
			code:    "INVALID_VERIFICATION_CODE",
			message: "The verification code is invalid or has expired.",
		})
	default:
		writeRequestError(w, r, h.logger, requestID, err, "confirm email verification failed")
	}
}

func writeRateLimited(w http.ResponseWriter, requestID string, err error) {
	var rateLimitErr *identity.RateLimitError
	retryAfter := time.Second
	if errors.As(err, &rateLimitErr) && rateLimitErr.RetryAfter > 0 {
		retryAfter = rateLimitErr.RetryAfter
	}
	seconds := int64((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeError(w, requestID, &apiError{
		status:  http.StatusTooManyRequests,
		code:    "RATE_LIMITED",
		message: "Too many requests. Try again later.",
	})
}

func writeRequestError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, requestID string, err error, logMessage string) {
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

	logger.ErrorContext(r.Context(), logMessage, "request_id", requestID, "error", err)
	writeError(w, requestID, &apiError{
		status:  http.StatusInternalServerError,
		code:    "INTERNAL_ERROR",
		message: "An unexpected error occurred.",
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
