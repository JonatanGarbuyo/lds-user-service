package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
)

const (
	maxBodyBytes    = 1 << 20
	maxRequestID    = 128
	jsonMediaType   = "application/json"
	requestIDHeader = "X-Request-Id"
)

type UserRegistrar interface {
	Execute(ctx context.Context, input identity.RegisterUserInput) (identity.RegisterUserResult, error)
}

type Handler struct {
	register UserRegistrar
	logger   *slog.Logger
}

func New(register UserRegistrar, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{register: register, logger: logger}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/users", h)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := beginAPIResponse(w, r)

	input, failure := decodeRegisterRequest(w, r)
	if failure != nil {
		writeError(w, requestID, failure)
		return
	}

	result, err := h.register.Execute(r.Context(), input)
	switch {
	case err == nil:
		if result.VerificationDeliveryError != nil {
			h.logger.ErrorContext(r.Context(), "email verification dispatch failed",
				"request_id", requestID,
				"error", result.VerificationDeliveryError,
			)
		}
		writeJSON(w, http.StatusCreated, newUserResponse(result.User))
	case errors.Is(err, identity.ErrEmailAlreadyExists):
		writeError(w, requestID, &apiError{
			status:  http.StatusConflict,
			code:    "EMAIL_ALREADY_EXISTS",
			message: "An account with this email already exists.",
		})
	case errors.Is(err, identity.ErrRegistrationBusy):
		w.Header().Set("Retry-After", "1")
		writeError(w, requestID, &apiError{
			status:  http.StatusServiceUnavailable,
			code:    "SERVICE_UNAVAILABLE",
			message: "Registration is temporarily unavailable.",
		})
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

		h.logger.ErrorContext(r.Context(), "register user failed", "request_id", requestID, "error", err)
		writeError(w, requestID, &apiError{
			status:  http.StatusInternalServerError,
			code:    "INTERNAL_ERROR",
			message: "An unexpected error occurred.",
		})
	}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func newUserResponse(user identity.User) userResponse {
	return userResponse{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Status:        string(user.Status),
		CreatedAt:     user.CreatedAt.UTC(),
		UpdatedAt:     user.UpdatedAt.UTC(),
	}
}

type apiError struct {
	status  int
	code    string
	message string
	fields  map[string]string
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	RequestID string            `json:"requestId"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func decodeRegisterRequest(w http.ResponseWriter, r *http.Request) (identity.RegisterUserInput, *apiError) {
	var request registerRequest
	if failure := decodeJSONBody(w, r, &request); failure != nil {
		return identity.RegisterUserInput{}, failure
	}
	return identity.RegisterUserInput{
		Email:    request.Email,
		Password: request.Password,
	}, nil
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) *apiError {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != jsonMediaType {
		return &apiError{
			status:  http.StatusUnsupportedMediaType,
			code:    "UNSUPPORTED_MEDIA_TYPE",
			message: "Content-Type must be application/json.",
		}
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return decodeFailure(err)
	}
	if err := decoder.Decode(&struct{}{}); err != nil {
		if !errors.Is(err, io.EOF) {
			return decodeFailure(err)
		}
	} else {
		return invalidJSON()
	}
	return nil
}

func decodeFailure(err error) *apiError {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return &apiError{
			status:  http.StatusRequestEntityTooLarge,
			code:    "PAYLOAD_TOO_LARGE",
			message: "Request body is too large.",
		}
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		if typeErr.Field == "" {
			return &apiError{
				status:  http.StatusBadRequest,
				code:    "VALIDATION_ERROR",
				message: "Request body must be a JSON object.",
			}
		}
		return &apiError{
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "The request contains invalid fields.",
			fields:  map[string]string{typeErr.Field: "must be of type string"},
		}
	}

	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		return &apiError{
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "Request body contains an unknown field.",
		}
	}

	if errors.Is(err, io.EOF) {
		return &apiError{
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "Request body must be a JSON object.",
		}
	}

	return invalidJSON()
}

func invalidJSON() *apiError {
	return &apiError{
		status:  http.StatusBadRequest,
		code:    "VALIDATION_ERROR",
		message: "Request body must be valid JSON.",
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, requestID string, failure *apiError) {
	writeJSON(w, failure.status, errorEnvelope{
		Error: errorBody{
			Code:      failure.code,
			Message:   failure.message,
			RequestID: requestID,
			Fields:    failure.fields,
		},
	})
}

func beginAPIResponse(w http.ResponseWriter, r *http.Request) string {
	requestID := requestIDFrom(r)
	w.Header().Set(requestIDHeader, requestID)
	w.Header().Set("Cache-Control", "no-store")
	return requestID
}

func requestIDFrom(r *http.Request) string {
	requestID := r.Header.Get(requestIDHeader)
	if isSafeRequestID(requestID) {
		return requestID
	}
	return newRequestID()
}

func isSafeRequestID(requestID string) bool {
	if requestID == "" || len(requestID) > maxRequestID {
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
	if _, err := rand.Read(buffer[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buffer[:])
}
