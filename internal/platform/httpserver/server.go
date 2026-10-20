package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const readinessTimeout = 2 * time.Second

type Pinger interface {
	Ping(ctx context.Context) error
}

type Server struct {
	logger     *slog.Logger
	httpServer *http.Server
	listener   net.Listener
}

type Options struct {
	Middleware []func(http.Handler) http.Handler
}

func New(addr string, pinger Pinger, logger *slog.Logger, register ...func(*http.ServeMux)) *Server {
	return NewWithOptions(addr, pinger, logger, Options{}, register...)
}

func NewWithOptions(addr string, pinger Pinger, logger *slog.Logger, options Options, register ...func(*http.ServeMux)) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /readyz", readyz(pinger))
	for _, routes := range register {
		routes(mux)
	}

	var handler http.Handler = mux
	for index := len(options.Middleware) - 1; index >= 0; index-- {
		handler = options.Middleware[index](handler)
	}

	return &Server{
		logger: logger,
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

func (s *Server) Start(ctx context.Context) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	s.listener = listener

	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("http server stopped unexpectedly", "error", err)
		}
	}()

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.httpServer.Addr
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func readyz(pinger Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		if err := pinger.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
