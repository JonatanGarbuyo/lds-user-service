package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/identity"
	identityemail "github.com/JonatanGarbuyo/lds-user-service/internal/identity/email"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/identity/password"
	identitypostgres "github.com/JonatanGarbuyo/lds-user-service/internal/identity/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/config"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/httpserver"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/ratelimit"
	"github.com/JonatanGarbuyo/lds-user-service/internal/readerstate"
	readerstatehttp "github.com/JonatanGarbuyo/lds-user-service/internal/readerstate/httpapi"
	"github.com/JonatanGarbuyo/lds-user-service/internal/sessions"
	sessionspostgres "github.com/JonatanGarbuyo/lds-user-service/internal/sessions/postgres"
)

func main() {
	if err := run(); err != nil {
		slog.Error("user service failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if cfg.AppEnv != "development" {
		return fmt.Errorf("development email sender is only supported when APP_ENV=development")
	}

	logger := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connectCtx, cancelConnect := context.WithTimeout(ctx, cfg.DBConnectTimeout)
	db, err := postgres.Open(connectCtx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		cancelConnect()
		return fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(connectCtx); err != nil {
		cancelConnect()
		db.Close()
		return fmt.Errorf("connect to database: %w", err)
	}
	cancelConnect()
	defer db.Close()

	mailSender, err := identityemail.NewDevSender(cfg.MailOutboxFile)
	if err != nil {
		return fmt.Errorf("configure development email sender: %w", err)
	}

	userRepository := identitypostgres.NewRepository(db.Pool)
	hashLimiter := identity.NewHashLimiter(identity.DefaultMaxConcurrentHashes)
	verification := identity.NewEmailVerificationService(identity.EmailVerificationDependencies{
		Users:          userRepository,
		Challenges:     identitypostgres.NewVerificationRepository(db.Pool),
		Hasher:         password.New(),
		HashLimiter:    hashLimiter,
		Sender:         mailSender,
		RequestLimiter: ratelimit.New(10, time.Minute),
		ConfirmLimiter: ratelimit.New(20, time.Minute),
		Now:            time.Now,
	})
	registerUser := identity.NewRegisterUserWithLimiter(userRepository, password.New(), verification, hashLimiter)
	registerHandler := httpapi.New(registerUser, logger)
	verificationHandler := httpapi.NewEmailVerification(verification, logger)

	sessionService := sessions.NewService(sessionspostgres.NewRepository(db.Pool), sessions.Options{
		IdleTTL:     cfg.SessionIdleTTL,
		AbsoluteTTL: cfg.SessionAbsoluteTTL,
	})
	signer, generatedKey, err := readerstate.LoadSigner(readerstate.SignerConfig{
		Issuer:                 cfg.ReaderStateIssuer,
		Audience:               cfg.ReaderStateAudience,
		TTL:                    cfg.ReaderStateTTL,
		PrivateKeyPEM:          []byte(cfg.ReaderStatePrivateKey),
		PrivateKeyFile:         cfg.ReaderStatePrivateKeyFile,
		PreviousPublicKeysPEM:  []byte(cfg.ReaderStatePreviousKeys),
		PreviousPublicKeysFile: cfg.ReaderStatePreviousKeysFile,
		GenerateIfMissing:      cfg.AppEnv == "development",
	})
	if err != nil {
		return fmt.Errorf("configure reader state signer: %w", err)
	}
	if generatedKey {
		logger.Warn("generated an ephemeral reader state key for development; snapshots will not survive a restart")
	}

	loginUser, err := identity.NewLoginUser(identity.LoginDependencies{
		Users:                userRepository,
		Passwords:            password.New(),
		Sessions:             sessionService,
		ReaderState:          signer,
		HashLimiter:          hashLimiter,
		VerificationRequired: cfg.EmailVerificationRequired,
	})
	if err != nil {
		return fmt.Errorf("configure login: %w", err)
	}
	currentUser := identity.NewCurrentUser(userRepository, sessionService)
	cookie := sessions.Cookie{
		Name:     cfg.SessionCookieName,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	csrf := httpserver.NewCSRF(cfg.CORSAllowedOrigins, cfg.SessionCookieName)
	authHandler := httpapi.NewAuth(
		loginUser,
		currentUser,
		cookie,
		csrf,
		logger,
		ratelimit.New(10, time.Minute),
	)
	jwksHandler := readerstatehttp.New(signer)

	cors := httpserver.NewCORS(cfg.CORSAllowedOrigins)
	server := httpserver.NewWithOptions(
		cfg.HTTPAddr,
		db,
		logger,
		httpserver.Options{Middleware: []func(http.Handler) http.Handler{cors.Middleware, csrf.Middleware}},
		registerHandler.Register,
		verificationHandler.Register,
		authHandler.Register,
		jwksHandler.Register,
	)
	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("start http server: %w", err)
	}
	logger.Info("user service started",
		"addr", server.Addr(),
		"env", cfg.AppEnv,
		"email_verification_required", cfg.EmailVerificationRequired,
		"mail_outbox_file", cfg.MailOutboxFile,
	)

	<-ctx.Done()
	logger.Info("shutting down user service")

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	logger.Info("user service stopped")
	return nil
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel}))
}
