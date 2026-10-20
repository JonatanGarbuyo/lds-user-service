package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAppEnv                    = "development"
	defaultHTTPAddr                  = ":8080"
	defaultLogLevel                  = "info"
	defaultShutdownTimeout           = 10 * time.Second
	defaultDBConnectTimeout          = 5 * time.Second
	defaultDBMaxConns                = 10
	defaultEmailVerificationRequired = true
	defaultMailOutboxFile            = "/tmp/lds-user-service-mail/outbox.jsonl"
	defaultSessionCookieName         = "lds_session"
	defaultSessionIdleTTL            = 30 * 24 * time.Hour
	defaultSessionAbsoluteTTL        = 90 * 24 * time.Hour
	defaultReaderStateIssuer         = "lds-user-service"
	defaultReaderStateAudience       = "lds-web"
	defaultReaderStateTTL            = 30 * time.Minute
	postgresScheme                   = "postgres"
	postgresqlScheme                 = "postgresql"
)

type Config struct {
	AppEnv                      string
	HTTPAddr                    string
	LogLevel                    string
	DatabaseURL                 string
	ShutdownTimeout             time.Duration
	DBConnectTimeout            time.Duration
	DBMaxConns                  int32
	EmailVerificationRequired   bool
	MailOutboxFile              string
	SessionCookieName           string
	SessionIdleTTL              time.Duration
	SessionAbsoluteTTL          time.Duration
	CORSAllowedOrigins          []string
	ReaderStateIssuer           string
	ReaderStateAudience         string
	ReaderStateTTL              time.Duration
	ReaderStatePrivateKey       string
	ReaderStatePrivateKeyFile   string
	ReaderStatePreviousKeys     string
	ReaderStatePreviousKeysFile string
}

func Load() (Config, error) {
	return LoadFrom(os.Getenv)
}

func LoadFrom(getenv func(string) string) (Config, error) {
	cfg := Config{
		AppEnv:                      valueOrDefault(getenv, "APP_ENV", defaultAppEnv),
		HTTPAddr:                    valueOrDefault(getenv, "HTTP_ADDR", defaultHTTPAddr),
		LogLevel:                    valueOrDefault(getenv, "LOG_LEVEL", defaultLogLevel),
		DatabaseURL:                 getenv("DATABASE_URL"),
		ShutdownTimeout:             defaultShutdownTimeout,
		DBConnectTimeout:            defaultDBConnectTimeout,
		DBMaxConns:                  defaultDBMaxConns,
		EmailVerificationRequired:   defaultEmailVerificationRequired,
		MailOutboxFile:              valueOrDefault(getenv, "MAIL_OUTBOX_FILE", defaultMailOutboxFile),
		SessionCookieName:           valueOrDefault(getenv, "SESSION_COOKIE_NAME", defaultSessionCookieName),
		SessionIdleTTL:              defaultSessionIdleTTL,
		SessionAbsoluteTTL:          defaultSessionAbsoluteTTL,
		CORSAllowedOrigins:          list(getenv("CORS_ALLOWED_ORIGINS")),
		ReaderStateIssuer:           valueOrDefault(getenv, "READER_STATE_ISSUER", defaultReaderStateIssuer),
		ReaderStateAudience:         valueOrDefault(getenv, "READER_STATE_AUDIENCE", defaultReaderStateAudience),
		ReaderStateTTL:              defaultReaderStateTTL,
		ReaderStatePrivateKey:       getenv("READER_STATE_PRIVATE_KEY"),
		ReaderStatePrivateKeyFile:   getenv("READER_STATE_PRIVATE_KEY_FILE"),
		ReaderStatePreviousKeys:     getenv("READER_STATE_PREVIOUS_PUBLIC_KEYS"),
		ReaderStatePreviousKeysFile: getenv("READER_STATE_PREVIOUS_PUBLIC_KEYS_FILE"),
	}

	var err error
	if cfg.ShutdownTimeout, err = durationOrDefault(getenv, "SHUTDOWN_TIMEOUT", defaultShutdownTimeout); err != nil {
		return Config{}, err
	}
	if cfg.DBConnectTimeout, err = durationOrDefault(getenv, "DB_CONNECT_TIMEOUT", defaultDBConnectTimeout); err != nil {
		return Config{}, err
	}
	if cfg.DBMaxConns, err = int32OrDefault(getenv, "DB_MAX_CONNS", defaultDBMaxConns); err != nil {
		return Config{}, err
	}
	if cfg.EmailVerificationRequired, err = boolOrDefault(getenv, "EMAIL_VERIFICATION_REQUIRED", defaultEmailVerificationRequired); err != nil {
		return Config{}, err
	}
	if cfg.SessionIdleTTL, err = durationOrDefault(getenv, "SESSION_IDLE_TTL", defaultSessionIdleTTL); err != nil {
		return Config{}, err
	}
	if cfg.SessionAbsoluteTTL, err = durationOrDefault(getenv, "SESSION_ABSOLUTE_TTL", defaultSessionAbsoluteTTL); err != nil {
		return Config{}, err
	}
	if cfg.ReaderStateTTL, err = durationOrDefault(getenv, "READER_STATE_TTL", defaultReaderStateTTL); err != nil {
		return Config{}, err
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validate(cfg Config) error {
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("config: DATABASE_URL is required")
	}
	parsed, err := url.Parse(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("config: DATABASE_URL is invalid: %w", err)
	}
	if parsed.Scheme != postgresScheme && parsed.Scheme != postgresqlScheme {
		return fmt.Errorf("config: DATABASE_URL must use the postgres or postgresql scheme, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("config: DATABASE_URL must include a host")
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: LOG_LEVEL must be one of debug, info, warn, error, got %q", cfg.LogLevel)
	}

	if cfg.ShutdownTimeout <= 0 {
		return fmt.Errorf("config: SHUTDOWN_TIMEOUT must be greater than zero")
	}
	if cfg.DBConnectTimeout <= 0 {
		return fmt.Errorf("config: DB_CONNECT_TIMEOUT must be greater than zero")
	}
	if cfg.MailOutboxFile == "" {
		return fmt.Errorf("config: MAIL_OUTBOX_FILE must not be empty")
	}
	if !validCookieName(cfg.SessionCookieName) {
		return fmt.Errorf("config: SESSION_COOKIE_NAME must be a valid cookie name")
	}
	if cfg.SessionAbsoluteTTL < cfg.SessionIdleTTL {
		return fmt.Errorf("config: SESSION_ABSOLUTE_TTL must be greater than or equal to SESSION_IDLE_TTL")
	}
	for _, origin := range cfg.CORSAllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" {
			return fmt.Errorf("config: CORS_ALLOWED_ORIGINS contains an invalid origin %q", origin)
		}
		if origin == "*" {
			return fmt.Errorf("config: CORS_ALLOWED_ORIGINS must list explicit origins, not *")
		}
	}
	if cfg.ReaderStateIssuer == "" || cfg.ReaderStateAudience == "" {
		return fmt.Errorf("config: READER_STATE_ISSUER and READER_STATE_AUDIENCE must not be empty")
	}
	if cfg.ReaderStatePrivateKey == "" && cfg.ReaderStatePrivateKeyFile == "" && cfg.AppEnv != defaultAppEnv {
		return fmt.Errorf("config: READER_STATE_PRIVATE_KEY or READER_STATE_PRIVATE_KEY_FILE is required outside development")
	}
	return nil
}

func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
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

func list(value string) []string {
	if value == "" {
		return nil
	}
	values := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func valueOrDefault(getenv func(string) string, key, fallback string) string {
	if value := getenv(key); value != "" {
		return value
	}
	return fallback
}

func durationOrDefault(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	value := getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a valid duration (for example 10s): %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}
	return parsed, nil
}

func boolOrDefault(getenv func(string) string, key string, fallback bool) (bool, error) {
	value := getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("config: %s must be a boolean (true or false): %w", key, err)
	}
	return parsed, nil
}

func int32OrDefault(getenv func(string) string, key string, fallback int32) (int32, error) {
	value := getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}
	return int32(parsed), nil
}
