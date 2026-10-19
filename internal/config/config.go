package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	defaultAppEnv           = "development"
	defaultHTTPAddr         = ":8080"
	defaultLogLevel         = "info"
	defaultShutdownTimeout  = 10 * time.Second
	defaultDBConnectTimeout = 5 * time.Second
	defaultDBMaxConns       = 10
	postgresScheme          = "postgres"
	postgresqlScheme        = "postgresql"
)

type Config struct {
	AppEnv           string
	HTTPAddr         string
	LogLevel         string
	DatabaseURL      string
	ShutdownTimeout  time.Duration
	DBConnectTimeout time.Duration
	DBMaxConns       int32
}

func Load() (Config, error) {
	return LoadFrom(os.Getenv)
}

func LoadFrom(getenv func(string) string) (Config, error) {
	cfg := Config{
		AppEnv:           valueOrDefault(getenv, "APP_ENV", defaultAppEnv),
		HTTPAddr:         valueOrDefault(getenv, "HTTP_ADDR", defaultHTTPAddr),
		LogLevel:         valueOrDefault(getenv, "LOG_LEVEL", defaultLogLevel),
		DatabaseURL:      getenv("DATABASE_URL"),
		ShutdownTimeout:  defaultShutdownTimeout,
		DBConnectTimeout: defaultDBConnectTimeout,
		DBMaxConns:       defaultDBMaxConns,
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
	return nil
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
