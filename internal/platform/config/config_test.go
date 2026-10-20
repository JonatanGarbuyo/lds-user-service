package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/config"
)

func env(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := config.LoadFrom(env(map[string]string{
		"DATABASE_URL": "postgres://lds:secret@localhost:5432/lds_user_service?sslmode=disable",
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if cfg.AppEnv != "development" {
		t.Errorf("AppEnv = %q, want %q", cfg.AppEnv, "development")
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %s, want %s", cfg.ShutdownTimeout, 10*time.Second)
	}
	if cfg.DBConnectTimeout != 5*time.Second {
		t.Errorf("DBConnectTimeout = %s, want %s", cfg.DBConnectTimeout, 5*time.Second)
	}
	if cfg.DBMaxConns != 10 {
		t.Errorf("DBMaxConns = %d, want %d", cfg.DBMaxConns, 10)
	}
	if !cfg.EmailVerificationRequired {
		t.Error("EmailVerificationRequired = false, want true by default")
	}
	if cfg.MailOutboxFile != "/tmp/lds-user-service-mail/outbox.jsonl" {
		t.Errorf("MailOutboxFile = %q, want the development outbox default", cfg.MailOutboxFile)
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	_, err := config.LoadFrom(env(nil))
	if err == nil {
		t.Fatal("LoadFrom() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Errorf("error = %q, want mention of DATABASE_URL", err)
	}
}

func TestLoadRejectsInvalidDatabaseURL(t *testing.T) {
	_, err := config.LoadFrom(env(map[string]string{
		"DATABASE_URL": "mysql://lds:secret@localhost:3306/lds",
	}))
	if err == nil {
		t.Fatal("LoadFrom() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Errorf("error = %q, want mention of DATABASE_URL", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := config.LoadFrom(env(map[string]string{
		"APP_ENV":                       "production",
		"HTTP_ADDR":                     ":9090",
		"LOG_LEVEL":                     "debug",
		"DATABASE_URL":                  "postgresql://lds:secret@db:5432/lds",
		"SHUTDOWN_TIMEOUT":              "30s",
		"DB_CONNECT_TIMEOUT":            "1m",
		"DB_MAX_CONNS":                  "20",
		"EMAIL_VERIFICATION_REQUIRED":   "false",
		"MAIL_OUTBOX_FILE":              "/tmp/custom-mail.jsonl",
		"SESSION_COOKIE_NAME":           "custom_session",
		"SESSION_IDLE_TTL":              "24h",
		"SESSION_ABSOLUTE_TTL":          "720h",
		"CORS_ALLOWED_ORIGINS":          "https://app.example.com, https://editor.example.com",
		"READER_STATE_ISSUER":           "https://users.example.com",
		"READER_STATE_AUDIENCE":         "https://site.example.com",
		"READER_STATE_TTL":              "15m",
		"READER_STATE_PRIVATE_KEY_FILE": "/run/secrets/reader-state.pem",
	}))
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if cfg.AppEnv != "production" {
		t.Errorf("AppEnv = %q, want %q", cfg.AppEnv, "production")
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":9090")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %s, want %s", cfg.ShutdownTimeout, 30*time.Second)
	}
	if cfg.DBConnectTimeout != time.Minute {
		t.Errorf("DBConnectTimeout = %s, want %s", cfg.DBConnectTimeout, time.Minute)
	}
	if cfg.DBMaxConns != 20 {
		t.Errorf("DBMaxConns = %d, want %d", cfg.DBMaxConns, 20)
	}
	if cfg.EmailVerificationRequired {
		t.Error("EmailVerificationRequired = true, want false")
	}
	if cfg.MailOutboxFile != "/tmp/custom-mail.jsonl" {
		t.Errorf("MailOutboxFile = %q, want /tmp/custom-mail.jsonl", cfg.MailOutboxFile)
	}
	if cfg.SessionCookieName != "custom_session" {
		t.Errorf("SessionCookieName = %q, want custom_session", cfg.SessionCookieName)
	}
	if cfg.SessionIdleTTL != 24*time.Hour || cfg.SessionAbsoluteTTL != 720*time.Hour {
		t.Errorf("session TTLs = %s/%s", cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL)
	}
	if len(cfg.CORSAllowedOrigins) != 2 || cfg.CORSAllowedOrigins[0] != "https://app.example.com" {
		t.Errorf("CORSAllowedOrigins = %v", cfg.CORSAllowedOrigins)
	}
	if cfg.ReaderStateTTL != 15*time.Minute {
		t.Errorf("ReaderStateTTL = %s, want 15m", cfg.ReaderStateTTL)
	}
}

func TestLoadRequiresReaderStateKeyOutsideDevelopment(t *testing.T) {
	_, err := config.LoadFrom(env(map[string]string{
		"APP_ENV":      "production",
		"DATABASE_URL": "postgres://lds:secret@localhost:5432/lds",
	}))
	if err == nil {
		t.Fatal("LoadFrom() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "READER_STATE_PRIVATE_KEY") {
		t.Errorf("error = %q, want mention of READER_STATE_PRIVATE_KEY", err)
	}
}

func TestLoadRejectsWildcardAndInvalidOrigins(t *testing.T) {
	for _, origin := range []string{"*", "https://app.example.com/path", "ftp://app.example.com", "not-an-origin"} {
		t.Run(origin, func(t *testing.T) {
			_, err := config.LoadFrom(env(map[string]string{
				"DATABASE_URL":         "postgres://lds:secret@localhost:5432/lds",
				"CORS_ALLOWED_ORIGINS": origin,
			}))
			if err == nil {
				t.Fatal("LoadFrom() error = nil, want error")
			}
			if !strings.Contains(err.Error(), "CORS_ALLOWED_ORIGINS") {
				t.Errorf("error = %q, want mention of CORS_ALLOWED_ORIGINS", err)
			}
		})
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{name: "shutdown timeout", key: "SHUTDOWN_TIMEOUT", value: "soon", want: "SHUTDOWN_TIMEOUT"},
		{name: "db connect timeout", key: "DB_CONNECT_TIMEOUT", value: "later", want: "DB_CONNECT_TIMEOUT"},
		{name: "db max conns", key: "DB_MAX_CONNS", value: "many", want: "DB_MAX_CONNS"},
		{name: "zero db max conns", key: "DB_MAX_CONNS", value: "0", want: "DB_MAX_CONNS"},
		{name: "log level", key: "LOG_LEVEL", value: "verbose", want: "LOG_LEVEL"},
		{name: "email verification required", key: "EMAIL_VERIFICATION_REQUIRED", value: "sometimes", want: "EMAIL_VERIFICATION_REQUIRED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string]string{
				"DATABASE_URL": "postgres://lds:secret@localhost:5432/lds",
				tt.key:         tt.value,
			}
			_, err := config.LoadFrom(env(values))
			if err == nil {
				t.Fatal("LoadFrom() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want mention of %s", err, tt.want)
			}
		})
	}
}
