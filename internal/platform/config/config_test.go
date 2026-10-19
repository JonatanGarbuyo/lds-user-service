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
		"APP_ENV":            "production",
		"HTTP_ADDR":          ":9090",
		"LOG_LEVEL":          "debug",
		"DATABASE_URL":       "postgresql://lds:secret@db:5432/lds",
		"SHUTDOWN_TIMEOUT":   "30s",
		"DB_CONNECT_TIMEOUT": "1m",
		"DB_MAX_CONNS":       "20",
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
