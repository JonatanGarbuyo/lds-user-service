package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/config"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/httpserver"
	"github.com/JonatanGarbuyo/lds-user-service/internal/platform/postgres"
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

	server := httpserver.New(cfg.HTTPAddr, db, logger)
	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("start http server: %w", err)
	}
	logger.Info("user service started", "addr", server.Addr(), "env", cfg.AppEnv)

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
