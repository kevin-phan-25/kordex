package main

import (
	"context"
	"errors"
	"flag"
	"kordex.local/control-plane/internal/config"
	"kordex.local/control-plane/internal/httpapi"
	"kordex.local/control-plane/internal/store"
	"kordex.local/control-plane/internal/telemetry"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("service stopped", "error", err.Error())
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	migrate := flag.Bool("migrate", false, "apply migrations and exit")
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db, err := store.Open(startup, cfg.DatabaseURL)
	if err != nil {
		return errors.New("database connection failed; verify configuration and availability")
	}
	defer db.Close()
	if *migrate {
		if err := db.Migrate(startup); err != nil {
			return errors.New("migration failed; verify schema compatibility and database privileges")
		}
		logger.Info("database migrations complete")
		return nil
	}
	if err := db.Ready(startup); err != nil {
		return errors.New("database not ready; run kordex -migrate first")
	}
	shutdown, err := telemetry.Setup(startup)
	if err != nil {
		return errors.New("telemetry setup failed")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			logger.Error("telemetry shutdown failed")
		}
	}()
	server := &http.Server{Addr: cfg.Address, Handler: httpapi.New(db, cfg.AdminToken, cfg.ProductName, logger), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() {
		logger.Info("starting control plane", "address", cfg.Address, "product", cfg.ProductName)
		done <- server.ListenAndServe()
	}()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(drain); err != nil {
			_ = server.Close()
			return err
		}
		err := <-done
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
