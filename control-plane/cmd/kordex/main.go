package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kordex.local/control-plane/internal/config"
	"kordex.local/control-plane/internal/httpapi"
	"kordex.local/control-plane/internal/identity"
	"kordex.local/control-plane/internal/store"
	"kordex.local/control-plane/internal/telemetry"
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
	maintenanceKey, err := httpapi.LoadMaintenanceKey(os.Getenv("KORDEX_MAINTENANCE_SIGNING_KEY_FILE"))
	if err != nil {
		return errors.New("invalid maintenance signing key file")
	}
	options := httpapi.Options{AllowBootstrap: cfg.AllowBootstrap, MaintenanceKey: maintenanceKey, RateLimitRPS: cfg.APIRateLimitRPS, RateLimitBurst: cfg.APIRateLimitBurst}
	if cfg.OIDCIssuer != "" {
		verifier, err := identity.New(startup, cfg.OIDCIssuer, cfg.OIDCAudience)
		if err != nil {
			return err
		}
		options.Verifier = verifier
	}
	server := &http.Server{Addr: cfg.Address, Handler: httpapi.NewWithOptions(db, cfg.AdminToken, cfg.ProductName, logger, options), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	metricsServer := &http.Server{Addr: cfg.MetricsAddress, Handler: httpapi.MetricsHandler(server.Handler), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	return serve(ctx, server, metricsServer, logger, cfg.ProductName)
}

func serve(ctx context.Context, api, metrics *http.Server, logger *slog.Logger, product string) error {
	apiListener, err := net.Listen("tcp", api.Addr)
	if err != nil {
		return err
	}
	metricsListener, err := net.Listen("tcp", metrics.Addr)
	if err != nil {
		_ = apiListener.Close()
		return err
	}
	done := make(chan error, 2)
	go func() {
		logger.Info("starting control plane", "address", api.Addr, "product", product)
		done <- api.Serve(apiListener)
	}()
	go func() {
		logger.Info("starting metrics listener", "address", metrics.Addr)
		done <- metrics.Serve(metricsListener)
	}()
	var first error
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			first = err
		}
	case <-ctx.Done():
	}
	drain, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, server := range []*http.Server{metrics, api} {
		if err := server.Shutdown(drain); err != nil {
			_ = server.Close()
			if first == nil {
				first = err
			}
		}
	}
	for i := 0; i < 2; i++ {
		if err := <-done; !errors.Is(err, http.ErrServerClosed) && first == nil {
			first = err
		}
	}
	return first
}
