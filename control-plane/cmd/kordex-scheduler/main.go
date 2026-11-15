// The scheduler is a continuously running worker. Cloud Run deployments require
// a worker pool or always-allocated CPU; request-only services cannot run it reliably.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kordex.local/control-plane/internal/config"
	"kordex.local/control-plane/internal/httpapi"
	"kordex.local/control-plane/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("scheduler stopped", "error", err)
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	key, err := httpapi.LoadMaintenanceKey(os.Getenv("KORDEX_MAINTENANCE_SIGNING_KEY_FILE"))
	if err != nil || len(key) == 0 {
		return errors.New("scheduler requires a maintenance signing key file")
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = config.ValidateDatabaseURL(os.Getenv("DATABASE_URL"), os.Getenv("KORDEX_LOCAL_DEVELOPMENT") == "true"); err != nil {
		return err
	}
	db, err := store.Open(startup, os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("database unavailable")
	}
	defer db.Close()
	if err = db.Ready(startup); err != nil {
		return errors.New("database not ready; apply migrations first")
	}
	worker := store.NewID()
	logger.Info("scheduler started", "worker_id", worker)
	for ctx.Err() == nil {
		tick, cancel := context.WithTimeout(ctx, 10*time.Second)
		result, err := db.ScheduleOnce(tick, key, worker, 250*time.Millisecond)
		cancel()
		delay := 100 * time.Millisecond
		if err != nil {
			logger.Error("scheduler transaction rolled back", "worker_id", worker)
			delay = 2 * time.Second
		} else if !result.Claimed {
			delay = 500 * time.Millisecond
		} else if len(result.Operations) > 0 {
			logger.Info("campaign operations admitted", "campaign_id", result.CampaignID, "epoch", result.Epoch, "count", len(result.Operations))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}
