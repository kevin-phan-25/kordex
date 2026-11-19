// The scheduler is a continuously running worker. Cloud Run deployments require
// a worker pool or always-allocated CPU; request-only services cannot run it reliably.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"

	"kordex.local/control-plane/internal/config"
	"kordex.local/control-plane/internal/httpapi"
	"kordex.local/control-plane/internal/schedulerhealth"
	"kordex.local/control-plane/internal/store"
	"kordex.local/control-plane/internal/telemetry"
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
	shutdownTelemetry, err := telemetry.Setup(startup)
	if err != nil {
		return errors.New("telemetry setup failed")
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(shutdown); err != nil {
			logger.Error("telemetry shutdown failed")
		}
	}()
	worker := store.NewID()
	metrics := telemetry.NewSchedulerMetrics()
	probe := schedulerhealth.New(15 * time.Second)
	healthAddress := os.Getenv("KORDEX_SCHEDULER_HEALTH_ADDR")
	if healthAddress == "" {
		healthAddress = "0.0.0.0:8081"
	}
	healthServer := &http.Server{Addr: healthAddress, Handler: probe.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		logger.Info("starting scheduler health listener", "address", healthAddress)
		if serveErr := healthServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Error("scheduler health listener stopped", "error", serveErr)
			stop()
		}
	}()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = healthServer.Shutdown(shutdown)
	}()
	metricsAddress := os.Getenv("KORDEX_SCHEDULER_METRICS_ADDR")
	var metricsServer *http.Server
	if metricsAddress != "" {
		metricsServer = &http.Server{Addr: metricsAddress, Handler: metrics.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			logger.Info("starting scheduler metrics listener", "address", metricsAddress)
			if serveErr := metricsServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
				logger.Error("scheduler metrics listener stopped", "error", serveErr)
				stop()
			}
		}()
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = metricsServer.Shutdown(shutdown)
		}()
	}
	logger.Info("scheduler started", "worker_id", worker)
	lastSnapshot := time.Time{}
	for ctx.Err() == nil {
		tick, cancel := context.WithTimeout(ctx, 10*time.Second)
		started := time.Now()
		tickContext, tickSpan := telemetry.StartSchedulerTick(tick, otel.Tracer("kordex.scheduler"))
		traceID := tickSpan.SpanContext().TraceID().String()
		result, err := db.ScheduleOnce(tickContext, key, worker, 250*time.Millisecond)
		outcome := "idle"
		admitted := 0
		delay := 100 * time.Millisecond
		if err != nil {
			outcome = "error"
			class := telemetry.ClassifySchedulerError(err)
			telemetry.EndSchedulerTick(tickSpan, outcome, admitted, class)
			metrics.RecordError(class)
			logger.Error("scheduler transaction rolled back", "worker_id", worker, "trace_id", traceID, "error_class", class, "error_type", fmt.Sprintf("%T", err))
			delay = 2 * time.Second
		} else {
			probe.RecordSuccessfulTick(time.Now())
		}
		if err == nil && !result.Claimed {
			delay = 500 * time.Millisecond
		} else if err == nil {
			outcome = "claimed"
			admitted = len(result.Operations)
			if admitted > 0 {
				logger.Info("campaign operations admitted", "campaign_id", result.CampaignID, "epoch", result.Epoch, "count", admitted, "trace_id", traceID)
			}
		}
		if err == nil {
			telemetry.EndSchedulerTick(tickSpan, outcome, admitted, "")
		}
		cancel()
		metrics.RecordTick(outcome, time.Since(started), admitted)
		if metricsServer != nil && (lastSnapshot.IsZero() || time.Since(lastSnapshot) >= 15*time.Second) {
			snapshotCtx, snapshotCancel := context.WithTimeout(ctx, 5*time.Second)
			snapshot, snapshotErr := db.SchedulerSnapshot(snapshotCtx)
			snapshotCancel()
			if snapshotErr != nil {
				class := telemetry.ClassifySchedulerError(snapshotErr)
				metrics.RecordError(class)
				logger.Warn("scheduler metrics snapshot failed", "error_class", class, "error_type", fmt.Sprintf("%T", snapshotErr))
			} else {
				metrics.SetSnapshot(snapshot)
				lastSnapshot = time.Now()
			}
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
