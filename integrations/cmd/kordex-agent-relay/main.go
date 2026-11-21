package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"kordex.local/integrations/agentrelay"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("agent relay stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	mode := env("KORDEX_RELAY_MODE", "cluster")
	address := env("KORDEX_RELAY_LISTEN_ADDRESS", agentrelay.DefaultListenAddress)
	upstream := os.Getenv("KORDEX_RELAY_API_UPSTREAM")
	mappings, err := agentrelay.LoadMappings(os.Getenv("KORDEX_RELAY_MAPPINGS_FILE"))
	if err != nil {
		return err
	}
	tlsConfig, err := agentrelay.LoadServerTLSConfig(
		os.Getenv("KORDEX_RELAY_TLS_CERT_FILE"),
		os.Getenv("KORDEX_RELAY_TLS_KEY_FILE"),
		os.Getenv("KORDEX_RELAY_CLIENT_CA_FILE"),
		os.Getenv("KORDEX_RELAY_SERVER_NAME"),
	)
	if err != nil {
		return err
	}
	maxBytes := int64(agentrelay.DefaultMaxRequest)
	if raw := os.Getenv("KORDEX_RELAY_MAX_REQUEST_BYTES"); raw != "" {
		maxBytes, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid relay request size limit")
		}
	}
	timeout := 20 * time.Second
	if raw := os.Getenv("KORDEX_RELAY_REQUEST_TIMEOUT"); raw != "" {
		timeout, err = time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("invalid relay request timeout")
		}
	}
	opts := agentrelay.Options{MaxRequestBytes: maxBytes, RequestTimeout: timeout}
	var handler *agentrelay.Handler
	switch mode {
	case "cluster":
		if err := agentrelay.ValidateListenAddress(address); err != nil {
			return err
		}
		handler, err = agentrelay.NewHandler(upstream, mappings, opts)
	case "workstation":
		if os.Getenv("KORDEX_RELAY_LISTEN_ADDRESS") == "" {
			return fmt.Errorf("workstation relay listen address must be explicitly configured")
		}
		if err := agentrelay.ValidateWorkstationListenAddress(address); err != nil {
			return err
		}
		allowedClients, parseErr := agentrelay.ParsePrivateClientCIDRs(os.Getenv("KORDEX_RELAY_ALLOWED_CLIENT_CIDRS"))
		if parseErr != nil {
			return parseErr
		}
		handler, err = agentrelay.NewWorkstationHandler(upstream, mappings, allowedClients, opts)
	default:
		return fmt.Errorf("KORDEX_RELAY_MODE must be cluster or workstation")
	}
	if err != nil {
		return err
	}
	defer handler.CloseIdleConnections()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("relay listener unavailable")
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      70 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	tlsListener := tls.NewListener(listener, tlsConfig)
	var healthServer *http.Server
	var healthListener net.Listener
	var healthDone chan error
	if mode == "workstation" {
		healthAddress := env("KORDEX_RELAY_HEALTH_ADDRESS", agentrelay.DefaultHealthAddress)
		if err := agentrelay.ValidateWorkstationHealthAddress(healthAddress); err != nil {
			return err
		}
		healthListener, err = net.Listen("tcp", healthAddress)
		if err != nil {
			return fmt.Errorf("relay health listener unavailable")
		}
		healthServer = &http.Server{
			Handler:           agentrelay.WorkstationHealthHandler(),
			ReadHeaderTimeout: 3 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       15 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		healthDone = make(chan error, 1)
		go func() { healthDone <- healthServer.Serve(healthListener) }()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(tlsListener) }()
	logger.Info("private agent relay listening", "address", address)
	shutdown := func() error {
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var shutdownErr error
		if healthServer != nil {
			if err := healthServer.Shutdown(drain); err != nil {
				_ = healthServer.Close()
				shutdownErr = err
			}
		}
		if err := server.Shutdown(drain); err != nil {
			_ = server.Close()
			shutdownErr = err
		}
		return shutdownErr
	}
	select {
	case err := <-done:
		_ = shutdown()
		if healthDone != nil {
			if healthErr := <-healthDone; !errors.Is(healthErr, http.ErrServerClosed) && healthErr != nil {
				return fmt.Errorf("relay health server failed")
			}
		}
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("relay server failed")
		}
		return nil
	case err := <-healthDone:
		_ = shutdown()
		if relayErr := <-done; !errors.Is(relayErr, http.ErrServerClosed) && relayErr != nil {
			return fmt.Errorf("relay server failed")
		}
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("relay health server failed")
		}
		return nil
	case <-ctx.Done():
	}
	if err := shutdown(); err != nil {
		return fmt.Errorf("relay shutdown failed")
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) && err != nil {
		return fmt.Errorf("relay server failed")
	}
	if healthDone != nil {
		if err := <-healthDone; !errors.Is(err, http.ErrServerClosed) && err != nil {
			return fmt.Errorf("relay health server failed")
		}
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
