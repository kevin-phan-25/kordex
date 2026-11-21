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
	"syscall"
	"time"

	"kordex.local/integrations/agentgateway"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("agent gateway stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	address := os.Getenv("KORDEX_GATEWAY_LISTEN_ADDRESS")
	if address == "" {
		address = agentgateway.DefaultListenAddress
	}
	if err := agentgateway.ValidateListenAddress(address); err != nil {
		return err
	}
	certificate, err := agentgateway.LoadOriginCertificate(
		os.Getenv("KORDEX_GATEWAY_TLS_CERT_FILE"),
		os.Getenv("KORDEX_GATEWAY_TLS_KEY_FILE"),
		os.Getenv("KORDEX_GATEWAY_TLS_SERVER_NAME"),
	)
	if err != nil {
		return err
	}
	handler, err := agentgateway.NewHandler(os.Getenv("KORDEX_GATEWAY_CLIENT_ID"), os.Getenv("KORDEX_GATEWAY_CLIENT_SECRET"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for agent gateway failed")
	}
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(tlsListener) }()
	logger.Info("agent gateway listening", "address", address)
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("agent gateway server failed")
		}
		return nil
	case <-ctx.Done():
	}
	drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(drain); err != nil {
		_ = server.Close()
		return fmt.Errorf("agent gateway shutdown failed")
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) && err != nil {
		return fmt.Errorf("agent gateway server failed")
	}
	return nil
}
