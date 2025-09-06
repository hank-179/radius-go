package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"radius-go/internal/api"
	"radius-go/internal/config"
	"radius-go/internal/logging"
	"radius-go/internal/radius"
	"radius-go/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "radius-go failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "Path to the YAML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger, cleanupLogs, err := logging.New(cfg.Logging)
	if err != nil {
		return err
	}
	defer func() { _ = cleanupLogs() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, dbCreated, err := store.Open(ctx, cfg.Database.Path, cfg.Security.BcryptCost)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			logger.Error("Failed to close database", zap.Error(err))
		}
	}()

	if dbCreated {
		created, err := st.CreateAPIKey(ctx, "bootstrap")
		if err != nil {
			return fmt.Errorf("create bootstrap api key: %w", err)
		}
		fmt.Printf("Initial API key (shown once): %s\n", created.Key)
		logger.Warn("Initial API key generated and printed to stdout", zap.Int64("api_key_id", created.APIKey.ID), zap.String("api_key_name", created.APIKey.Name))
	}

	router, err := api.NewRouter(st, logger.Named("api"), api.RouterConfig{
		AllowedSources: cfg.API.AllowedSources,
	})
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              cfg.Server.APIAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	radiusServer, err := radius.NewServer(cfg.Server.RadiusAddr, cfg.Clients, st, logger.Named("radius"))
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("Starting API server", zap.String("addr", cfg.Server.APIAddr))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api server: %w", err)
		}
	}()
	go func() {
		logger.Info("Starting RADIUS server", zap.String("addr", cfg.Server.RadiusAddr))
		if err := radiusServer.ListenAndServe(ctx); err != nil {
			errCh <- fmt.Errorf("radius server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("Shutdown signal received")
	case err := <-errCh:
		stop()
		logger.Error("Server failed", zap.Error(err))
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("API server shutdown failed", zap.Error(err))
		return err
	}
	logger.Info("Server stopped")
	return nil
}
