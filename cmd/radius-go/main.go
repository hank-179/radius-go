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

const gracefulShutdownTimeout = 10 * time.Second

type apiServer interface {
	ListenAndServe() error
	Shutdown(context.Context) error
	Close() error
}

type radiusServer interface {
	ListenAndServe(context.Context) error
}

type serverResult struct {
	name string
	err  error
}

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
		TrustedProxies: cfg.API.TrustedProxies,
	})
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              cfg.Server.APIAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	radiusServer, err := radius.NewServer(
		cfg.Server.RadiusAddr,
		cfg.Server.RadiusMaxConcurrentRequests,
		cfg.Clients,
		st,
		logger.Named("radius"),
	)
	if err != nil {
		return err
	}

	logger.Info("Starting API server", zap.String("addr", cfg.Server.APIAddr))
	logger.Info("Starting RADIUS server", zap.String("addr", cfg.Server.RadiusAddr))
	return runServers(ctx, httpServer, radiusServer, logger)
}

func runServers(ctx context.Context, api apiServer, radius radiusServer, logger *zap.Logger) error {
	serverCtx, cancelServers := context.WithCancel(ctx)
	defer cancelServers()

	results := make(chan serverResult, 2)
	go func() {
		err := api.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		} else if err != nil {
			err = fmt.Errorf("api server: %w", err)
		}
		results <- serverResult{name: "API", err: err}
	}()
	go func() {
		err := radius.ListenAndServe(serverCtx)
		if err != nil {
			err = fmt.Errorf("radius server: %w", err)
		}
		results <- serverResult{name: "RADIUS", err: err}
	}()

	completed := 0
	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("Shutdown signal received")
	case result := <-results:
		completed++
		switch {
		case result.err != nil:
			runErr = result.err
			logger.Error("Server failed", zap.String("server", result.name), zap.Error(result.err))
		case ctx.Err() == nil:
			runErr = fmt.Errorf("%s server stopped unexpectedly", result.name)
			logger.Error("Server stopped unexpectedly", zap.String("server", result.name))
		}
	}
	cancelServers()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancelShutdown()
	apiForcedClosed := false
	forceCloseAPI := func() {
		if apiForcedClosed {
			return
		}
		apiForcedClosed = true
		if err := api.Close(); err != nil {
			logger.Error("API server forced close failed", zap.Error(err))
			runErr = errors.Join(runErr, fmt.Errorf("force close API server: %w", err))
		}
	}
	if err := api.Shutdown(shutdownCtx); err != nil {
		logger.Error("API server shutdown failed", zap.Error(err))
		runErr = errors.Join(runErr, fmt.Errorf("shut down API server: %w", err))
		forceCloseAPI()
	}

	for completed < 2 {
		select {
		case result := <-results:
			completed++
			if result.err != nil {
				runErr = errors.Join(runErr, result.err)
			}
		case <-shutdownCtx.Done():
			forceCloseAPI()
			return errors.Join(runErr, fmt.Errorf("wait for servers to stop: %w", shutdownCtx.Err()))
		}
	}

	logger.Info("Server stopped")
	return runErr
}
