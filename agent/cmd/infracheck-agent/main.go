package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/infracheck/infracheck/container/agent/internal/agent"
	"github.com/infracheck/infracheck/container/agent/internal/config"
	"github.com/infracheck/infracheck/container/agent/internal/storage"
)

func main() {
	cfgPath := os.Getenv("INFRACHECK_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/infracheck/config.yaml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: config.LogLevel(cfg.Agent.LogLevel)}))
	slog.SetDefault(logger)

	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	app, err := agent.New(cfg, db, logger)
	if err != nil {
		slog.Error("failed to initialize agent", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app.Start(ctx)
	agent.StartMDNS(ctx, cfg, logger)

	server := &http.Server{
		Addr:              cfg.Agent.BindAddress + ":" + cfg.Agent.PortString(),
		Handler:           app.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("agent listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown failed", "error", err)
	}
}
