package main

import (
	"context"
	"github.com/HarounAhmad/vpn-certd/internal/app"
	"github.com/HarounAhmad/vpn-certd/internal/config"
	"github.com/HarounAhmad/vpn-certd/internal/constants"
	"github.com/HarounAhmad/vpn-certd/internal/logging"
	"github.com/HarounAhmad/vpn-certd/internal/security"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HarounAhmad/vpn-certd/pkg/version"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.LogLevel)
	log.Info("starting", "name", version.Name, "version", version.Version, "commit", version.Commit)

	if err := security.EnsureSocketDir(cfg.SocketPath); err != nil {
		log.Error("socket_dir", slog.String("err", err.Error()))
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := app.New(log).StartServer(ctx, cfg.SocketPath); err != nil {
		log.Error("start_server", slog.String("err", err.Error()))
		os.Exit(2)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	cancel()
	time.Sleep(constants.ShutdownTimeout)
	log.Info("stopped")
}
