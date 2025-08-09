package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/app"
	"github.com/HarounAhmad/vpn-certd/internal/config"
	"github.com/HarounAhmad/vpn-certd/internal/constants"
	"github.com/HarounAhmad/vpn-certd/internal/logging"
	"github.com/HarounAhmad/vpn-certd/internal/pki"
	"github.com/HarounAhmad/vpn-certd/internal/security"
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

	ca, err := pki.LoadCA(cfg.PKIDir, cfg.StateDir)
	if err != nil {
		log.Error("load_ca", slog.String("err", err.Error()))
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	a := app.New(log)
	a.CA = ca
	if err := a.StartServer(ctx, cfg.SocketPath); err != nil {
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
