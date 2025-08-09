package config

import (
	"flag"
	"os"

	"github.com/HarounAhmad/vpn-certd/pkg/internal/constants"
)

type Config struct {
	SocketPath string
	PKIDir     string
	StateDir   string
	LogLevel   string
}

func Load() Config {
	var c Config

	socket := getenvDefault(constants.EnvSocket, constants.DefaultSocketPath)
	pki := getenvDefault(constants.EnvPKIDir, constants.DefaultPKIDir)
	state := getenvDefault(constants.EnvStateDir, constants.DefaultStateDir)
	level := getenvDefault(constants.EnvLogLevel, constants.DefaultLogLevel)

	flag.StringVar(&c.SocketPath, "socket", socket, "UNIX socket path")
	flag.StringVar(&c.PKIDir, "pki", pki, "PKI directory (intermediate CA)")
	flag.StringVar(&c.StateDir, "state", state, "State directory")
	flag.StringVar(&c.LogLevel, "log-level", level, "log level: debug|info|warn|error")
	flag.Parse()

	return c
}

func getenvDefault(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}
