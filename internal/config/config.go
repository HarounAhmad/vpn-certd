package config

import (
	"flag"
	"os"

	"github.com/HarounAhmad/vpn-certd/internal/constants"
)

type Config struct {
	SocketPath string
	PKIDir     string
	StateDir   string
	LogLevel   string
	PolicyPath string
	CRLOutPath string
}

func Load() Config {
	var c Config

	socket := getenvDefault(constants.EnvSocket, constants.DefaultSocketPath)
	pki := getenvDefault(constants.EnvPKIDir, constants.DefaultPKIDir)
	state := getenvDefault(constants.EnvStateDir, constants.DefaultStateDir)
	level := getenvDefault(constants.EnvLogLevel, constants.DefaultLogLevel)
	policy := getenvDefault(constants.EnvPolicyPath, constants.DefaultPolicy)
	crlout := getenvDefault(constants.EnvCRLOutPath, constants.DefaultCRLOut)

	flag.StringVar(&c.SocketPath, "socket", socket, "UNIX socket path")
	flag.StringVar(&c.PKIDir, "pki", pki, "PKI directory (intermediate CA)")
	flag.StringVar(&c.StateDir, "state", state, "State directory")
	flag.StringVar(&c.LogLevel, "log-level", level, "log level: debug|info|warn|error")
	flag.StringVar(&c.PolicyPath, "policy", policy, "policy YAML file path")
	flag.StringVar(&c.CRLOutPath, "crl-out", crlout, "CRL deployment path for OpenVPN")
	flag.Parse()

	return c
}

func getenvDefault(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}
