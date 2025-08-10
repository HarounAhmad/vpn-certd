package constants

import (
	"time"
)

const (
	AppName     = "vpn-certd"
	EnvSocket   = "VPN_CERTD_SOCKET"
	EnvPKIDir   = "VPN_CERTD_PKI_DIR"
	EnvStateDir = "VPN_CERTD_STATE_DIR"
	EnvLogLevel = "VPN_CERTD_LOG_LEVEL"

	DefaultSocketPath = "/run/vpn-certd.sock"
	DefaultPKIDir     = "/etc/vpn-certd/pki"
	DefaultStateDir   = "/var/lib/vpn-certd"
	DefaultLogLevel   = "info"
)

const (
	ShutdownTimeout   = 5 * time.Second
	ReadWriteDeadline = 30 * time.Second
)

const (
	// octal literals
	DirPerm0700    = 0o700
	FilePerm0600   = 0o600
	SocketPerm0600 = 0o600
)

const (
	EnvPolicyPath = "VPNCERTD_POLICY"
	EnvCRLOutPath = "VPNCERTD_CRL_OUT"
	DefaultPolicy = "/etc/vpn-certd/policy.yaml"
	DefaultCRLOut = "/etc/openvpn/crl.pem"
)
