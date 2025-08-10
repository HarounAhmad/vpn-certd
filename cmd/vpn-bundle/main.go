package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HarounAhmad/vpn-certd/internal/bundle"
)

func mustRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func main() {
	var cn, caPath, taPath, certPath, keyPath, outZip, remote, proto string
	var port int

	flag.StringVar(&cn, "cn", "", "Common Name")
	flag.StringVar(&caPath, "ca", "", "Path to ca.crt (PEM)")
	flag.StringVar(&taPath, "ta", "", "Path to ta.key (tls-crypt)")
	flag.StringVar(&certPath, "cert", "", "Path to client cert PEM")
	flag.StringVar(&keyPath, "key", "", "Path to client key PEM (optional)")
	flag.StringVar(&remote, "remote", "vpn.example.com", "OpenVPN remote host")
	flag.IntVar(&port, "port", 1194, "OpenVPN remote port")
	flag.StringVar(&proto, "proto", "udp", "OpenVPN proto (udp|tcp)")
	flag.StringVar(&outZip, "out", "", "Output zip path (default: ./dist/<cn>.zip)")
	flag.Parse()

	if cn == "" || caPath == "" || taPath == "" || certPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags: -cn -ca -ta -cert")
		os.Exit(2)
	}

	if outZip == "" {
		_ = os.MkdirAll("dist", 0o755)
		outZip = filepath.Join("dist", cn+".zip")
	}

	key := ""
	if keyPath != "" {
		key = mustRead(keyPath)
	}

	in := bundle.Inputs{
		CN:         cn,
		CAPEM:      mustRead(caPath),
		TaKey:      mustRead(taPath),
		CertPEM:    mustRead(certPath),
		KeyPEMOpt:  key,
		RemoteHost: remote,
		RemotePort: port,
		Proto:      proto,
	}
	out, err := bundle.Build(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bundle:", err)
		os.Exit(2)
	}
	if err := os.WriteFile(outZip, out.ZipBytes, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write zip:", err)
		os.Exit(2)
	}
	fmt.Printf(`OK %s
size=%d
sha256_b64=%s
`, outZip, len(out.ZipBytes), base64.StdEncoding.EncodeToString([]byte{}))
}
