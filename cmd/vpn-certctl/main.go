package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/api"
)

func main() {
	var socket, op, cn, profile, keyType, pass, csr, serial, reason string
	flag.StringVar(&socket, "socket", "./dist/run/vpn-certd.sock", "unix socket")
	flag.StringVar(&op, "op", "HEALTH", "op: HEALTH|SIGN|GENKEY_AND_SIGN|REVOKE|GET_CRL|LIST_ISSUED")
	flag.StringVar(&cn, "cn", "", "common name")
	flag.StringVar(&profile, "profile", "client", "profile: client|server")
	flag.StringVar(&keyType, "key-type", "rsa4096", "key type: rsa4096|ed25519")
	flag.StringVar(&pass, "passphrase", "", "passphrase (for GENKEY_AND_SIGN)")
	flag.StringVar(&csr, "csr", "", "PEM CSR (for SIGN)")
	flag.StringVar(&serial, "serial", "", "serial (for REVOKE)")
	flag.StringVar(&reason, "reason", "", "reason (for REVOKE)")
	flag.Parse()

	req := api.Request{
		Op:         api.Op(op),
		CN:         cn,
		Profile:    api.Profile(profile),
		KeyType:    api.KeyType(keyType),
		Passphrase: pass,
		CSRPEM:     csr,
		Serial:     serial,
		Reason:     reason,
	}

	b, _ := json.Marshal(req)
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(2)
	}
	defer conn.Close()
	if _, err := conn.Write(append(b, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(2)
	}
	dec := json.NewDecoder(conn)
	var resp api.Response
	if err := dec.Decode(&resp); err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}
