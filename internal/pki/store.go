package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CA struct {
	Cert   *x509.Certificate
	Key    crypto.Signer
	Chain  [][]byte
	PKIDir string
	State  string
}

const (
	fileIntCAKey  = "int-ca.key"
	fileIntCACert = "int-ca.crt"
	fileSerial    = "serial"
)

func LoadCA(pkiDir, stateDir string) (*CA, error) {
	keyPath := filepath.Join(pkiDir, fileIntCAKey)
	crtPath := filepath.Join(pkiDir, fileIntCACert)

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid CA key PEM")
	}
	priv, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	cb, _ := pem.Decode(crtPEM)
	if cb == nil || !strings.Contains(cb.Type, "CERTIFICATE") {
		return nil, errors.New("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	serialPath := filepath.Join(stateDir, fileSerial)
	if _, err := os.Stat(serialPath); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(serialPath, []byte("1000"), 0o600); err != nil {
			return nil, fmt.Errorf("init serial: %w", err)
		}
	}

	return &CA{
		Cert:   cert,
		Key:    priv,
		PKIDir: pkiDir,
		State:  stateDir,
	}, nil
}

func nextSerial(stateDir string) (*big.Int, error) {
	path := filepath.Join(stateDir, fileSerial)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	n := new(big.Int)
	if _, ok := n.SetString(s, 10); !ok {
		return nil, errors.New("bad serial file")
	}
	next := new(big.Int).Add(n, big.NewInt(1))
	if err := os.WriteFile(path, []byte(next.String()), 0o600); err != nil {
		return nil, err
	}
	return n, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return k, nil
	case "PRIVATE KEY":
		anyk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := anyk.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 key type %T", anyk)
		}
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", block.Type)
	}
}

func (c *CA) SignCert(tpl *x509.Certificate, pub any) ([]byte, *big.Int, error) {
	serial, err := nextSerial(c.State)
	if err != nil {
		return nil, nil, fmt.Errorf("serial: %w", err)
	}
	tpl.SerialNumber = serial
	now := time.Now().Add(-1 * time.Minute)
	tpl.NotBefore = now
	if tpl.NotAfter.IsZero() {
		tpl.NotAfter = now.Add(180 * 24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, pub, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return p, serial, nil
}

func (c *CA) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}))
}
