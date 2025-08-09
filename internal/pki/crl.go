package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	fileRevoked = "revoked.json"
	fileCRL     = "crl.pem"
)

type RevokedEntry struct {
	Serial        string `json:"serial"`
	Reason        string `json:"reason"`
	RevokedAtUnix int64  `json:"revoked_at_unix"`
}

type revokedDB struct {
	Entries []RevokedEntry `json:"entries"`
}

func (c *CA) crlPath() string     { return filepath.Join(c.State, fileCRL) }
func (c *CA) revokedPath() string { return filepath.Join(c.State, fileRevoked) }

func (c *CA) loadRevoked() (*revokedDB, error) {
	path := c.revokedPath()
	var db revokedDB
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &db, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, err
	}
	return &db, nil
}

func (c *CA) saveRevoked(db *revokedDB) error {
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.revokedPath(), b, 0o600)
}

func parseSerialDec(s string) (*big.Int, error) {
	n := new(big.Int)
	if _, ok := n.SetString(s, 10); !ok {
		return nil, fmt.Errorf("bad serial: %s", s)
	}
	return n, nil
}

func (c *CA) RevokeAndWriteCRL(serialDec string, reason string) (string, error) {
	db, err := c.loadRevoked()
	if err != nil {
		return "", fmt.Errorf("load revoked: %w", err)
	}
	for _, e := range db.Entries {
		if e.Serial == serialDec {
			return c.writeCRL(db) // idempotent
		}
	}
	db.Entries = append(db.Entries, RevokedEntry{
		Serial:        serialDec,
		Reason:        reason,
		RevokedAtUnix: time.Now().Unix(),
	})
	if err := c.saveRevoked(db); err != nil {
		return "", fmt.Errorf("save revoked: %w", err)
	}
	return c.writeCRL(db)
}

func (c *CA) writeCRL(db *revokedDB) (string, error) {
	revoked := make([]pkix.RevokedCertificate, 0, len(db.Entries))
	for _, e := range db.Entries {
		n, err := parseSerialDec(e.Serial)
		if err != nil {
			return "", err
		}
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   n,
			RevocationTime: time.Unix(e.RevokedAtUnix, 0).UTC(),
			// ReasonCode not required by OpenVPN; omit extension.
		})
	}

	now := time.Now().UTC()
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  c.Cert.SignatureAlgorithm,
		RevokedCertificates: revoked,
		Number:              big.NewInt(now.Unix()),
		ThisUpdate:          now,
		NextUpdate:          now.Add(7 * 24 * time.Hour),
	}, c.Cert, c.Key)
	if err != nil {
		return "", fmt.Errorf("create crl: %w", err)
	}

	p := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err := os.WriteFile(c.crlPath(), p, 0o600); err != nil {
		return "", fmt.Errorf("write crl: %w", err)
	}
	return string(p), nil
}

func (c *CA) ReadCRL() (string, error) {
	b, err := os.ReadFile(c.crlPath())
	if err != nil {
		return "", err
	}
	return string(b), nil
}
