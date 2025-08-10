package pki

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/api"
)

const fileIssued = "issued.jsonl"

func (c *CA) issuedPath() string { return filepath.Join(c.State, fileIssued) }

func (c *CA) AppendIssued(cn, profile, serial, notAfterRFC3339, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("append_issued: bad cert pem")
	}
	sum := sha256.Sum256(block.Bytes)
	ent := api.IssuedMeta{
		Serial:   serial,
		CN:       cn,
		Profile:  profile,
		NotAfter: notAfterRFC3339,
		SHA256:   hex.EncodeToString(sum[:]),
	}
	b, err := json.Marshal(ent)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(c.issuedPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func (c *CA) ListIssued(max int) ([]api.IssuedMeta, error) {
	f, err := os.Open(c.issuedPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []api.IssuedMeta{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []api.IssuedMeta
	sc := bufio.NewScanner(f)
	const maxLine = 512 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)

	for sc.Scan() {
		var ent api.IssuedMeta
		if err := json.Unmarshal(sc.Bytes(), &ent); err != nil {
			continue
		}
		out = append(out, ent)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if max > 0 && len(out) > max {
		out = out[len(out)-max:]
	}
	return out, nil
}

func parseCertNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("bad cert pem")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

func (c *CA) ExistsCNActive(cn string) (bool, error) {
	list, err := c.ListIssued(0)
	if err != nil {
		return false, err
	}
	for _, it := range list {
		na, err := time.Parse(time.RFC3339, it.NotAfter)
		if err != nil {
			continue
		}
		if it.CN == cn && time.Now().Before(na) {
			if revoked, _ := c.isSerialRevoked(it.Serial); revoked {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}
