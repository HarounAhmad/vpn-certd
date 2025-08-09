package validate

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"

	"github.com/HarounAhmad/vpn-certd/internal/api"
)

var (
	reCN = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)
)

const (
	maxCSRSizePEM = 64 * 1024
	minPassLen    = 10
	maxPassLen    = 128
)

func CN(s string) error {
	if !reCN.MatchString(s) {
		return errors.New("invalid_cn")
	}
	return nil
}

func Profile(p api.Profile) error {
	switch p {
	case api.ProfileClient, api.ProfileServer:
		return nil
	default:
		return errors.New("invalid_profile")
	}
}

func KeyType(k api.KeyType) error {
	switch k {
	case api.KeyRSA4096, api.KeyEd25519:
		return nil
	default:
		return errors.New("invalid_key_type")
	}
}

func Passphrase(p string) error {
	if len(p) < minPassLen || len(p) > maxPassLen {
		return errors.New("invalid_passphrase_length")
	}
	// very light policy; strengthen later
	if strings.ContainsRune(p, '\n') {
		return errors.New("invalid_passphrase_newline")
	}
	return nil
}

func CSR(pepem string) error {
	if len(pepem) == 0 || len(pepem) > maxCSRSizePEM {
		return errors.New("invalid_csr_size")
	}
	block, _ := pem.Decode([]byte(pepem))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return errors.New("invalid_csr_pem")
	}
	return nil
}

func SubjectCN(subj string) error {
	rdns, err := parseCNOnly(subj)
	if err != nil {
		return err
	}
	return CN(rdns)
}

func parseCNOnly(subj string) (string, error) {
	s := strings.TrimSpace(subj)
	if s == "" {
		return "", nil
	}
	// We don't fully parse DN; tolerate "CN=foo" or "/CN=foo"
	s = strings.TrimPrefix(s, "/")
	parts := strings.Split(s, "/")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "CN") {
			return strings.TrimSpace(kv[1]), nil
		}
	}
	return "", errors.New("invalid_subject_no_cn")
}

var _ = pkix.Name{}
