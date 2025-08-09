package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/api"
)

type SignResult struct {
	CertPEM  string
	KeyPEM   string
	NotAfter time.Time
}

func BuildClientTemplate(cn string, days int) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
	}
}

func BuildServerTemplate(cn string, days int, altNames []string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
	}
}

func GenKeyAndSign(ca *CA, cn string, kt api.KeyType, profile api.Profile, days int, passphrase string) (*SignResult, error) {
	if ca == nil {
		return nil, errors.New("nil CA")
	}
	switch profile {
	case api.ProfileClient, api.ProfileServer:
	default:
		return nil, errors.New("invalid profile")
	}

	var pub any
	var keyDER []byte

	switch kt {
	case api.KeyRSA4096:
		rk, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("rsa gen: %w", err)
		}
		pub = &rk.PublicKey
		keyDER, err = x509.MarshalPKCS8PrivateKey(rk)
		if err != nil {
			return nil, fmt.Errorf("marshal pkcs8: %w", err)
		}
	case api.KeyEd25519:
		_, ek, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ed25519 gen: %w", err)
		}
		pub = ek.Public().(ed25519.PublicKey)
		keyDER, err = x509.MarshalPKCS8PrivateKey(ek)
		if err != nil {
			return nil, fmt.Errorf("marshal pkcs8: %w", err)
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	var tpl *x509.Certificate
	switch profile {
	case api.ProfileClient:
		tpl = BuildClientTemplate(cn, days)
	case api.ProfileServer:
		tpl = BuildServerTemplate(cn, days, nil)
	}

	certPEM, _, err := ca.SignCert(tpl, pub)
	if err != nil {
		return nil, err
	}

	if passphrase == "" {
		return nil, errors.New("empty passphrase")
	}
	enc, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyDER, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(enc)

	return &SignResult{
		CertPEM:  string(certPEM),
		KeyPEM:   string(keyPEM),
		NotAfter: tpl.NotAfter,
	}, nil
}

func SignCSR(ca *CA, csrPEM string, profile api.Profile, days int) (*SignResult, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("bad csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr sig: %w", err)
	}

	var tpl *x509.Certificate
	switch profile {
	case api.ProfileClient:
		tpl = BuildClientTemplate(csr.Subject.CommonName, days)
	case api.ProfileServer:
		tpl = BuildServerTemplate(csr.Subject.CommonName, days, nil)
	default:
		return nil, errors.New("invalid profile")
	}

	certPEM, _, err := ca.SignCert(tpl, csr.PublicKey)
	if err != nil {
		return nil, err
	}

	return &SignResult{
		CertPEM:  string(certPEM),
		KeyPEM:   "",
		NotAfter: tpl.NotAfter,
	}, nil
}

func pubOf(priv any) (any, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey), nil
	default:
		return nil, errors.New("unsupported key")
	}
}
