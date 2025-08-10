package app

import (
	"context"
	"log/slog"
	"regexp"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/api"
	"github.com/HarounAhmad/vpn-certd/internal/pki"
	"github.com/HarounAhmad/vpn-certd/internal/policy"
	"github.com/HarounAhmad/vpn-certd/internal/security"
	"github.com/HarounAhmad/vpn-certd/internal/server/unixjson"
	"github.com/HarounAhmad/vpn-certd/internal/validate"
	"github.com/HarounAhmad/vpn-certd/internal/xerr"
)

type App struct {
	Log       *slog.Logger
	CA        *pki.CA
	Policy    policy.Policy
	cnPattern *regexp.Regexp
	CRLOut    string
}

func New(log *slog.Logger) *App { return &App{Log: log} }

func (a *App) Handler() unixjson.Handler { return a }

func (a *App) Handle(_ context.Context, req api.Request) (api.Response, error) {
	switch req.Op {
	case api.OpHealth:
		return api.Response{Serial: "ok", NotAfter: time.Now().UTC().Format(time.RFC3339)}, nil

	case api.OpGenKeyAndSign:
		if err := validate.CN(req.CN); err != nil {
			return api.Response{}, xerr.Bad("cn")
		}
		if err := a.ensureCN(req.CN); err != nil {
			return api.Response{}, err
		}
		if err := validate.Profile(req.Profile); err != nil {
			return api.Response{}, xerr.Bad("profile")
		}
		if err := validate.KeyType(req.KeyType); err != nil {
			return api.Response{}, xerr.Bad("key_type")
		}
		if err := validate.Passphrase(req.Passphrase); err != nil {
			return api.Response{}, xerr.Bad("passphrase")
		}
		if a.CA == nil {
			return api.Response{}, xerr.InternalErr("ca_not_loaded")
		}
		days := a.Policy.ClientDays
		if req.Profile == api.ProfileServer {
			days = a.Policy.ServerDays
		}
		res, err := pki.GenKeyAndSign(a.CA, req.CN, req.KeyType, req.Profile, days, req.Passphrase)
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		_ = a.CA.AppendIssued(req.CN, string(req.Profile), res.Serial, res.NotAfter.UTC().Format(time.RFC3339), res.CertPEM)
		return api.Response{
			CertPEM:   res.CertPEM,
			KeyPEMEnc: res.KeyPEM,
			NotAfter:  res.NotAfter.UTC().Format(time.RFC3339),
			Serial:    res.Serial,
		}, nil

	case api.OpSign:
		if err := validate.CN(req.CN); err != nil {
			return api.Response{}, xerr.Bad("cn")
		}
		if err := a.ensureCN(req.CN); err != nil {
			return api.Response{}, err
		}
		if err := validate.Profile(req.Profile); err != nil {
			return api.Response{}, xerr.Bad("profile")
		}
		if err := validate.CSR(req.CSRPEM); err != nil {
			return api.Response{}, xerr.Bad("csr_pem")
		}
		if a.CA == nil {
			return api.Response{}, xerr.InternalErr("ca_not_loaded")
		}
		days := a.Policy.ClientDays
		if req.Profile == api.ProfileServer {
			days = a.Policy.ServerDays
		}
		res, err := pki.SignCSR(a.CA, req.CSRPEM, req.Profile, days)
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		_ = a.CA.AppendIssued(req.CN, string(req.Profile), res.Serial, res.NotAfter.UTC().Format(time.RFC3339), res.CertPEM)
		return api.Response{
			CertPEM:  res.CertPEM,
			NotAfter: res.NotAfter.UTC().Format(time.RFC3339),
			Serial:   res.Serial,
		}, nil

	case api.OpRevoke:
		if err := validate.SerialDec(req.Serial); err != nil {
			return api.Response{}, xerr.Bad("serial")
		}
		if err := validate.Reason(req.Reason); err != nil {
			return api.Response{}, xerr.Bad("reason")
		}
		if a.CA == nil {
			return api.Response{}, xerr.InternalErr("ca_not_loaded")
		}
		crl, err := a.CA.RevokeAndWriteCRL(req.Serial, req.Reason)
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		// deploy to OpenVPN path atomically
		if a.CRLOut != "" {
			if err := security.AtomicWrite(a.CRLOut, []byte(crl), 0o644); err != nil {
				a.Log.Warn("crl_deploy_failed", "path", a.CRLOut, "err", err.Error())
			}
		}
		return api.Response{CRLPEM: crl}, nil

	case api.OpGetCRL:
		if a.CA == nil {
			return api.Response{}, xerr.InternalErr("ca_not_loaded")
		}
		crl, err := a.CA.ReadCRL()
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		return api.Response{CRLPEM: crl}, nil

	case api.OpListIssued:
		if a.CA == nil {
			return api.Response{}, xerr.InternalErr("ca_not_loaded")
		}
		list, err := a.CA.ListIssued(200)
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		return api.Response{Issued: list}, nil

	default:
		return api.Response{}, xerr.Bad("unknown_op")
	}
}

func (a *App) ensureCN(cn string) error {
	// policy regex
	if a.cnPattern != nil && !a.cnPattern.MatchString(cn) {
		return xerr.Bad("cn_policy")
	}
	// uniqueness
	if !a.Policy.AllowDuplicateCN {
		exists, err := a.CA.ExistsCNActive(cn)
		if err != nil {
			return xerr.InternalErr(err.Error())
		}
		if exists {
			return xerr.ConflictErr("cn_exists_active")
		}
	}
	return nil
}
