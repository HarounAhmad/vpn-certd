package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/api"
	"github.com/HarounAhmad/vpn-certd/internal/constants"
	"github.com/HarounAhmad/vpn-certd/internal/pki"
	"github.com/HarounAhmad/vpn-certd/internal/server/unixjson"
	"github.com/HarounAhmad/vpn-certd/internal/validate"
	"github.com/HarounAhmad/vpn-certd/internal/xerr"
)

type App struct {
	Log *slog.Logger
	CA  *pki.CA
}

func New(log *slog.Logger) *App {
	return &App{Log: log}
}

func (a *App) Handler() unixjson.Handler { return a }

const defaultClientDays = 180
const defaultServerDays = 365

func (a *App) Handle(ctx context.Context, req api.Request) (api.Response, error) {
	switch req.Op {
	case api.OpHealth:
		return api.Response{Serial: "ok", NotAfter: time.Now().UTC().Format(time.RFC3339)}, nil

	case api.OpGenKeyAndSign:
		if err := validate.CN(req.CN); err != nil {
			return api.Response{}, xerr.Bad("cn")
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
		days := defaultClientDays
		if req.Profile == api.ProfileServer {
			days = defaultServerDays
		}
		res, err := pki.GenKeyAndSign(a.CA, req.CN, req.KeyType, req.Profile, days, req.Passphrase)
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		return api.Response{
			CertPEM:   res.CertPEM,
			KeyPEMEnc: res.KeyPEM,
			NotAfter:  res.NotAfter.UTC().Format(time.RFC3339),
		}, nil

	case api.OpSign:
		if err := validate.CN(req.CN); err != nil {
			return api.Response{}, xerr.Bad("cn")
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
		days := defaultClientDays
		if req.Profile == api.ProfileServer {
			days = defaultServerDays
		}
		res, err := pki.SignCSR(a.CA, req.CSRPEM, req.Profile, days)
		if err != nil {
			return api.Response{}, xerr.InternalErr(err.Error())
		}
		return api.Response{
			CertPEM:  res.CertPEM,
			NotAfter: res.NotAfter.UTC().Format(time.RFC3339),
		}, nil

	case api.OpRevoke:
		// Implement in next step
		return api.Response{}, xerr.NotImplemented("revoke")

	case api.OpGetCRL:
		// Implement in next step
		return api.Response{}, xerr.NotImplemented("get_crl")

	default:
		return api.Response{}, xerr.Bad("unknown_op")
	}
}

func (a *App) StartServer(ctx context.Context, socket string) error {
	s := &unixjson.Server{
		Socket: socket,
		Log:    a.Log.With("component", constants.AppName),
		H:      a.Handler(),
	}
	return s.Start(ctx)
}
