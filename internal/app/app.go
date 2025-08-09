package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/HarounAhmad/vpn-certd/internal/api"
	"github.com/HarounAhmad/vpn-certd/internal/constants"
	"github.com/HarounAhmad/vpn-certd/internal/server/unixjson"
	"github.com/HarounAhmad/vpn-certd/internal/validate"
	"github.com/HarounAhmad/vpn-certd/internal/xerr"
)

type App struct {
	Log *slog.Logger
}

func New(log *slog.Logger) *App {
	return &App{Log: log}
}

func (a *App) Handler() unixjson.Handler { return a }

func (a *App) Handle(ctx context.Context, req api.Request) (api.Response, error) {
	switch req.Op {
	case api.OpHealth:
		return api.Response{Serial: "ok", NotAfter: time.Now().UTC().Format(time.RFC3339)}, nil

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
		return api.Response{}, xerr.NotImplemented("sign")

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
		return api.Response{}, xerr.NotImplemented("genkey_and_sign")

	case api.OpRevoke:
		if req.Serial == "" {
			return api.Response{}, xerr.Bad("serial")
		}
		return api.Response{}, xerr.NotImplemented("revoke")

	case api.OpGetCRL:
		return api.Response{}, xerr.NotImplemented("get_crl")

	default:
		return api.Response{}, errors.New("unknown_op")
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
