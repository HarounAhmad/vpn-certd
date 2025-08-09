package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/HarounAhmad/vpn-certd/pkg/internal/api"
	"github.com/HarounAhmad/vpn-certd/pkg/internal/constants"
	"github.com/HarounAhmad/vpn-certd/pkg/internal/server/unixjson"
)

type App struct {
	Log *slog.Logger
}

func New(log *slog.Logger) *App {
	return &App{Log: log}
}

func (a *App) Handler() unixjson.Handler {
	return a
}

func (a *App) Handle(ctx context.Context, req api.Request) (api.Response, error) {
	switch req.Op {
	case api.OpHealth:
		return api.Response{Serial: "ok", NotAfter: time.Now().UTC().Format(time.RFC3339)}, nil
	case api.OpSign, api.OpGenKeyAndSign, api.OpRevoke, api.OpGetCRL:
		return api.Response{}, errors.New("not_implemented_step1")
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
