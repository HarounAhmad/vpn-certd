package unixjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/HarounAhmad/vpn-certd/pkg/internal/api"
	"github.com/HarounAhmad/vpn-certd/pkg/internal/constants"
)

type Handler interface {
	Handle(ctx context.Context, req api.Request) (api.Response, error)
}

type Server struct {
	Socket string
	Log    *slog.Logger
	H      Handler
	l      net.Listener
}

func (s *Server) Start(ctx context.Context) error {
	if s.Socket == "" || s.H == nil || s.Log == nil {
		return errors.New("server not configured")
	}
	_ = os.Remove(s.Socket)
	l, err := net.Listen("unix", s.Socket)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(s.Socket, constants.SocketPerm0600); err != nil {
		_ = l.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}
	s.l = l
	s.Log.Info("listening", "socket", s.Socket)
	go s.acceptLoop()
	go func() {
		<-ctx.Done()
		_ = s.l.Close()
	}()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.l.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(constants.ReadWriteDeadline))

	dec := json.NewDecoder(c)
	dec.DisallowUnknownFields()
	var req api.Request
	if err := dec.Decode(&req); err != nil {
		s.respondErr(c, "bad_request: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), constants.ReadWriteDeadline)
	defer cancel()

	resp, err := s.H.Handle(ctx, req)
	if err != nil {
		resp.Error = err.Error()
	}
	enc := json.NewEncoder(c)
	_ = enc.Encode(&resp)
}

func (s *Server) respondErr(c net.Conn, msg string) {
	_ = json.NewEncoder(c).Encode(api.Response{Error: msg})
}
