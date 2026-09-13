// SPDX-License-Identifier: Apache-2.0

// Package serve runs the HTTP server of the service. It serves HTTP/1.1
// and HTTP/2 without TLS (h2c) on one port, so Connect clients can use
// gRPC. It adds /healthz and /readyz. It is a minimal local stand-in for
// the shared services/internal/serve package. The orchestrator replaces
// it later.
package serve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ShutdownTimeout bounds the graceful shutdown.
const ShutdownTimeout = 10 * time.Second

// Server wraps http.Server with health endpoints.
type Server struct {
	http  *http.Server
	ready func() bool
}

// New builds a server on listen with mux. ready reports whether the
// service can take traffic. Nil means always ready.
func New(listen string, mux *http.ServeMux, ready func() bool) *Server {
	if ready == nil {
		ready = func() bool { return true }
	}
	s := &Server{ready: ready}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !s.ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	s.http = &http.Server{
		Addr:              listen,
		Handler:           mux,
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Run serves until ctx ends, then shuts down.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return fmt.Errorf("serve: listen %s: %w", s.http.Addr, err)
	}
	return s.serve(ctx, ln)
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- s.http.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	if err := s.http.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("serve: shutdown: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Healthcheck does a GET on url and fails when the status is not 200.
// The container HEALTHCHECK calls it with the /readyz URL.
func Healthcheck(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("serve: %s returned %d", url, resp.StatusCode)
	}
	return nil
}
