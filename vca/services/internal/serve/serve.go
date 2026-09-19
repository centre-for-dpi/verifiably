// SPDX-License-Identifier: Apache-2.0

// Package serve runs the HTTP server of a service (ADR-005 decision 6).
// One http.Server on one port serves HTTP/1.1 and HTTP/2 without TLS
// (h2c), so Connect clients can use gRPC and browsers can use JSON. The
// server adds /healthz and /readyz, a request id, W3C trace context
// propagation, JSON access logs with log/slog, and a graceful shutdown.
//
// Healthcheck probes /readyz for the container HEALTHCHECK.
package serve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/internal/serve/trace"
)

// RequestIDHeader carries the request id.
const RequestIDHeader = "X-Request-Id"

// DefaultShutdownTimeout bounds the graceful shutdown.
const DefaultShutdownTimeout = 10 * time.Second

// Options configure Run.
type Options struct {
	// Listen is the address to bind, for example :8080.
	Listen string
	// Handler serves every path that is not a health endpoint.
	Handler http.Handler
	// Ready reports whether the service can take traffic. Nil means yes.
	Ready func() bool
	// ReadyMessage returns the body of a ready response. A service uses
	// it to report a count, for example the number of providers. Nil
	// means the body "ready".
	ReadyMessage func() string
	// Log receives the access log and the lifecycle messages. Nil means
	// slog.Default.
	Log *slog.Logger
	// ShutdownTimeout bounds the graceful shutdown. Zero means
	// DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
	// Listener replaces the TCP listener on Listen. Tests use it.
	Listener net.Listener
}

func (o Options) withDefaults() Options {
	if o.Handler == nil {
		o.Handler = http.NotFoundHandler()
	}
	if o.Ready == nil {
		o.Ready = func() bool { return true }
	}
	if o.ReadyMessage == nil {
		o.ReadyMessage = func() string { return "ready\n" }
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.ShutdownTimeout <= 0 {
		o.ShutdownTimeout = DefaultShutdownTimeout
	}
	return o
}

// Handler returns the full handler of the server: health endpoints, the
// middleware, and opts.Handler. Tests can call it with httptest.
func Handler(opts Options) http.Handler {
	opts = opts.withDefaults()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		anyval.DiscardWrite(w.Write([]byte("ok\n")))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !opts.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			anyval.DiscardWrite(w.Write([]byte("not ready\n")))
			return
		}
		anyval.DiscardWrite(w.Write([]byte(opts.ReadyMessage())))
	})
	mux.Handle("/", opts.Handler)
	return RequestID(trace.Middleware(AccessLog(opts.Log, mux)))
}

// Run serves until ctx ends, then shuts down. It returns nil after a
// clean shutdown.
func Run(ctx context.Context, opts Options) error {
	opts = opts.withDefaults()
	ln := opts.Listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", opts.Listen)
		if err != nil {
			return fmt.Errorf("serve: listen %s: %w", opts.Listen, err)
		}
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:           Handler(opts),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
	}
	opts.Log.Info("listening", "addr", ln.Addr().String())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	opts.Log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("serve: shutdown: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Healthcheck does a GET on /readyz of the server on listen and fails
// when the status is not 200. The container HEALTHCHECK calls it.
func Healthcheck(ctx context.Context, listen string) error {
	url := "http://127.0.0.1" + PortOf(listen) + "/readyz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer func() { anyval.Discard(resp.Body.Close()) }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("serve: %s returned %d", url, resp.StatusCode)
	}
	return nil
}

// PortOf returns the ":port" part of a listen address. An address
// without a port maps to ":8080".
func PortOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 && i < len(listen)-1 {
		return listen[i:]
	}
	return ":8080"
}

type ctxKey struct{}

// RequestIDFrom returns the request id stored by RequestID.
func RequestIDFrom(ctx context.Context) string {
	id := anyval.As[string](ctx.Value(ctxKey{}))
	return id
}

// RequestID keeps a safe incoming X-Request-Id or makes a new one. It
// stores the id in the request context and echoes it in the response.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !safeID(id) {
			id = newID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

// safeID accepts ids of 1 to 128 printable ASCII characters without spaces.
func safeID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

func newID() string {
	b := make([]byte, 12)
	anyval.Must(rand.Read(b))
	return hex.EncodeToString(b)
}

// AccessLog writes one JSON line per request to log.
func AccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		attrs := []any{
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"bytes", rec.bytes, "duration_ms", time.Since(start).Milliseconds(),
			"request_id", RequestIDFrom(r.Context()),
		}
		if tc, ok := trace.FromContext(r.Context()); ok {
			attrs = append(attrs, "trace_id", tc.TraceID, "span_id", tc.SpanID)
		}
		log.Info("request", attrs...)
	})
}

// statusRecorder captures the status and size of a response.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush forwards to the wrapped writer so streaming responses work.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
