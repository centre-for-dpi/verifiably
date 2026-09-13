// SPDX-License-Identifier: Apache-2.0

// Package trace propagates the W3C Trace Context traceparent header
// (https://www.w3.org/TR/trace-context/). A request that carries a valid
// traceparent keeps its trace id and gets a new span id. A request
// without one starts a new trace. The handler puts the context in the
// request context and echoes the traceparent in the response, so a
// caller can find the log lines of its request.
//
// The package is pure apart from the random ids. It has no exporter.
// An OpenTelemetry exporter is a follow-up that reads the same context.
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Header is the name of the trace context header.
const Header = "traceparent"

// Context is a parsed traceparent value.
type Context struct {
	// TraceID is 16 bytes in hex.
	TraceID string
	// SpanID is 8 bytes in hex.
	SpanID string
	// ParentID is the span id of the caller. Empty on a new trace.
	ParentID string
	// Sampled is the sampled flag of the caller.
	Sampled bool
}

// String returns the traceparent header value of the context.
func (c Context) String() string {
	flags := "00"
	if c.Sampled {
		flags = "01"
	}
	return "00-" + c.TraceID + "-" + c.SpanID + "-" + flags
}

// Parse reads a traceparent header value (version 00).
func Parse(value string) (Context, error) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 {
		return Context{}, fmt.Errorf("trace: traceparent needs 4 fields, got %d", len(parts))
	}
	if parts[0] != "00" {
		return Context{}, fmt.Errorf("trace: unsupported traceparent version %q", parts[0])
	}
	if !isHex(parts[1], 32) || parts[1] == strings.Repeat("0", 32) {
		return Context{}, fmt.Errorf("trace: bad trace id %q", parts[1])
	}
	if !isHex(parts[2], 16) || parts[2] == strings.Repeat("0", 16) {
		return Context{}, fmt.Errorf("trace: bad span id %q", parts[2])
	}
	if !isHex(parts[3], 2) {
		return Context{}, fmt.Errorf("trace: bad flags %q", parts[3])
	}
	flags, _ := hex.DecodeString(parts[3])
	return Context{TraceID: strings.ToLower(parts[1]), SpanID: strings.ToLower(parts[2]), Sampled: flags[0]&1 == 1}, nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// New starts a new trace with a random trace id and span id.
func New() Context {
	return Context{TraceID: randomHex(16), SpanID: randomHex(8)}
}

// Child returns a context in the same trace with a new span id.
func (c Context) Child() Context {
	return Context{TraceID: c.TraceID, SpanID: randomHex(8), ParentID: c.SpanID, Sampled: c.Sampled}
}

func randomHex(n int) string {
	b := make([]byte, n)
	// crypto/rand never fails on the supported platforms (Go 1.24 and later).
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type ctxKey struct{}

// WithContext stores c in ctx.
func WithContext(ctx context.Context, c Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext returns the trace context of ctx. ok is false when none
// is stored.
func FromContext(ctx context.Context) (c Context, ok bool) {
	c, ok = ctx.Value(ctxKey{}).(Context)
	return c, ok
}

// Middleware reads or starts the trace context, stores it in the request,
// and echoes it in the response header.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Parse(r.Header.Get(Header))
		if err != nil {
			c = New()
		} else {
			c = c.Child()
		}
		w.Header().Set(Header, c.String())
		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), c)))
	})
}

// Inject sets the traceparent header of an outgoing request from ctx.
// A request without a trace context is left as it is.
func Inject(ctx context.Context, h http.Header) {
	if c, ok := FromContext(ctx); ok {
		h.Set(Header, c.String())
	}
}
