package tracing

// W3C Trace-Context propagation (https://www.w3.org/TR/trace-context/).
//
// traceparent format: 00-<traceID-32hex>-<spanID-16hex>-<flags-2hex>
//
// Extract reads an incoming traceparent and seeds the context with a parent
// span so child spans inherit the correct trace ID and sampled flag.
//
// Inject writes the current span's traceparent into outbound request headers
// so downstream services (CREDEBL, walt.id, Inji) can continue the trace.

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
)

// Extract reads the W3C traceparent (and tracestate) headers from r,
// places a remote-parent placeholder in the returned context, and returns
// it. If there is no valid traceparent, ctx is returned unchanged.
//
// The placeholder span is never exported — it exists only to seed the
// trace ID and sampled flag into the first local span started in the request.
func Extract(ctx context.Context, r *http.Request) context.Context {
	tp := r.Header.Get("traceparent")
	if tp == "" {
		return ctx
	}
	sc, ok := parseTraceparent(tp)
	if !ok {
		return ctx
	}
	// Remote parent: mark as Sampled=true only when the upstream set the
	// sampled flag. We always respect the upstream decision so traces aren't
	// split at the boundary.
	placeholder := &Span{sc: sc}
	return context.WithValue(ctx, contextKey{}, placeholder)
}

// Inject writes the current span's W3C traceparent header into h.
// Per the W3C Trace Context spec, the header is propagated even for unsampled
// spans (flags=00) so downstream services share the same trace_id for
// correlation. Only the sampled flag differs: 01 when sampled, 00 otherwise.
// No-ops when ctx carries no valid span context.
func Inject(ctx context.Context, h http.Header) {
	s := SpanFromContext(ctx)
	if s == nil || !s.sc.IsValid() {
		return
	}
	flags := "00"
	if s.sc.Sampled {
		flags = "01"
	}
	h.Set("traceparent", "00-"+s.sc.TraceIDHex()+"-"+s.sc.SpanIDHex()+"-"+flags)
}

// parseTraceparent parses the version-00 traceparent wire format.
// Returns (SpanContext, true) on success, (zero, false) on any parse error.
func parseTraceparent(s string) (SpanContext, bool) {
	// "00-<32hex>-<16hex>-<2hex>"
	parts := strings.Split(s, "-")
	if len(parts) != 4 || parts[0] != "00" {
		return SpanContext{}, false
	}
	traceBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(traceBytes) != 16 {
		return SpanContext{}, false
	}
	spanBytes, err := hex.DecodeString(parts[2])
	if err != nil || len(spanBytes) != 8 {
		return SpanContext{}, false
	}
	flags, err := hex.DecodeString(parts[3])
	if err != nil || len(flags) != 1 {
		return SpanContext{}, false
	}
	var sc SpanContext
	copy(sc.TraceID[:], traceBytes)
	copy(sc.SpanID[:], spanBytes)
	sc.Sampled = flags[0]&0x01 != 0
	return sc, true
}
