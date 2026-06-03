package tracing

import (
	"fmt"
	"net/http"
)

// Middleware returns an http.Handler middleware that wraps every request in
// a server-side span named "http.server".
//
// Behaviour:
//   - Calls Extract to inherit an upstream trace (e.g. from an API gateway
//     or Caddy that honours W3C Trace-Context).
//   - Starts the span BEFORE calling next, so the duration covers the full
//     handler time including template rendering.
//   - Records method, path, scheme, matched route pattern, and status code.
//   - Marks the span as StatusError when the response status ≥ 500.
//
// Usage in main.go:
//
//	mux := http.NewServeMux()
//	// ... register routes ...
//	handler := tracing.Middleware(tracing.Global())(mux)
func Middleware(t *Tracer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Inherit any upstream trace context before starting our span.
			ctx := Extract(r.Context(), r)
			ctx, span := t.Start(ctx, "http.server")

			span.SetAttr("http.method", r.Method)
			span.SetAttr("http.url", r.URL.Path)
			span.SetAttr("http.scheme", requestScheme(r))
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				span.SetAttr("net.peer.ip", xff)
			}

			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r.WithContext(ctx))

			span.SetAttr("http.status_code", fmt.Sprintf("%d", rw.status))
			// r.Pattern is set by net/http ServeMux after ServeHTTP returns
			// only on Go 1.22+. It gives the matched pattern (e.g.
			// "POST /api/v1/credentials/issue") rather than the raw URL.
			if r.Pattern != "" {
				span.SetAttr("http.route", r.Pattern)
			}
			if rw.status >= 500 {
				span.SetStatus(StatusError, fmt.Sprintf("HTTP %d", rw.status))
			}
			span.End()
		})
	}
}

// statusRecorder wraps an http.ResponseWriter and captures the written status
// code so the tracing middleware can record it as an attribute.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *statusRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		return fwd
	}
	return "http"
}
