// Package tracing is a stdlib-only distributed tracing implementation.
//
// Design goals:
//   - Zero external dependencies (mirrors internal/metrics philosophy).
//   - W3C Trace-Context compliant: parses and emits traceparent headers so
//     spans from verifiably-go correlate with upstream API gateways and
//     downstream DPG backends that also honor the spec.
//   - Two export paths: SlogExporter (structured log line per span, works with
//     any log aggregator) and OTLPJSONExporter (HTTP POST to Grafana Tempo /
//     Jaeger; no protobuf — OTLP defines a JSON encoding).
//   - Drop-in replaceable: the global Tracer API surface mirrors the real
//     go.opentelemetry.io/otel API so migrating later is a 1:1 import swap.
//
// Env vars (read in cmd/server/main.go, not here):
//
//	VERIFIABLY_OTEL_ENDPOINT      OTLP/HTTP base URL, e.g. http://tempo:4318
//	VERIFIABLY_OTEL_SAMPLE_RATE   float 0.0-1.0 (default 1.0)
//	VERIFIABLY_OTEL_SERVICE_NAME  default "verifiably-go"
package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// contextKey is the private key type for storing a Span in a context.
type contextKey struct{}

// StatusCode classifies whether a span completed successfully.
type StatusCode int

const (
	StatusUnset StatusCode = 0
	StatusOK    StatusCode = 1
	StatusError StatusCode = 2
)

// SpanContext carries the immutable identity of a span.
type SpanContext struct {
	TraceID [16]byte
	SpanID  [8]byte
	Sampled bool
}

// TraceIDHex returns the 32-char lowercase hex encoding of the trace ID.
func (sc SpanContext) TraceIDHex() string { return hex.EncodeToString(sc.TraceID[:]) }

// SpanIDHex returns the 16-char lowercase hex encoding of the span ID.
func (sc SpanContext) SpanIDHex() string { return hex.EncodeToString(sc.SpanID[:]) }

// IsValid reports whether the span context carries a non-zero trace ID.
func (sc SpanContext) IsValid() bool { return sc.TraceID != [16]byte{} }

// Span records the timing and metadata of one unit of work.
// All methods are nil-safe so callers can ignore a nil span without panicking.
type Span struct {
	tracer    *Tracer
	sc        SpanContext
	parentID  [8]byte // zero when root
	name      string
	start     time.Time
	attrs     map[string]string
	status    StatusCode
	statusMsg string
	ended     bool
}

// SetAttr records a key=value attribute. Returns s for chaining.
func (s *Span) SetAttr(key, value string) *Span {
	if s == nil || !s.sc.Sampled {
		return s
	}
	if s.attrs == nil {
		s.attrs = make(map[string]string, 4)
	}
	s.attrs[key] = value
	return s
}

// RecordError marks the span as errored and stores the message.
func (s *Span) RecordError(err error) *Span {
	if s == nil || err == nil || !s.sc.Sampled {
		return s
	}
	s.status = StatusError
	s.statusMsg = err.Error()
	return s
}

// SetStatus overrides the span status.
func (s *Span) SetStatus(code StatusCode, msg string) *Span {
	if s == nil || !s.sc.Sampled {
		return s
	}
	s.status = code
	s.statusMsg = msg
	return s
}

// SpanCtx returns the span's immutable identity.
func (s *Span) SpanCtx() SpanContext {
	if s == nil {
		return SpanContext{}
	}
	return s.sc
}

// ParentSpanIDHex returns the 16-char hex parent span ID, or "" for root spans.
func (s *Span) ParentSpanIDHex() string {
	if s == nil || s.parentID == ([8]byte{}) {
		return ""
	}
	return hex.EncodeToString(s.parentID[:])
}

// End finalizes the span and hands it to the exporter. Idempotent.
func (s *Span) End() {
	if s == nil || !s.sc.Sampled || s.ended {
		return
	}
	s.ended = true
	s.tracer.export(s, time.Now())
}

// sampler makes head-based sampling decisions using the trace ID as the
// sampling key. This ensures all spans in a trace agree on the decision
// even when the tracer is re-instantiated (deterministic on trace ID).
type sampler struct {
	rate float64
}

func newSampler(rate float64) sampler {
	switch {
	case rate <= 0:
		return sampler{0}
	case rate >= 1:
		return sampler{1}
	default:
		return sampler{rate}
	}
}

// shouldSample returns true when the first 8 bytes of traceID, interpreted
// as a big-endian uint64, fall below (rate * MaxUint64).
func (s sampler) shouldSample(traceID [16]byte) bool {
	if s.rate >= 1 {
		return true
	}
	if s.rate <= 0 {
		return false
	}
	var n uint64
	for i := 0; i < 8; i++ {
		n = n<<8 | uint64(traceID[i])
	}
	// Avoid overflow: if rate==1 this path is unreachable; multiply is safe.
	threshold := uint64(s.rate * float64(^uint64(0)))
	return n < threshold
}

// Tracer creates and exports spans.
type Tracer struct {
	serviceName string
	sampler     sampler
	exporter    SpanExporter
}

// NewTracer constructs a Tracer. Use SetGlobal to install it process-wide.
func NewTracer(serviceName string, sampleRate float64, exp SpanExporter) *Tracer {
	if exp == nil {
		exp = NoopExporter{}
	}
	return &Tracer{
		serviceName: serviceName,
		sampler:     newSampler(sampleRate),
		exporter:    exp,
	}
}

// Start creates a new span and returns a derived context.
// If ctx already carries a span, the new span is a child of it.
func (t *Tracer) Start(ctx context.Context, name string) (context.Context, *Span) {
	parent := SpanFromContext(ctx)

	var sc SpanContext
	var parentID [8]byte

	if parent != nil && parent.sc.IsValid() {
		// Child span: inherit the trace ID and sample decision from parent.
		sc.TraceID = parent.sc.TraceID
		parentID = parent.sc.SpanID
		sc.Sampled = parent.sc.Sampled
	} else {
		// Root span: generate a fresh trace ID and make the sample decision.
		if _, err := rand.Read(sc.TraceID[:]); err != nil {
			// crypto/rand failure is effectively impossible; ignore.
			return ctx, &Span{}
		}
		sc.Sampled = t.sampler.shouldSample(sc.TraceID)
	}

	if sc.Sampled {
		if _, err := rand.Read(sc.SpanID[:]); err != nil {
			return ctx, &Span{}
		}
	}

	span := &Span{
		tracer:   t,
		sc:       sc,
		parentID: parentID,
		name:     name,
		start:    time.Now(),
	}
	return context.WithValue(ctx, contextKey{}, span), span
}

// SpanFromContext retrieves the current span from ctx. Returns nil if none.
func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(contextKey{}).(*Span)
	return s
}

// Shutdown drains the exporter (if it supports draining). Call on graceful
// shutdown to ensure all buffered spans are flushed before the process exits.
func (t *Tracer) Shutdown(ctx context.Context) error {
	type shutdowner interface {
		Shutdown(context.Context) error
	}
	if s, ok := t.exporter.(shutdowner); ok {
		return s.Shutdown(ctx)
	}
	return nil
}

func (t *Tracer) export(s *Span, endTime time.Time) {
	if t.exporter == nil {
		return
	}
	t.exporter.ExportSpan(ExportedSpan{
		ServiceName: t.serviceName,
		Span:        s,
		EndTime:     endTime,
	})
}
