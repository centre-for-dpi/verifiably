package tracing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ExportedSpan carries everything an exporter needs about a finished span.
type ExportedSpan struct {
	ServiceName string
	Span        *Span
	EndTime     time.Time
}

// SpanExporter receives finished spans from the Tracer.
type SpanExporter interface {
	ExportSpan(ExportedSpan)
}

// NoopExporter silently discards all spans. Default when tracing is disabled.
type NoopExporter struct{}

func (NoopExporter) ExportSpan(ExportedSpan) {}

// CombinedExporter fans a span out to multiple exporters in sequence.
// Use when you want both slog lines AND OTLP export.
type CombinedExporter []SpanExporter

func (c CombinedExporter) ExportSpan(es ExportedSpan) {
	for _, e := range c {
		e.ExportSpan(es)
	}
}

// SlogExporter writes one structured slog.Info line per finished span.
//
// The emitted fields are understood by Grafana Loki's trace-to-log linking:
// a Loki datasource with a "Derived Fields" rule matching `trace_id` can
// open the trace directly in Tempo without a separate OTLP export path.
//
// Example log line (JSON handler):
//
//	{"level":"INFO","msg":"span","trace_id":"a3f2...","span_id":"c1d2...",
//	 "name":"http.server","duration_ms":42.3,"http.method":"GET",...}
type SlogExporter struct{}

func (SlogExporter) ExportSpan(es ExportedSpan) {
	s := es.Span
	dur := es.EndTime.Sub(s.start)

	args := []any{
		"trace_id", s.sc.TraceIDHex(),
		"span_id", s.sc.SpanIDHex(),
		"name", s.name,
		"duration_ms", dur.Seconds() * 1000,
	}
	if pid := s.ParentSpanIDHex(); pid != "" {
		args = append(args, "parent_span_id", pid)
	}
	if es.ServiceName != "" {
		args = append(args, "service", es.ServiceName)
	}
	for k, v := range s.attrs {
		args = append(args, k, v)
	}
	if s.status == StatusError {
		args = append(args, "error", s.statusMsg)
		slog.Error("span", args...)
		return
	}
	slog.Info("span", args...)
}

// ──────────────────────────────────────────────────────────────────────────────
// OTLPJSONExporter
// ──────────────────────────────────────────────────────────────────────────────

// OTLPJSONExporter batches finished spans and ships them to an OTLP/HTTP
// collector using the JSON encoding (no protobuf required).
//
// Compatible with Grafana Tempo (≥ v1.5), Jaeger (≥ v1.35), and the
// OpenTelemetry Collector.  Configure the endpoint as:
//
//	VERIFIABLY_OTEL_ENDPOINT=http://tempo:4318
//
// The exporter posts to <endpoint>/v1/traces.  Spans are batched in groups
// of up to 100 or flushed every 5 s, whichever comes first.  If the export
// channel is full (> 256 pending), new spans are dropped — tracing must
// never block the hot path.
type OTLPJSONExporter struct {
	endpoint    string
	client      *http.Client
	ch          chan ExportedSpan
	wg          sync.WaitGroup
	shutdownOnce sync.Once
}

// NewOTLPExporter creates and starts an OTLPJSONExporter.
// endpoint is the OTLP/HTTP base URL (no trailing slash), e.g. "http://tempo:4318".
func NewOTLPExporter(endpoint string) *OTLPJSONExporter {
	e := &OTLPJSONExporter{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: 5 * time.Second},
		ch:       make(chan ExportedSpan, 256),
	}
	e.wg.Add(1)
	go e.run()
	return e
}

// ExportSpan enqueues es for batch export. Drops the span if the buffer is full.
func (e *OTLPJSONExporter) ExportSpan(es ExportedSpan) {
	select {
	case e.ch <- es:
	default:
		// Drop rather than block the caller.
	}
}

// Shutdown closes the export channel, waits for the batch goroutine to drain,
// and returns when all buffered spans have been sent or ctx is cancelled.
// Safe to call multiple times; only the first call closes the channel.
func (e *OTLPJSONExporter) Shutdown(ctx context.Context) error {
	e.shutdownOnce.Do(func() { close(e.ch) })
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *OTLPJSONExporter) run() {
	defer e.wg.Done()
	const maxBatch = 100
	const flushEvery = 5 * time.Second

	batch := make([]ExportedSpan, 0, maxBatch)
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		e.send(batch)
		batch = batch[:0]
	}

	for {
		select {
		case es, ok := <-e.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, es)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// ── OTLP JSON wire types ──────────────────────────────────────────────────────

type otlpPayload struct {
	ResourceSpans []otlpResourceSpan `json:"resourceSpans"`
}

type otlpResourceSpan struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpAttr `json:"attributes"`
}

type otlpScopeSpan struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpSpan struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId,omitempty"`
	Name              string     `json:"name"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []otlpAttr `json:"attributes,omitempty"`
	Status            otlpStatus `json:"status"`
}

type otlpAttr struct {
	Key   string        `json:"key"`
	Value otlpAttrValue `json:"value"`
}

type otlpAttrValue struct {
	StringValue string `json:"stringValue"`
}

type otlpStatus struct {
	Code    int    `json:"code"` // 0=unset 1=ok 2=error  (OTLP StatusCode enum)
	Message string `json:"message,omitempty"`
}

func (e *OTLPJSONExporter) send(batch []ExportedSpan) {
	if len(batch) == 0 {
		return
	}

	// Group by service — single resource span per unique service name.
	type group struct {
		service string
		spans   []otlpSpan
	}
	byService := make(map[string]*group)

	for _, es := range batch {
		svc := es.ServiceName
		if svc == "" {
			svc = "verifiably-go"
		}
		s := es.Span
		os := otlpSpan{
			TraceID:           s.sc.TraceIDHex(),
			SpanID:            s.sc.SpanIDHex(),
			ParentSpanID:      s.ParentSpanIDHex(),
			Name:              s.name,
			StartTimeUnixNano: fmt.Sprintf("%d", s.start.UnixNano()),
			EndTimeUnixNano:   fmt.Sprintf("%d", es.EndTime.UnixNano()),
			Status:            otlpStatus{Code: int(s.status), Message: s.statusMsg},
		}
		for k, v := range s.attrs {
			os.Attributes = append(os.Attributes, otlpAttr{
				Key:   k,
				Value: otlpAttrValue{StringValue: v},
			})
		}
		if g, ok := byService[svc]; ok {
			g.spans = append(g.spans, os)
		} else {
			byService[svc] = &group{service: svc, spans: []otlpSpan{os}}
		}
	}

	rspans := make([]otlpResourceSpan, 0, len(byService))
	for svc, g := range byService {
		rspans = append(rspans, otlpResourceSpan{
			Resource: otlpResource{
				Attributes: []otlpAttr{
					{Key: "service.name", Value: otlpAttrValue{StringValue: svc}},
				},
			},
			ScopeSpans: []otlpScopeSpan{{
				Scope: otlpScope{Name: "verifiably-go/tracing", Version: "1.0"},
				Spans: g.spans,
			}},
		})
	}

	b, err := json.Marshal(otlpPayload{ResourceSpans: rspans})
	if err != nil {
		slog.Error("tracing: marshal OTLP payload", "err", err)
		return
	}

	resp, err := e.client.Post(e.endpoint+"/v1/traces", "application/json", bytes.NewReader(b))
	if err != nil {
		slog.Error("tracing: OTLP export failed", "endpoint", e.endpoint, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Error("tracing: OTLP collector rejected batch",
			"status", resp.StatusCode,
			"spans", len(batch))
	}
}
