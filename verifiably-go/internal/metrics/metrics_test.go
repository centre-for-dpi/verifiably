package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCounter_IncAndReset(t *testing.T) {
	r := newRegistry()
	r.Inc("http_requests_total", "method", "GET", "status", "200")
	r.Inc("http_requests_total", "method", "GET", "status", "200")
	r.Inc("http_requests_total", "method", "POST", "status", "400")

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	if !strings.Contains(out, `http_requests_total{method="GET",status="200"} 2`) {
		t.Errorf("missing GET/200 counter line in:\n%s", out)
	}
	if !strings.Contains(out, `http_requests_total{method="POST",status="400"} 1`) {
		t.Errorf("missing POST/400 counter line in:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE http_requests_total counter") {
		t.Errorf("missing TYPE line in:\n%s", out)
	}
}

func TestCounter_NoLabels(t *testing.T) {
	r := newRegistry()
	r.IncN("process_starts_total", 3)

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "process_starts_total 3") {
		t.Errorf("no-label counter format wrong:\n%s", out)
	}
}

func TestHistogram_BucketCounts(t *testing.T) {
	r := newRegistry()
	r.ObserveDuration("adapter_duration_seconds", 10*time.Millisecond, "op", "issue")
	r.ObserveDuration("adapter_duration_seconds", 200*time.Millisecond, "op", "issue")
	r.ObserveDuration("adapter_duration_seconds", 3*time.Second, "op", "issue")

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	// 10 ms falls in ≤ 0.025 bucket and all coarser ones
	if !strings.Contains(out, `adapter_duration_seconds_bucket{op="issue",le="0.025"} 1`) {
		t.Errorf("0.025 bucket should be 1:\n%s", out)
	}
	// 200 ms falls in ≤ 0.5 bucket
	if !strings.Contains(out, `adapter_duration_seconds_bucket{op="issue",le="0.5"} 2`) {
		t.Errorf("0.5 bucket should be 2:\n%s", out)
	}
	// 3 s only in +Inf
	if !strings.Contains(out, `adapter_duration_seconds_bucket{op="issue",le="+Inf"} 3`) {
		t.Errorf("+Inf bucket should be 3:\n%s", out)
	}
	if !strings.Contains(out, `adapter_duration_seconds_count{op="issue"} 3`) {
		t.Errorf("count should be 3:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE adapter_duration_seconds histogram") {
		t.Errorf("missing histogram TYPE line:\n%s", out)
	}
}

func TestHandler_ContentType(t *testing.T) {
	r := newRegistry()
	r.Inc("test_counter")

	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}
	if rr.Code != 200 {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestHandler_Empty(t *testing.T) {
	r := newRegistry()
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	// Empty registry should produce no output (or just whitespace), not panic.
	if rr.Code != 200 {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// ── Gauge ─────────────────────────────────────────────────────────────────────

func TestGauge_SetAndFormat(t *testing.T) {
	r := newRegistry()
	r.SetGauge("trusted_issuer_days_until_expiry", 45, "did", "did:web:a.gov", "name", "Issuer A")

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE trusted_issuer_days_until_expiry gauge") {
		t.Errorf("missing gauge TYPE line:\n%s", out)
	}
	if !strings.Contains(out, `trusted_issuer_days_until_expiry{did="did:web:a.gov",name="Issuer A"} 45`) {
		t.Errorf("missing gauge value line:\n%s", out)
	}
}

func TestGauge_Update(t *testing.T) {
	r := newRegistry()
	r.SetGauge("endpoint_up", 1, "did", "did:web:a.gov")
	r.SetGauge("endpoint_up", 0, "did", "did:web:a.gov")

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	if !strings.Contains(out, `endpoint_up{did="did:web:a.gov"} 0`) {
		t.Errorf("gauge should reflect latest value (0):\n%s", out)
	}
	if strings.Contains(out, `} 1`) {
		t.Errorf("old gauge value 1 should be gone:\n%s", out)
	}
}

func TestGauge_Delete(t *testing.T) {
	r := newRegistry()
	r.SetGauge("cleanup_gauge", 99, "did", "did:web:gone.gov")
	r.DeleteGauge("cleanup_gauge", "did", "did:web:gone.gov")

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	if strings.Contains(out, "cleanup_gauge") {
		t.Errorf("deleted gauge should not appear in output:\n%s", out)
	}
}

func TestGauge_DeleteNoop(t *testing.T) {
	r := newRegistry()
	// Deleting a gauge that was never set should not panic
	r.DeleteGauge("nonexistent_gauge", "k", "v")
}

func TestGauge_NoLabels(t *testing.T) {
	r := newRegistry()
	r.SetGauge("simple_gauge", 7)

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	if !strings.Contains(out, "simple_gauge 7") {
		t.Errorf("no-label gauge format wrong:\n%s", out)
	}
}

func TestGauge_MultipleEntries(t *testing.T) {
	r := newRegistry()
	r.SetGauge("expiry", 30, "did", "did:web:a.gov")
	r.SetGauge("expiry", 90, "did", "did:web:b.gov")

	var buf strings.Builder
	r.writeTo(&buf)
	out := buf.String()

	// TYPE line should appear exactly once
	count := strings.Count(out, "# TYPE expiry gauge")
	if count != 1 {
		t.Errorf("TYPE line should appear once, got %d:\n%s", count, out)
	}
}

func TestConcurrent_Inc(t *testing.T) {
	r := newRegistry()
	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			r.Inc("concurrent_total", "w", "1")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
	c := r.counter("concurrent_total", []string{"w", "1"})
	if c.val.Load() != 100 {
		t.Errorf("concurrent Inc: got %d, want 100", c.val.Load())
	}
}
