package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/verifiably/verifiably-go/internal/metrics"
)

// isolateMetricsDefault swaps the process-global metrics.Default for a fresh,
// empty registry for the duration of the test and restores the original in
// Cleanup, so counters recorded here neither leak into nor depend on other
// tests. metrics exports no constructor and the registry type is unexported,
// so the maps are seeded through reflect/unsafe (test-only; no production
// change per plan §4).
func isolateMetricsDefault(t *testing.T) {
	t.Helper()
	old := metrics.Default
	fresh := reflect.New(reflect.TypeOf(old).Elem())
	for _, name := range []string{"ctrs", "hist", "gauges"} {
		f := fresh.Elem().FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("metrics registry has no field %q", name)
		}
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.MakeMap(f.Type()))
	}
	reflect.ValueOf(&metrics.Default).Elem().Set(fresh)
	t.Cleanup(func() { metrics.Default = old })
}

// metricsPromServer fakes the Prometheus instant-query API. respond maps a
// PromQL substring to the JSON body; unmatched queries get an empty vector.
func metricsPromServer(t *testing.T, respond map[string]string, status int) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/api/v1/query" {
			http.Error(w, "wrong path", 404)
			return
		}
		q := r.URL.Query().Get("query")
		for k, body := range respond {
			if strings.Contains(q, k) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[]}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestPromQuery(t *testing.T) {
	t.Run("parses vector results", func(t *testing.T) {
		srv, _ := metricsPromServer(t, map[string]string{
			"credential_issued_total": `{"status":"success","data":{"result":[{"metric":{"dpg":"a","status":"ok"},"value":[1700000000,"3"]},{"metric":{"dpg":"b"},"value":[1700000000,"not-a-number"]}]}}`,
		}, 200)
		vs, err := promQuery(context.Background(), srv.URL, "sum(credential_issued_total)")
		if err != nil || len(vs) != 2 || vs[0].Value != 3 || vs[0].Metric["dpg"] != "a" || vs[1].Value != 0 {
			t.Fatalf("vs=%+v err=%v", vs, err)
		}
	})
	t.Run("non-success status", func(t *testing.T) {
		srv, _ := metricsPromServer(t, map[string]string{"x": `{"status":"error","data":{"result":[]}}`}, 200)
		if _, err := promQuery(context.Background(), srv.URL, "x"); err == nil || !strings.Contains(err.Error(), "prometheus status: error") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("decode error", func(t *testing.T) {
		srv, _ := metricsPromServer(t, map[string]string{"x": `{not json`}, 200)
		if _, err := promQuery(context.Background(), srv.URL, "x"); err == nil {
			t.Fatal("expected decode error")
		}
	})
	t.Run("connection error", func(t *testing.T) {
		if _, err := promQuery(context.Background(), "http://127.0.0.1:1", "x"); err == nil {
			t.Fatal("expected dial error")
		}
	})
	t.Run("bad URL", func(t *testing.T) {
		if _, err := promQuery(context.Background(), "http://bad host", "x"); err == nil {
			t.Fatal("expected request-build error")
		}
	})
}

func TestBuildMetricsFromPrometheus(t *testing.T) {
	full := map[string]string{
		"credential_issued_total":        `{"status":"success","data":{"result":[{"metric":{"dpg":"walt","schema":"Person","status":"ok"},"value":[0,"4"]},{"metric":{"dpg":"walt","schema":"Person","status":"error"},"value":[0,"1"]}]}}`,
		"verification_requested_total":   `{"status":"success","data":{"result":[{"metric":{"dpg":"walt","schema":"Person"},"value":[0,"2"]}]}}`,
		"verification_completed_total":   `{"status":"success","data":{"result":[{"metric":{"dpg":"walt","schema":"Person"},"value":[0,"1"]}]}}`,
		"adapter_duration_seconds_sum":   `{"status":"success","data":{"result":[{"metric":{"dpg":"walt","op":"issue"},"value":[0,"0.5"]},{"metric":{"dpg":"walt","op":"verify"},"value":[0,"1"]}]}}`,
		"adapter_duration_seconds_count": `{"status":"success","data":{"result":[{"metric":{"dpg":"walt","op":"issue"},"value":[0,"5"]},{"metric":{"dpg":"walt","op":"verify"},"value":[0,"2"]}]}}`,
	}
	srv, calls := metricsPromServer(t, full, 200)
	body, err := buildMetricsFromPrometheus(context.Background(), srv.URL)
	if err != nil || *calls != 5 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
	if body.CredIssuedOK != 4 || body.CredIssuedError != 1 || body.VerifRequested != 2 || body.VerifCompleted != 1 {
		t.Fatalf("totals = %+v", body)
	}
	if body.IssueLatency.AvgMS != "100.0 ms" || body.IssueLatency.Calls != 5 || body.VerifyLatency.AvgMS != "500.0 ms" {
		t.Fatalf("latency = %+v / %+v", body.IssueLatency, body.VerifyLatency)
	}
	if len(body.DPGRows) != 1 || body.DPGRows[0].IssueAvgMS != "100.0 ms" || body.DPGRows[0].VerifyAvgMS != "500.0 ms" {
		t.Fatalf("dpg rows = %+v", body.DPGRows)
	}
	if len(body.SchemaRows) != 1 || body.SchemaRows[0].ErrorPct != "20.0 %" || body.SchemaRows[0].VerifReq != 2 {
		t.Fatalf("schema rows = %+v", body.SchemaRows)
	}

	// Each of the five queries failing in turn returns an error.
	queries := []string{"credential_issued_total", "verification_requested_total", "verification_completed_total", "adapter_duration_seconds_sum", "adapter_duration_seconds_count"}
	for _, bad := range queries {
		resp := map[string]string{}
		for k, v := range full {
			resp[k] = v
		}
		resp[bad] = `{"status":"error"}`
		s, _ := metricsPromServer(t, resp, 200)
		if _, err := buildMetricsFromPrometheus(context.Background(), s.URL); err == nil {
			t.Errorf("%s failing must error", bad)
		}
	}
}

func TestAggregateMetrics_EmptyAndUnorderedInput(t *testing.T) {
	body := aggregateMetrics(nil, nil, nil, nil, nil)
	if body.IssueLatency.AvgMS != "—" || body.VerifyLatency.AvgMS != "—" || len(body.DPGRows) != 0 || len(body.SchemaRows) != 0 {
		t.Fatalf("empty = %+v", body)
	}
	issued := []promVector{
		{Metric: map[string]string{"dpg": "b", "schema": "Z", "status": "ok"}, Value: 1},
		{Metric: map[string]string{"dpg": "a", "schema": "Y", "status": "ok"}, Value: 1},
		{Metric: map[string]string{"dpg": "a", "schema": "X", "status": "error"}, Value: 2},
	}
	body = aggregateMetrics(issued, nil, nil, nil, nil)
	if len(body.DPGRows) != 2 || body.DPGRows[0].DPG != "a" || body.DPGRows[1].DPG != "b" {
		t.Fatalf("dpg order = %+v", body.DPGRows)
	}
	if len(body.SchemaRows) != 3 || body.SchemaRows[0].Schema != "X" || body.SchemaRows[1].Schema != "Y" || body.SchemaRows[2].DPG != "b" {
		t.Fatalf("schema order = %+v", body.SchemaRows)
	}
	if body.SchemaRows[0].ErrorPct != "100.0 %" || body.DPGRows[0].IssueAvgMS != "—" {
		t.Fatalf("rows = %+v", body.SchemaRows)
	}
}

func TestBuildMetricsFromMemory(t *testing.T) {
	isolateMetricsDefault(t)
	metrics.IncN("credential_issued_total", 3, "dpg", "mem-dpg", "schema", "MemSchema", "status", "ok")
	metrics.Inc("credential_issued_total", "dpg", "mem-dpg", "schema", "MemSchema", "status", "error")
	metrics.Inc("verification_requested_total", "dpg", "mem-dpg", "schema", "MemSchema", "status", "ok")
	metrics.Inc("verification_completed_total", "dpg", "mem-dpg", "schema", "MemSchema", "status", "ok")
	metrics.ObserveDuration("adapter_duration_seconds", 200*time.Millisecond, "dpg", "mem-dpg", "op", "issue")
	metrics.ObserveDuration("other_duration_seconds", time.Second, "dpg", "mem-dpg", "op", "issue")
	body := buildMetricsFromMemory()
	var row *dpgRow
	for i := range body.DPGRows {
		if body.DPGRows[i].DPG == "mem-dpg" {
			row = &body.DPGRows[i]
		}
	}
	if row == nil || row.IssuedOK != 3 || row.IssuedError != 1 || row.VerifReq != 1 || row.VerifDone != 1 || row.IssueAvgMS == "—" {
		t.Fatalf("mem-dpg row = %+v (rows=%+v)", row, body.DPGRows)
	}
	found := false
	for _, s := range body.SchemaRows {
		if s.DPG == "mem-dpg" && s.Schema == "MemSchema" && s.ErrorPct != "—" {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema rows = %+v", body.SchemaRows)
	}
}

func TestShowAdminMetrics(t *testing.T) {
	newH := func(t *testing.T, admin bool) (*H, []*http.Cookie) {
		h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "admin_metrics")}
		cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = admin })
		return h, cookies
	}
	get := func(h *H, cookies []*http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
		req.Host = "portal.example"
		for _, c := range cookies {
			req.AddCookie(c)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ShowAdminMetrics(rr, req)
		return rr
	}

	t.Run("admin mode off → 404", func(t *testing.T) {
		h, cookies := newH(t, true)
		h.AuthAdminMode = "off"
		if rr := get(h, cookies, nil); rr.Code != http.StatusNotFound {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("not admin → redirect to login", func(t *testing.T) {
		h, cookies := newH(t, false)
		rr := get(h, cookies, nil)
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/admin/login" {
			t.Fatalf("status=%d location=%q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("memory source, full page, X-Forwarded-Host", func(t *testing.T) {
		h, cookies := newH(t, true)
		t.Setenv("VERIFIABLY_OTEL_ENDPOINT", "otel.example:4317")
		rr := get(h, cookies, map[string]string{"X-Forwarded-Host": "public.example", "X-Forwarded-Proto": "https"})
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, ">In-memory<") ||
			!strings.Contains(body, "https://public.example/metrics") || !strings.Contains(body, "otel.example:4317") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
	})
	t.Run("prometheus source (HTMX fragment) with Grafana link", func(t *testing.T) {
		h, cookies := newH(t, true)
		srv, _ := metricsPromServer(t, map[string]string{
			"credential_issued_total": `{"status":"success","data":{"result":[{"metric":{"dpg":"prom-dpg","schema":"S","status":"ok"},"value":[0,"7"]}]}}`,
		}, 200)
		h.PrometheusURL = srv.URL
		h.GrafanaURL = "http://grafana.example"
		rr := get(h, cookies, map[string]string{"HX-Request": "true", "HX-Target": "main"})
		body := rr.Body.String()
		if rr.Code != 200 || strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "Historical data from Prometheus") ||
			!strings.Contains(body, `href="http://grafana.example"`) || !strings.Contains(body, "prom-dpg") || !strings.Contains(body, "http://portal.example/metrics") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
	})
	t.Run("prometheus unreachable → memory-fallback banner", func(t *testing.T) {
		h, cookies := newH(t, true)
		h.PrometheusURL = "http://127.0.0.1:1"
		rr := get(h, cookies, nil)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Prometheus unreachable") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}
