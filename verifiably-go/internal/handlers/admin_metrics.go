package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/verifiably/verifiably-go/internal/metrics"
)

// metricsPageBody is the view model for the admin metrics dashboard.
type metricsPageBody struct {
	CredIssuedOK    int64
	CredIssuedError int64
	VerifRequested  int64
	VerifCompleted  int64
	// Latency by operation — kept separate because issue and verify
	// have fundamentally different latency profiles.
	IssueLatency  latencySummary
	VerifyLatency latencySummary
	// Breakdowns
	DPGRows    []dpgRow
	SchemaRows []schemaRow
	// Observability config
	OTLPEndpoint  string
	MetricsURL    string
	PrometheusURL string // empty when not configured
	GrafanaURL    string // empty when not configured
	// DataSource tells the template where the numbers came from.
	// "prometheus" | "memory" | "memory-fallback"
	DataSource string
}

type latencySummary struct {
	Calls int64
	AvgMS string // "12.3 ms" or "—"
	Note  string // human-readable explanation
}

type dpgRow struct {
	DPG         string
	IssuedOK    int64
	IssuedError int64
	VerifReq    int64
	VerifDone   int64
	IssueAvgMS  string
	VerifyAvgMS string
}

type schemaRow struct {
	DPG         string
	Schema      string
	IssuedOK    int64
	IssuedError int64
	ErrorPct    string // "4.2 %" or "—"
	VerifReq    int64
	VerifDone   int64
}

// ShowAdminMetrics handles GET /admin/metrics.
func (h *H) ShowAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if h.AuthAdminMode == "off" {
		http.NotFound(w, r)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}

	metricsURL := externalScheme(r) + "://" + r.Host + "/metrics"
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		metricsURL = externalScheme(r) + "://" + xfh + "/metrics"
	}

	var body metricsPageBody
	if h.PrometheusURL != "" {
		var err error
		body, err = buildMetricsFromPrometheus(r.Context(), h.PrometheusURL)
		if err != nil {
			body = buildMetricsFromMemory()
			body.DataSource = "memory-fallback"
		} else {
			body.DataSource = "prometheus"
		}
	} else {
		body = buildMetricsFromMemory()
		body.DataSource = "memory"
	}

	body.OTLPEndpoint = os.Getenv("VERIFIABLY_OTEL_ENDPOINT")
	body.MetricsURL = metricsURL
	body.PrometheusURL = h.PrometheusURL
	body.GrafanaURL = h.GrafanaURL

	h.render(w, r, "admin_metrics", h.pageData(sess, body))
}

// ── Prometheus data source ───────────────────────────────────────────────────

type promVector struct {
	Metric map[string]string
	Value  float64
}

// promQuery executes a Prometheus instant query and returns the vector results.
func promQuery(ctx context.Context, baseURL, promql string) ([]promVector, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	u := baseURL + "/api/v1/query?query=" + url.QueryEscape(promql)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string  `json:"metric"`
				Value  [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Status != "success" {
		return nil, fmt.Errorf("prometheus status: %s", out.Status)
	}

	result := make([]promVector, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		var vs string
		_ = json.Unmarshal(r.Value[1], &vs)
		v, _ := strconv.ParseFloat(vs, 64)
		result = append(result, promVector{Metric: r.Metric, Value: v})
	}
	return result, nil
}

func buildMetricsFromPrometheus(ctx context.Context, baseURL string) (metricsPageBody, error) {
	issued, err := promQuery(ctx, baseURL, "sum by (dpg, schema, status)(credential_issued_total)")
	if err != nil {
		return metricsPageBody{}, err
	}
	verifReq, err := promQuery(ctx, baseURL, "sum by (dpg, schema, status)(verification_requested_total)")
	if err != nil {
		return metricsPageBody{}, err
	}
	verifDone, err := promQuery(ctx, baseURL, "sum by (dpg, schema, status)(verification_completed_total)")
	if err != nil {
		return metricsPageBody{}, err
	}
	durSum, err := promQuery(ctx, baseURL, "sum by (dpg, op)(adapter_duration_seconds_sum)")
	if err != nil {
		return metricsPageBody{}, err
	}
	durCount, err := promQuery(ctx, baseURL, "sum by (dpg, op)(adapter_duration_seconds_count)")
	if err != nil {
		return metricsPageBody{}, err
	}

	return aggregateMetrics(issued, verifReq, verifDone, durSum, durCount), nil
}

// ── In-memory data source ────────────────────────────────────────────────────

func buildMetricsFromMemory() metricsPageBody {
	ctrs, hists := metrics.Samples()

	var issued, verifReqVecs, verifDoneVecs, durSum, durCount []promVector
	for _, c := range ctrs {
		switch c.Name {
		case "credential_issued_total":
			issued = append(issued, promVector{Metric: c.Labels, Value: float64(c.Value)})
		case "verification_requested_total":
			verifReqVecs = append(verifReqVecs, promVector{Metric: c.Labels, Value: float64(c.Value)})
		case "verification_completed_total":
			verifDoneVecs = append(verifDoneVecs, promVector{Metric: c.Labels, Value: float64(c.Value)})
		}
	}
	for _, hs := range hists {
		if hs.Name != "adapter_duration_seconds" {
			continue
		}
		durSum = append(durSum, promVector{Metric: hs.Labels, Value: hs.SumSeconds})
		durCount = append(durCount, promVector{Metric: hs.Labels, Value: float64(hs.Count)})
	}

	return aggregateMetrics(issued, verifReqVecs, verifDoneVecs, durSum, durCount)
}

// ── Shared aggregation ───────────────────────────────────────────────────────

type dpgAccum struct {
	issuedOK, issuedErr     int64
	verifReq, verifDone     int64
	issueSumMS, issueCount  float64
	verifySumMS, verifyCount float64
}

type schemaKey struct{ dpg, schema string }

func aggregateMetrics(
	issued, verifReq, verifDone, durSum, durCount []promVector,
) metricsPageBody {
	dpgMap := map[string]*dpgAccum{}
	getDPG := func(dpg string) *dpgAccum {
		if a, ok := dpgMap[dpg]; ok {
			return a
		}
		a := &dpgAccum{}
		dpgMap[dpg] = a
		return a
	}

	type schemaAccum struct {
		issuedOK, issuedErr int64
		verifReq, verifDone int64
	}
	schemaMap := map[schemaKey]*schemaAccum{}
	getSch := func(dpg, schema string) *schemaAccum {
		k := schemaKey{dpg, schema}
		if a, ok := schemaMap[k]; ok {
			return a
		}
		a := &schemaAccum{}
		schemaMap[k] = a
		return a
	}

	var credOK, credErr, totalVerifReq, totalVerifDone int64

	for _, v := range issued {
		dpg := v.Metric["dpg"]
		schema := v.Metric["schema"]
		status := v.Metric["status"]
		n := int64(v.Value)
		if status == "ok" {
			credOK += n
			getDPG(dpg).issuedOK += n
			getSch(dpg, schema).issuedOK += n
		} else {
			credErr += n
			getDPG(dpg).issuedErr += n
			getSch(dpg, schema).issuedErr += n
		}
	}
	for _, v := range verifReq {
		dpg := v.Metric["dpg"]
		schema := v.Metric["schema"]
		n := int64(v.Value)
		totalVerifReq += n
		getDPG(dpg).verifReq += n
		getSch(dpg, schema).verifReq += n
	}
	for _, v := range verifDone {
		dpg := v.Metric["dpg"]
		schema := v.Metric["schema"]
		n := int64(v.Value)
		totalVerifDone += n
		getDPG(dpg).verifDone += n
		getSch(dpg, schema).verifDone += n
	}

	// Build latency lookup: op → sumMS / count
	latSum := map[string]float64{}
	latCount := map[string]float64{}
	dpgLatSum := map[string]map[string]float64{}   // dpg → op → sumMS
	dpgLatCount := map[string]map[string]float64{} // dpg → op → count
	for _, v := range durSum {
		dpg := v.Metric["dpg"]
		op := v.Metric["op"]
		latSum[op] += v.Value * 1000 // seconds → ms
		if dpgLatSum[dpg] == nil {
			dpgLatSum[dpg] = map[string]float64{}
		}
		dpgLatSum[dpg][op] += v.Value * 1000
	}
	for _, v := range durCount {
		dpg := v.Metric["dpg"]
		op := v.Metric["op"]
		latCount[op] += v.Value
		if dpgLatCount[dpg] == nil {
			dpgLatCount[dpg] = map[string]float64{}
		}
		dpgLatCount[dpg][op] += v.Value
	}

	fmtAvgF := func(count, sumMS float64) string {
		if count == 0 {
			return "—"
		}
		return fmt.Sprintf("%.1f ms", sumMS/count)
	}
	fmtAvg := func(count int64, sumMS float64) string {
		return fmtAvgF(float64(count), sumMS)
	}
	_ = fmtAvg

	// ── DPG rows ─────────────────────────────────────────────────────────────
	dpgNames := make([]string, 0, len(dpgMap))
	for k := range dpgMap {
		dpgNames = append(dpgNames, k)
	}
	sort.Strings(dpgNames)

	dpgRows := make([]dpgRow, 0, len(dpgNames))
	for _, name := range dpgNames {
		a := dpgMap[name]
		dpgRows = append(dpgRows, dpgRow{
			DPG:         name,
			IssuedOK:    a.issuedOK,
			IssuedError: a.issuedErr,
			VerifReq:    a.verifReq,
			VerifDone:   a.verifDone,
			IssueAvgMS:  fmtAvgF(dpgLatCount[name]["issue"], dpgLatSum[name]["issue"]),
			VerifyAvgMS: fmtAvgF(dpgLatCount[name]["verify"], dpgLatSum[name]["verify"]),
		})
	}

	// ── Schema rows ──────────────────────────────────────────────────────────
	schKeys := make([]schemaKey, 0, len(schemaMap))
	for k := range schemaMap {
		schKeys = append(schKeys, k)
	}
	sort.Slice(schKeys, func(i, j int) bool {
		if schKeys[i].dpg != schKeys[j].dpg {
			return schKeys[i].dpg < schKeys[j].dpg
		}
		return schKeys[i].schema < schKeys[j].schema
	})

	schRows := make([]schemaRow, 0, len(schKeys))
	for _, k := range schKeys {
		a := schemaMap[k]
		total := a.issuedOK + a.issuedErr
		errPct := "—"
		if total > 0 {
			errPct = fmt.Sprintf("%.1f %%", float64(a.issuedErr)/float64(total)*100)
		}
		schRows = append(schRows, schemaRow{
			DPG:         k.dpg,
			Schema:      k.schema,
			IssuedOK:    a.issuedOK,
			IssuedError: a.issuedErr,
			ErrorPct:    errPct,
			VerifReq:    a.verifReq,
			VerifDone:   a.verifDone,
		})
	}

	totalIssueCalls := int64(latCount["issue"])
	totalVerifyCalls := int64(latCount["verify"])

	return metricsPageBody{
		CredIssuedOK:    credOK,
		CredIssuedError: credErr,
		VerifRequested:  totalVerifReq,
		VerifCompleted:  totalVerifDone,
		IssueLatency: latencySummary{
			Calls: totalIssueCalls,
			AvgMS: fmtAvgF(float64(totalIssueCalls), latSum["issue"]),
			Note:  "Tiempo de llamada al adapter para emitir una credencial.",
		},
		VerifyLatency: latencySummary{
			Calls: totalVerifyCalls,
			AvgMS: fmtAvgF(float64(totalVerifyCalls), latSum["verify"]),
			Note:  "Tiempo de llamada al adapter (creación de request + polls de resultado). No incluye el tiempo del usuario.",
		},
		DPGRows:    dpgRows,
		SchemaRows: schRows,
	}
}
