// Package metrics is a minimal, stdlib-only Prometheus text-format exporter.
// It exposes counters and histograms via a Default registry and an HTTP
// handler that writes the standard Prometheus exposition format (v0.0.4).
// No external dependencies — wire format is identical to what
// prometheus/client_golang produces so any Prometheus scraper works.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Default is the process-global registry. Use the package-level functions
// (Inc, IncN, ObserveDuration) rather than calling Default directly.
var Default = newRegistry()

// histoBuckets are the upper-bound values (seconds) for each histogram bucket.
// Chosen for backend adapter call latency: fast network path ≤ 5 ms,
// warm response ≤ 100 ms, slow response ≤ 2 s, anything beyond is +Inf.
var histoBuckets = []float64{0.005, 0.025, 0.1, 0.5, 2.0}

// ctr is a labelled counter.
type ctr struct {
	name string
	ls   string // "dpg=\"waltid\",schema=\"x\"" — no outer braces; may be empty
	val  atomic.Int64
}

// histo is a labelled histogram with fixed buckets.
type histo struct {
	name    string
	ls      string
	sumNS   atomic.Int64   // sum of observed durations in nanoseconds
	count   atomic.Int64
	buckets [6]atomic.Int64 // len(histoBuckets) upper bounds + 1 for +Inf
}

type registry struct {
	mu   sync.Mutex
	ctrs map[string]*ctr
	hist map[string]*histo
}

func newRegistry() *registry {
	return &registry{
		ctrs: make(map[string]*ctr),
		hist: make(map[string]*histo),
	}
}

// labStr converts ["k1","v1","k2","v2"] → `k1="v1",k2="v2"`.
// Odd-length slices drop the trailing key.
// Values are sanitized for the Prometheus text exposition format: `"` is
// escaped to `\"`, and `\n` / `\r` are escaped so a user-supplied label value
// (e.g. a schema name with a newline) cannot inject fake metric lines.
func labStr(kv []string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		v := kv[i+1]
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		v = strings.ReplaceAll(v, "\n", `\n`)
		v = strings.ReplaceAll(v, "\r", `\r`)
		b.WriteString(kv[i])
		b.WriteString(`="`)
		b.WriteString(v)
		b.WriteByte('"')
	}
	return b.String()
}

// mapKey returns the lookup key separating name and label string with \x00.
func mapKey(name, ls string) string { return name + "\x00" + ls }

func (r *registry) counter(name string, kv []string) *ctr {
	ls := labStr(kv)
	k := mapKey(name, ls)
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.ctrs[k]; ok {
		return c
	}
	c := &ctr{name: name, ls: ls}
	r.ctrs[k] = c
	return c
}

func (r *registry) histogram(name string, kv []string) *histo {
	ls := labStr(kv)
	k := mapKey(name, ls)
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.hist[k]; ok {
		return h
	}
	h := &histo{name: name, ls: ls}
	r.hist[k] = h
	return h
}

// Inc increments the named counter by 1. Labels must be key, value pairs.
func (r *registry) Inc(name string, labels ...string) {
	r.counter(name, labels).val.Add(1)
}

// IncN increments the named counter by n.
func (r *registry) IncN(name string, n int64, labels ...string) {
	r.counter(name, labels).val.Add(n)
}

// ObserveDuration records d in the named histogram.
func (r *registry) ObserveDuration(name string, d time.Duration, labels ...string) {
	h := r.histogram(name, labels)
	secs := d.Seconds()
	h.sumNS.Add(d.Nanoseconds())
	h.count.Add(1)
	for i, le := range histoBuckets {
		if secs <= le {
			h.buckets[i].Add(1)
		}
	}
	h.buckets[len(histoBuckets)].Add(1) // +Inf is always == count
}

// Handler returns an HTTP handler that writes the current metrics in
// Prometheus text exposition format (Content-Type: text/plain; version=0.0.4).
func (r *registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.writeTo(w)
	})
}

func (r *registry) snapshot() ([]*ctr, []*histo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctrs := make([]*ctr, 0, len(r.ctrs))
	for _, c := range r.ctrs {
		ctrs = append(ctrs, c)
	}
	hists := make([]*histo, 0, len(r.hist))
	for _, h := range r.hist {
		hists = append(hists, h)
	}
	return ctrs, hists
}

func (r *registry) writeTo(w io.Writer) {
	ctrs, hists := r.snapshot()

	sort.Slice(ctrs, func(i, j int) bool {
		if ctrs[i].name != ctrs[j].name {
			return ctrs[i].name < ctrs[j].name
		}
		return ctrs[i].ls < ctrs[j].ls
	})
	sort.Slice(hists, func(i, j int) bool {
		if hists[i].name != hists[j].name {
			return hists[i].name < hists[j].name
		}
		return hists[i].ls < hists[j].ls
	})

	lastName := ""
	for _, c := range ctrs {
		if c.name != lastName {
			fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
			lastName = c.name
		}
		if c.ls != "" {
			fmt.Fprintf(w, "%s{%s} %d\n", c.name, c.ls, c.val.Load())
		} else {
			fmt.Fprintf(w, "%s %d\n", c.name, c.val.Load())
		}
	}

	lastName = ""
	for _, h := range hists {
		if h.name != lastName {
			fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)
			lastName = h.name
		}
		ls := h.ls
		for i, le := range histoBuckets {
			if ls != "" {
				fmt.Fprintf(w, "%s_bucket{%s,le=%q} %d\n", h.name, ls, fmt.Sprintf("%g", le), h.buckets[i].Load())
			} else {
				fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", h.name, fmt.Sprintf("%g", le), h.buckets[i].Load())
			}
		}
		infCount := h.buckets[len(histoBuckets)].Load()
		sumSecs := float64(h.sumNS.Load()) / 1e9
		if ls != "" {
			fmt.Fprintf(w, "%s_bucket{%s,le=\"+Inf\"} %d\n", h.name, ls, infCount)
			fmt.Fprintf(w, "%s_sum{%s} %g\n", h.name, ls, sumSecs)
			fmt.Fprintf(w, "%s_count{%s} %d\n", h.name, ls, h.count.Load())
		} else {
			fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h.name, infCount)
			fmt.Fprintf(w, "%s_sum %g\n", h.name, sumSecs)
			fmt.Fprintf(w, "%s_count %d\n", h.name, h.count.Load())
		}
	}
}

// ── Snapshot types ────────────────────────────────────────────────────────────

// CounterSample is a point-in-time reading of a single labelled counter.
type CounterSample struct {
	Name   string
	Labels map[string]string
	Value  int64
}

// HistoSample is a point-in-time reading of a single labelled histogram.
type HistoSample struct {
	Name       string
	Labels     map[string]string
	Count      int64
	SumSeconds float64
	// Buckets holds cumulative counts for each upper bound in histoBuckets
	// plus +Inf as the last element.
	Buckets [6]int64
	// UpperBounds mirrors histoBuckets for template iteration.
	UpperBounds [5]float64
}

// Samples returns a point-in-time snapshot of all counters and histograms
// in the Default registry. Safe to call concurrently.
func Samples() ([]CounterSample, []HistoSample) { return Default.samples() }

func (r *registry) samples() ([]CounterSample, []HistoSample) {
	ctrs, hists := r.snapshot()
	cs := make([]CounterSample, len(ctrs))
	for i, c := range ctrs {
		cs[i] = CounterSample{
			Name:   c.name,
			Labels: parseLabels(c.ls),
			Value:  c.val.Load(),
		}
	}
	hs := make([]HistoSample, len(hists))
	for i, h := range hists {
		var buckets [6]int64
		for j := range buckets {
			buckets[j] = h.buckets[j].Load()
		}
		var ub [5]float64
		copy(ub[:], histoBuckets)
		hs[i] = HistoSample{
			Name:        h.name,
			Labels:      parseLabels(h.ls),
			Count:       h.count.Load(),
			SumSeconds:  float64(h.sumNS.Load()) / 1e9,
			Buckets:     buckets,
			UpperBounds: ub,
		}
	}
	return cs, hs
}

// parseLabels parses the Prometheus label string produced by labStr back into
// a key→value map. The format is: key1="escaped_val1",key2="escaped_val2".
// Values containing commas are not handled (our label values never do).
func parseLabels(ls string) map[string]string {
	if ls == "" {
		return nil
	}
	m := make(map[string]string)
	for _, part := range strings.Split(ls, ",") {
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		key := part[:idx]
		val := part[idx+1:]
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = unescapeLabVal(val[1 : len(val)-1])
		}
		m[key] = val
	}
	return m
}

func unescapeLabVal(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(s[i])
				b.WriteByte(s[i+1])
			}
			i += 2
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// ── Package-level helpers using Default ──────────────────────────────────────

// Inc increments the named counter by 1.
func Inc(name string, labels ...string) { Default.Inc(name, labels...) }

// IncN increments the named counter by n.
func IncN(name string, n int64, labels ...string) { Default.IncN(name, n, labels...) }

// ObserveDuration records d in the named histogram.
func ObserveDuration(name string, d time.Duration, labels ...string) {
	Default.ObserveDuration(name, d, labels...)
}

// Handler returns an http.Handler that serves /metrics in Prometheus format.
func Handler() http.Handler { return Default.Handler() }
