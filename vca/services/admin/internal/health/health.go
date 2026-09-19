// SPDX-License-Identifier: Apache-2.0

// Package health probes the readiness endpoint of every service in the
// deployment (ADR-009 decision 1). The admin service reports the result
// through the GetServiceHealth RPC and the portal shows it.
//
// A probe is one GET on the readyz path of the service. A status 200
// means ready. The probe reads the version from the X-Vca-Version
// response header, or from a version=<value> token in the body.
package health

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// VersionHeader carries the version of the running image.
const VersionHeader = "X-Vca-Version"

// DefaultTimeout bounds one probe.
const DefaultTimeout = 5 * time.Second

// maxBody caps the body the probe reads.
const maxBody = 4 << 10

// Target is one service to probe.
type Target struct {
	// Name is the service name, for example trust-registry.
	Name string
	// URL is the readiness endpoint, for example
	// https://trust.example/readyz.
	URL string
}

// Result is the health of one service.
type Result struct {
	// Name is the service name.
	Name string
	// Version is the version of the running image, when the service
	// reports one.
	Version string
	// Ready reports whether the probe passed.
	Ready bool
	// CheckedAt is the time of the probe.
	CheckedAt time.Time
	// Error is the reason the probe failed. It is empty on a pass.
	Error string
}

// Prober runs the probes.
type Prober struct {
	client  *http.Client
	timeout time.Duration
	now     func() time.Time
}

// New returns a prober. A nil client selects a client with the timeout.
// A zero timeout selects DefaultTimeout. A nil clock selects time.Now.
func New(client *http.Client, timeout time.Duration, now func() time.Time) *Prober {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	if now == nil {
		now = time.Now
	}
	return &Prober{client: client, timeout: timeout, now: now}
}

// CheckAll probes every target at the same time and returns the results
// sorted by name.
func (p *Prober) CheckAll(ctx context.Context, targets []Target) []Result {
	out := make([]Result, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target Target) {
			defer wg.Done()
			out[i] = p.Check(ctx, target)
		}(i, target)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Check probes one target.
func (p *Prober) Check(ctx context.Context, target Target) Result {
	res := Result{Name: target.Name, CheckedAt: p.now().UTC()}
	if target.URL == "" {
		res.Error = "the service has no readiness URL"
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		res.Error = "the readiness URL is not valid"
		return res
	}
	resp, err := p.client.Do(req)
	if err != nil {
		res.Error = Reason(err)
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	res.Version = Version(resp.Header.Get(VersionHeader), string(body))
	res.CheckedAt = p.now().UTC()
	if resp.StatusCode != http.StatusOK {
		res.Error = "the readiness probe returned status " + resp.Status
		return res
	}
	res.Ready = true
	return res
}

// Version returns the version from the header, or from a version=<value>
// token in the body. It returns "" when neither names one.
func Version(header, body string) string {
	if v := strings.TrimSpace(header); v != "" {
		return v
	}
	for _, field := range strings.Fields(body) {
		if value, ok := strings.CutPrefix(field, "version="); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// Reason returns a short sentence for a probe error. The text never
// holds a credential, because a readiness URL carries none.
func Reason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "the service did not answer in time"
	}
	return "the service could not be reached"
}
