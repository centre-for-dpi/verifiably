package trust

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/internal/metrics"
)

const (
	metricExpiry   = "trusted_issuer_days_until_expiry"
	metricEndpoint = "trusted_issuer_endpoint_up"
)

// EndpointStatus captures the last known health of an issuer's /healthz endpoint.
type EndpointStatus struct {
	Up      bool
	Checked bool // false until the first probe completes
	At      time.Time
}

// Monitor runs background probes for the trust registry health dashboard and
// emits two Prometheus gauges:
//
//	trusted_issuer_days_until_expiry{did,name}  — hourly
//	trusted_issuer_endpoint_up{did,name}        — every 5 minutes
//
// Both gauges are cleaned up automatically when an issuer is removed from the
// registry. The monitor also keeps an in-memory status map that
// ShowFederationMembers uses to render the health semaphore in the admin UI.
type Monitor struct {
	mu        sync.RWMutex
	status    map[string]EndpointStatus // DID → last probe result
	knownDIDs map[string]struct{}       // DIDs we've emitted gauges for
	client    *http.Client
}

// NewMonitor creates a Monitor with a 5-second HTTP timeout per healthz probe.
func NewMonitor() *Monitor {
	return &Monitor{
		status:    make(map[string]EndpointStatus),
		knownDIDs: make(map[string]struct{}),
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Start launches the expiry and endpoint goroutines. Both run immediately on
// start and then on their respective tickers. Shut down by cancelling ctx.
func (m *Monitor) Start(ctx context.Context, reg Registry) {
	go m.runExpiry(ctx, reg)
	go m.runEndpoint(ctx, reg)
}

// EndpointStatus returns the last known endpoint health for the given DID.
// Returns the zero value (Checked=false) when no probe has run yet.
func (m *Monitor) EndpointStatus(did string) EndpointStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status[did]
}

// runExpiry emits trusted_issuer_days_until_expiry every hour.
func (m *Monitor) runExpiry(ctx context.Context, reg Registry) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	m.emitExpiry(ctx, reg)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.emitExpiry(ctx, reg)
		}
	}
}

// runEndpoint probes each issuer's /healthz every 5 minutes.
func (m *Monitor) runEndpoint(ctx context.Context, reg Registry) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	m.probeEndpoints(ctx, reg)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeEndpoints(ctx, reg)
		}
	}
}

func (m *Monitor) emitExpiry(ctx context.Context, reg Registry) {
	issuers, err := reg.TrustedIssuers(ctx)
	if err != nil {
		slog.Warn("trust health: query issuers for expiry", "err", err)
		return
	}

	// Build current DID set; delete gauges for removed issuers.
	current := make(map[string]struct{}, len(issuers))
	for _, issuer := range issuers {
		current[issuer.DID] = struct{}{}
	}
	m.mu.Lock()
	for did := range m.knownDIDs {
		if _, ok := current[did]; !ok {
			metrics.DeleteGauge(metricExpiry, "did", did)
			metrics.DeleteGauge(metricEndpoint, "did", did)
		}
	}
	m.knownDIDs = current
	m.mu.Unlock()

	now := time.Now().UTC()
	for _, issuer := range issuers {
		if issuer.ValidUntil.IsZero() {
			continue // no expiry configured — skip
		}
		days := int64(issuer.ValidUntil.Sub(now).Hours() / 24)
		name := issuer.DisplayName
		if name == "" {
			name = issuer.DID
		}
		metrics.SetGauge(metricExpiry, days, "did", issuer.DID, "name", name)
	}
}

func (m *Monitor) probeEndpoints(ctx context.Context, reg Registry) {
	issuers, err := reg.TrustedIssuers(ctx)
	if err != nil {
		slog.Warn("trust health: query issuers for endpoint probe", "err", err)
		return
	}
	for _, issuer := range issuers {
		if issuer.ServiceEndpoint == "" {
			continue
		}
		name := issuer.DisplayName
		if name == "" {
			name = issuer.DID
		}
		up := m.checkHealthz(ctx, issuer.ServiceEndpoint)
		upVal := int64(0)
		if up {
			upVal = 1
		}
		metrics.SetGauge(metricEndpoint, upVal, "did", issuer.DID, "name", name)

		m.mu.Lock()
		m.status[issuer.DID] = EndpointStatus{Up: up, Checked: true, At: time.Now()}
		m.mu.Unlock()

		if !up {
			slog.Warn("trust health: issuer endpoint down",
				"did", issuer.DID, "endpoint", issuer.ServiceEndpoint)
		}
	}
}

func (m *Monitor) checkHealthz(ctx context.Context, serviceEndpoint string) bool {
	url := fmt.Sprintf("%s/healthz", serviceEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
