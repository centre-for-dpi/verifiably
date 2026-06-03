package trust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// healthzServer creates an httptest.Server whose /healthz handler returns the
// given status code. The caller must call Close() when done.
func healthzServer(code int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
}

// registryWith returns a memStore pre-loaded with the given issuers.
func registryWith(issuers ...TrustedIssuer) Registry {
	r := NewMemStore()
	for _, iss := range issuers {
		_ = r.Add(context.Background(), iss)
	}
	return r
}

// ── NewMonitor ────────────────────────────────────────────────────────────────

func TestNewMonitor_InitialState(t *testing.T) {
	m := NewMonitor()
	status := m.EndpointStatus("did:web:anyone.gov")
	if status.Checked {
		t.Error("EndpointStatus should not be Checked before first probe")
	}
	if status.Up {
		t.Error("EndpointStatus should not be Up before first probe")
	}
}

// ── probeEndpoints ────────────────────────────────────────────────────────────

func TestMonitor_ProbeEndpoints_Up(t *testing.T) {
	srv := healthzServer(http.StatusOK)
	defer srv.Close()

	reg := registryWith(TrustedIssuer{
		DID:             "did:web:issuer.gov",
		ServiceEndpoint: srv.URL,
	})
	m := NewMonitor()
	m.probeEndpoints(context.Background(), reg)

	status := m.EndpointStatus("did:web:issuer.gov")
	if !status.Checked {
		t.Error("status.Checked should be true after probe")
	}
	if !status.Up {
		t.Error("status.Up should be true when /healthz returns 200")
	}
}

func TestMonitor_ProbeEndpoints_Down(t *testing.T) {
	srv := healthzServer(http.StatusServiceUnavailable)
	defer srv.Close()

	reg := registryWith(TrustedIssuer{
		DID:             "did:web:issuer.gov",
		ServiceEndpoint: srv.URL,
	})
	m := NewMonitor()
	m.probeEndpoints(context.Background(), reg)

	status := m.EndpointStatus("did:web:issuer.gov")
	if !status.Checked {
		t.Error("status.Checked should be true even for a down endpoint")
	}
	if status.Up {
		t.Error("status.Up should be false when /healthz returns 5xx")
	}
}

func TestMonitor_ProbeEndpoints_Unreachable(t *testing.T) {
	// Port on loopback that refuses connections
	reg := registryWith(TrustedIssuer{
		DID:             "did:web:issuer.gov",
		ServiceEndpoint: "http://127.0.0.1:1", // port 1 is not open
	})
	m := NewMonitor()
	m.probeEndpoints(context.Background(), reg)

	status := m.EndpointStatus("did:web:issuer.gov")
	if !status.Checked {
		t.Error("status.Checked should be true even for unreachable endpoint")
	}
	if status.Up {
		t.Error("status.Up should be false for unreachable endpoint")
	}
}

func TestMonitor_ProbeEndpoints_SkipsNoEndpoint(t *testing.T) {
	reg := registryWith(TrustedIssuer{
		DID: "did:web:issuer.gov",
		// ServiceEndpoint deliberately empty
	})
	m := NewMonitor()
	m.probeEndpoints(context.Background(), reg)

	status := m.EndpointStatus("did:web:issuer.gov")
	if status.Checked {
		t.Error("issuers without ServiceEndpoint should not be probed")
	}
}

// ── emitExpiry ────────────────────────────────────────────────────────────────

func TestMonitor_EmitExpiry_SkipsZeroValidUntil(t *testing.T) {
	reg := registryWith(TrustedIssuer{
		DID: "did:web:forever.gov",
		// ValidUntil zero = no expiry, should be skipped
	})
	m := NewMonitor()
	// Should not panic or emit any gauge
	m.emitExpiry(context.Background(), reg)
}

func TestMonitor_EmitExpiry_EmitsFutureExpiry(t *testing.T) {
	reg := registryWith(TrustedIssuer{
		DID:         "did:web:soon.gov",
		DisplayName: "Soon",
		ValidUntil:  time.Now().Add(45 * 24 * time.Hour), // 45 days from now
	})
	m := NewMonitor()
	// Should complete without error; gauge emission is verified by checking
	// the metrics output in metrics_test.go
	m.emitExpiry(context.Background(), reg)
	// knownDIDs should track this issuer
	m.mu.RLock()
	_, tracked := m.knownDIDs["did:web:soon.gov"]
	m.mu.RUnlock()
	if !tracked {
		t.Error("emitExpiry should track the issued DID in knownDIDs")
	}
}

// ── stale gauge cleanup ───────────────────────────────────────────────────────

func TestMonitor_StaleGaugeCleanup(t *testing.T) {
	ctx := context.Background()

	// Registry with one issuer that has an expiry set.
	reg := registryWith(TrustedIssuer{
		DID:        "did:web:ephemeral.gov",
		ValidUntil: time.Now().Add(60 * 24 * time.Hour),
	})

	m := NewMonitor()
	// First run: emits gauge, tracks the DID.
	m.emitExpiry(ctx, reg)

	m.mu.RLock()
	_, present := m.knownDIDs["did:web:ephemeral.gov"]
	m.mu.RUnlock()
	if !present {
		t.Fatal("DID should be in knownDIDs after first emit")
	}

	// Remove the issuer from the registry.
	_ = reg.Remove(ctx, "did:web:ephemeral.gov")

	// Second run: the DID is gone, so the gauge must be deleted.
	m.emitExpiry(ctx, reg)

	m.mu.RLock()
	_, still := m.knownDIDs["did:web:ephemeral.gov"]
	m.mu.RUnlock()
	if still {
		t.Error("removed issuer's DID should no longer be in knownDIDs after cleanup")
	}
}

// ── checkHealthz ─────────────────────────────────────────────────────────────

func TestCheckHealthz_OK(t *testing.T) {
	srv := healthzServer(http.StatusOK)
	defer srv.Close()

	m := NewMonitor()
	if !m.checkHealthz(context.Background(), srv.URL) {
		t.Error("checkHealthz should return true for HTTP 200")
	}
}

func TestCheckHealthz_NotOK(t *testing.T) {
	srv := healthzServer(http.StatusInternalServerError)
	defer srv.Close()

	m := NewMonitor()
	if m.checkHealthz(context.Background(), srv.URL) {
		t.Error("checkHealthz should return false for HTTP 500")
	}
}

func TestCheckHealthz_URL(t *testing.T) {
	// Verify that checkHealthz appends /healthz to the service endpoint.
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewMonitor()
	m.checkHealthz(context.Background(), srv.URL)
	if !strings.HasSuffix(capturedPath, "/healthz") {
		t.Errorf("checkHealthz should request /healthz, got path %q", capturedPath)
	}
}
