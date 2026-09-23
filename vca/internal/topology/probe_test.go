// SPDX-License-Identifier: Apache-2.0

package topology_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// readyServer answers /readyz with the status, after the delay.
func readyServer(t *testing.T, status int, delay time.Duration) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		time.Sleep(delay)
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	return s
}

// capabilityStub answers GetCapabilities with a fixed adapter name.
type capabilityStub struct {
	backendv1connect.UnimplementedCapabilityServiceHandler
	calls atomic.Int32
	fail  bool
}

func (c *capabilityStub) GetCapabilities(
	context.Context, *connect.Request[backendv1.GetCapabilitiesRequest],
) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	c.calls.Add(1)
	if c.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		Adapter:  "dpg-adapter-test",
		Features: []backendv1.Feature{backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API},
		DpgInfo:  &backendv1.DpgInfo{DisplayName: "Test stack"},
	}), nil
}

// adapterServer serves the stub over Connect.
func adapterServer(t *testing.T, stub *capabilityStub) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(stub))
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// closedAddress returns a URL whose port refuses connections.
func closedAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return "http://" + addr
}

// resolveAll is a lookup that resolves every host.
func resolveAll(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }

func peer(pair, home, adapter string) topology.Peer {
	role, dpg := commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID
	services := map[string]string{topology.HomeService(role): home}
	if adapter != "" {
		services["dpg-adapter-waltid"] = adapter
	}
	return topology.Peer{Pair: pair, Role: role, Dpg: dpg, PublicURL: "https://" + pair + ".example", Services: services}
}

func TestProbeStates(t *testing.T) {
	ready := readyServer(t, http.StatusOK, 0)
	starting := readyServer(t, http.StatusServiceUnavailable, 0)
	adapter := adapterServer(t, &capabilityStub{})
	peers := []topology.Peer{
		peer("issuer-waltid", ready.URL, adapter.URL),
		peer("issuer-inji", starting.URL, adapter.URL),
		peer("issuer-credebl", closedAddress(t), adapter.URL),
		peer("holder-waltid", "http://no-such-host.invalid:8080", adapter.URL),
		{Pair: "admin-waltid", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://admin.example"},
	}
	p := &topology.Prober{
		Peers:  peers,
		Client: ready.Client(),
		Lookup: func(_ context.Context, host string) ([]string, error) {
			if strings.HasSuffix(host, ".invalid") {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			return []string{"127.0.0.1"}, nil
		},
	}
	snap := p.Snapshot(context.Background())
	want := map[string]topology.State{
		"issuer-waltid":  topology.Live,
		"issuer-inji":    topology.Starting,
		"issuer-credebl": topology.Starting,
		"holder-waltid":  topology.Absent,
		"admin-waltid":   topology.Absent,
	}
	if len(snap.Peers) != len(peers) {
		t.Fatalf("snapshot has %d peers, want %d", len(snap.Peers), len(peers))
	}
	for _, s := range snap.Peers {
		if s.State != want[s.Peer.Pair] {
			t.Errorf("%s: state %v, want %v (%v)", s.Peer.Pair, s.State, want[s.Peer.Pair], s.Err)
		}
		if s.State == topology.Live && s.Capabilities == nil {
			t.Errorf("%s: a live peer must carry its capabilities", s.Peer.Pair)
		}
		if s.State != topology.Live && s.Capabilities != nil {
			t.Errorf("%s: only a live peer carries capabilities", s.Peer.Pair)
		}
	}
	live := snap.Live()
	if len(live) != 1 || live[0].Peer.Pair != "issuer-waltid" {
		t.Errorf("live = %v", live)
	}
	for _, s := range snap.Peers {
		if s.State == topology.Absent && s.Err == nil {
			t.Errorf("%s: an absent peer must say why", s.Peer.Pair)
		}
	}
	if topology.Live.String() != "live" || topology.Starting.String() != "starting" || topology.Absent.String() != "absent" ||
		topology.State(9).String() != "unknown" {
		t.Error("the state names are wrong")
	}
}

func TestProbeTreatsAFailedCapabilityReadAsStarting(t *testing.T) {
	ready := readyServer(t, http.StatusOK, 0)
	adapter := adapterServer(t, &capabilityStub{fail: true})
	p := &topology.Prober{
		Peers: []topology.Peer{peer("issuer-waltid", ready.URL, adapter.URL)}, Client: ready.Client(), Lookup: resolveAll,
	}
	snap := p.Snapshot(context.Background())
	if snap.Peers[0].State != topology.Starting || snap.Peers[0].Err == nil {
		t.Fatalf("state = %v, err = %v", snap.Peers[0].State, snap.Peers[0].Err)
	}
}

func TestProbeWithoutAnAdapterIsLiveWhenReady(t *testing.T) {
	ready := readyServer(t, http.StatusOK, 0)
	p := &topology.Prober{
		Peers: []topology.Peer{{
			Pair: "admin-waltid", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID,
			PublicURL: "https://admin.example", Services: map[string]string{"admin": ready.URL},
		}},
		Client: ready.Client(), Lookup: resolveAll,
	}
	snap := p.Snapshot(context.Background())
	if snap.Peers[0].State != topology.Live || snap.Peers[0].Capabilities != nil {
		t.Fatalf("state = %v, capabilities = %v", snap.Peers[0].State, snap.Peers[0].Capabilities)
	}
	if got := snap.ForRole(commonv1.Role_ROLE_ADMIN); len(got) != 1 {
		t.Fatalf("ForRole = %v", got)
	}
	if got := snap.ForRole(commonv1.Role_ROLE_ISSUER); len(got) != 0 {
		t.Fatalf("ForRole = %v", got)
	}
}

func TestProbeReadsCapabilities(t *testing.T) {
	ready := readyServer(t, http.StatusOK, 0)
	stub := &capabilityStub{}
	adapter := adapterServer(t, stub)
	p := &topology.Prober{
		Peers: []topology.Peer{peer("issuer-waltid", ready.URL, adapter.URL)}, Client: ready.Client(), Lookup: resolveAll,
	}
	snap := p.Snapshot(context.Background())
	caps := snap.Peers[0].Capabilities
	if caps.GetAdapter() != "dpg-adapter-test" || caps.GetDpgInfo().GetDisplayName() != "Test stack" {
		t.Fatalf("capabilities = %v", caps)
	}
	if !snap.Peers[0].Has(backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API) ||
		snap.Peers[0].Has(backendv1.Feature_FEATURE_REVOCATION) {
		t.Fatal("Has must read the feature list")
	}
	if stub.calls.Load() != 1 {
		t.Fatalf("the adapter was called %d times, want 1", stub.calls.Load())
	}
}

func TestProbeCachesForTTL(t *testing.T) {
	var hits atomic.Int32
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ready.Close)
	now := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	p := &topology.Prober{
		Peers:  []topology.Peer{peer("issuer-waltid", ready.URL, "")},
		Client: ready.Client(), Lookup: resolveAll, TTL: 15 * time.Second,
		Now: func() time.Time { return now },
	}
	ctx := context.Background()
	first := p.Snapshot(ctx)
	second := p.Snapshot(ctx)
	if hits.Load() != 1 {
		t.Fatalf("two snapshots inside the TTL hit the peer %d times, want 1", hits.Load())
	}
	if !first.Taken.Equal(second.Taken) {
		t.Fatal("the second snapshot is not the cached one")
	}
	now = now.Add(15 * time.Second)
	third := p.Snapshot(ctx)
	if hits.Load() != 2 {
		t.Fatalf("a snapshot after the TTL hit the peer %d times, want 2", hits.Load())
	}
	if third.Taken.Equal(first.Taken) {
		t.Fatal("the snapshot after the TTL is still the old one")
	}
	p.Refresh(ctx)
	if hits.Load() != 3 {
		t.Fatalf("Refresh must probe again, got %d hits", hits.Load())
	}
}

func TestProbeRunsInParallelWithinBudget(t *testing.T) {
	slow := readyServer(t, http.StatusOK, 800*time.Millisecond)
	var peers []topology.Peer
	for i := 0; i < 12; i++ {
		peers = append(peers, peer(fmt.Sprintf("issuer-waltid-%d", i), slow.URL, ""))
	}
	p := &topology.Prober{Peers: peers, Client: slow.Client(), Lookup: resolveAll}
	start := time.Now()
	snap := p.Snapshot(context.Background())
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("12 peers took %v, want under 2 s", took)
	}
	for _, s := range snap.Peers {
		if s.State != topology.Live {
			t.Errorf("%s: %v (%v)", s.Peer.Pair, s.State, s.Err)
		}
	}
}

func TestProbeTimesOutASlowPeer(t *testing.T) {
	slow := readyServer(t, http.StatusOK, 300*time.Millisecond)
	p := &topology.Prober{
		Peers: []topology.Peer{peer("issuer-waltid", slow.URL, "")}, Client: slow.Client(), Lookup: resolveAll,
		Timeout: 50 * time.Millisecond,
	}
	snap := p.Snapshot(context.Background())
	if snap.Peers[0].State != topology.Starting {
		t.Fatalf("a peer slower than the timeout must be starting, got %v", snap.Peers[0].State)
	}
}

func TestProbeUsesTheDefaultResolverAndClient(t *testing.T) {
	ready := readyServer(t, http.StatusOK, 0)
	// The default lookup resolves the loopback host of the test server.
	p := &topology.Prober{Peers: []topology.Peer{peer("issuer-waltid", ready.URL, "")}}
	snap := p.Snapshot(context.Background())
	if snap.Peers[0].State != topology.Live {
		t.Fatalf("state = %v (%v)", snap.Peers[0].State, snap.Peers[0].Err)
	}
	u, err := url.Parse(ready.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "127.0.0.1" {
		t.Fatalf("the test server is not on the loopback: %s", u.Hostname())
	}
}

func TestProbeMarksABadHomeURLAbsent(t *testing.T) {
	p := &topology.Prober{Peers: []topology.Peer{peer("issuer-waltid", "::not a url", "")}, Lookup: resolveAll}
	snap := p.Snapshot(context.Background())
	if snap.Peers[0].State != topology.Absent || snap.Peers[0].Err == nil {
		t.Fatalf("state = %v, err = %v", snap.Peers[0].State, snap.Peers[0].Err)
	}
}
