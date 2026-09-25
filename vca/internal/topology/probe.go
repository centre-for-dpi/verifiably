// SPDX-License-Identifier: Apache-2.0

package topology

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// State says what the probe found for one peer (ADR-034 decision 3).
type State int

const (
	// Absent means the host of the home service does not resolve. The
	// pair does not run, so no page shows it.
	Absent State = iota
	// Starting means the host resolves but the pair is not ready yet.
	Starting
	// Live means the home service is ready and the adapter, when the
	// pair has one, answered its capabilities.
	Live
)

// String names the state for a log line.
func (s State) String() string {
	switch s {
	case Absent:
		return "absent"
	case Starting:
		return "starting"
	case Live:
		return "live"
	default:
		return "unknown"
	}
}

// Status is the probe result of one peer.
type Status struct {
	// Peer is the candidate.
	Peer Peer
	// State is what the probe found.
	State State
	// Capabilities is the answer of the adapter. Only a live peer with
	// an adapter carries it.
	Capabilities *backendv1.GetCapabilitiesResponse
	// Err says why the peer is not live.
	Err error
}

// Has reports whether the adapter of the peer lists the feature.
func (s Status) Has(f backendv1.Feature) bool {
	for _, got := range s.Capabilities.GetFeatures() {
		if got == f {
			return true
		}
	}
	return false
}

// Snapshot is the result of one probe of every peer.
type Snapshot struct {
	// Taken is the time of the probe.
	Taken time.Time
	// Peers holds one status per peer, in the order of the peer list.
	Peers []Status
}

// Live returns the live peers, in order.
func (s Snapshot) Live() []Status {
	var out []Status
	for _, p := range s.Peers {
		if p.State == Live {
			out = append(out, p)
		}
	}
	return out
}

// ForRole returns the peers of one role that are not absent, in order.
func (s Snapshot) ForRole(role commonv1.Role) []Status {
	var out []Status
	for _, p := range s.Peers {
		if p.Peer.Role == role && p.State != Absent {
			out = append(out, p)
		}
	}
	return out
}

// StackName returns the display name of a stack: the name the first
// live adapter of the stack reports, or the short name of the enum value
// until an adapter answers (ADR-001 decision 4).
func (s Snapshot) StackName(d configv1.Dpg) string {
	for _, st := range s.Live() {
		if st.Peer.Dpg == d {
			if name := st.Capabilities.GetDpgInfo().GetDisplayName(); name != "" {
				return name
			}
		}
	}
	return shortName(d.String())
}

// Defaults of the prober (ADR-034 decision 2).
const (
	DefaultTTL     = 15 * time.Second
	DefaultTimeout = time.Second
)

// Prober checks every peer and caches the answer. The zero value with a
// peer list works: it uses the default client, the default resolver,
// a 1 s timeout, and a 15 s cache.
type Prober struct {
	// Peers are the candidates, from Parse.
	Peers []Peer
	// Client makes the requests. Nil means http.DefaultClient.
	Client *http.Client
	// Lookup resolves a host name. Nil means the default resolver.
	Lookup func(ctx context.Context, host string) ([]string, error)
	// TTL is the life of a snapshot. Zero means DefaultTTL.
	TTL time.Duration
	// Timeout bounds the probe of one peer. Zero means DefaultTimeout.
	Timeout time.Duration
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	probeMu sync.Mutex
	cached  Snapshot
	loaded  bool
}

// Snapshot returns the cached snapshot while it lives, or probes every
// peer in parallel and caches the result.
func (p *Prober) Snapshot(ctx context.Context) Snapshot {
	if s, ok := p.fresh(); ok {
		return s
	}
	p.probeMu.Lock()
	defer p.probeMu.Unlock()
	if s, ok := p.fresh(); ok {
		return s
	}
	return p.Refresh(ctx)
}

// Refresh probes every peer now and replaces the cache.
func (p *Prober) Refresh(ctx context.Context) Snapshot {
	snap := Snapshot{Taken: p.now(), Peers: make([]Status, len(p.Peers))}
	var wg sync.WaitGroup
	for i, peer := range p.Peers {
		wg.Add(1)
		go func(i int, peer Peer) {
			defer wg.Done()
			snap.Peers[i] = p.probe(ctx, peer)
		}(i, peer)
	}
	wg.Wait()
	p.mu.Lock()
	p.cached, p.loaded = snap, true
	p.mu.Unlock()
	return snap
}

// fresh returns the cached snapshot when it is inside the TTL.
func (p *Prober) fresh() (Snapshot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.loaded || !p.now().Before(p.cached.Taken.Add(p.ttl())) {
		return Snapshot{}, false
	}
	return p.cached, true
}

// probe checks one peer within the timeout.
func (p *Prober) probe(ctx context.Context, peer Peer) Status {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	status := Status{Peer: peer}
	home := peer.Home()
	if home == "" {
		status.Err = errors.New("the pair names no home service")
		return status
	}
	u, err := url.Parse(home)
	if err != nil || u.Hostname() == "" {
		status.Err = fmt.Errorf("the home URL %q has no host", home)
		return status
	}
	if _, err := p.lookup(ctx, u.Hostname()); err != nil {
		status.Err = fmt.Errorf("%s does not resolve: %w", u.Hostname(), err)
		return status
	}
	status.State = Starting
	if err := p.ready(ctx, home); err != nil {
		status.Err = err
		return status
	}
	if adapter := peer.Adapter(); adapter != "" {
		client := backendv1connect.NewCapabilityServiceClient(p.client(), adapter)
		resp, err := client.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			status.Err = fmt.Errorf("read the capabilities of the adapter: %w", err)
			return status
		}
		status.Capabilities = resp.Msg
	}
	status.State = Live
	return status
}

// ready asks the home service whether it takes traffic.
func (p *Prober) ready(ctx context.Context, home string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, home+"/readyz", nil)
	if err != nil {
		return err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("readiness: %w", err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		return cerr
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness: status %d", resp.StatusCode)
	}
	return nil
}

func (p *Prober) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient
}

func (p *Prober) lookup(ctx context.Context, host string) ([]string, error) {
	if p.Lookup != nil {
		return p.Lookup(ctx, host)
	}
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (p *Prober) ttl() time.Duration {
	if p.TTL > 0 {
		return p.TTL
	}
	return DefaultTTL
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return DefaultTimeout
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}
