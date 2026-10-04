// SPDX-License-Identifier: Apache-2.0

// Package stacks finds the DPG stacks of a deployment whose adapter
// answers, and calls the tenant and notification services of an
// adapter for the admin service (ADR-037, ADR-038, ADR-040).
//
// A stack is one DPG. The topology snapshot holds one status per pair,
// and each pair of a stack runs its own adapter, whose answer may list
// other features than its siblings. List keeps the first live pair of
// each stack, for its name. A stack offers a feature when the answer of
// any of its live pairs lists it, and a call for that feature goes to
// the first such pair (ADR-034 decision 5). The package holds no vendor name: the name of a
// stack comes from the adapter (ADR-001 decision 4).
package stacks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// ErrNotOffered reports a stack that does not run now, or whose adapter
// does not list the feature a call needs.
var ErrNotOffered = errors.New("stacks: the stack does not offer the feature")

// Stack is one DPG of the deployment whose adapter answered.
type Stack struct {
	// Dpg names the stack.
	Dpg configv1.Dpg
	// Name is the display name the adapter reports, or the short name
	// of the enum value when the adapter reports none.
	Name string
	// Adapter is the internal URL of the adapter.
	Adapter string
	// Capabilities is the answer of the adapter.
	Capabilities *backendv1.GetCapabilitiesResponse
}

// Has reports whether the adapter of the stack lists a feature.
func (s Stack) Has(f backendv1.Feature) bool {
	for _, got := range s.Capabilities.GetFeatures() {
		if got == f {
			return true
		}
	}
	return false
}

// pairs returns every live pair with an adapter answer, in snapshot
// order, each as a stack.
func pairs(snap topology.Snapshot) []Stack {
	var out []Stack
	for _, st := range snap.Live() {
		adapter := st.Peer.Adapter()
		if adapter == "" || st.Capabilities == nil {
			continue
		}
		name := st.Capabilities.GetDpgInfo().GetDisplayName()
		if name == "" {
			name = shortName(st.Peer.Dpg)
		}
		out = append(out, Stack{Dpg: st.Peer.Dpg, Name: name, Adapter: adapter, Capabilities: st.Capabilities})
	}
	return out
}

// firstPerDpg keeps the first stack of each DPG that keep accepts.
func firstPerDpg(list []Stack, keep func(Stack) bool) []Stack {
	var out []Stack
	seen := map[configv1.Dpg]bool{}
	for _, s := range list {
		if seen[s.Dpg] || !keep(s) {
			continue
		}
		seen[s.Dpg] = true
		out = append(out, s)
	}
	return out
}

// List returns one stack per DPG with a live adapter, in snapshot order:
// the first live pair of the DPG.
func List(snap topology.Snapshot) []Stack {
	return firstPerDpg(pairs(snap), func(Stack) bool { return true })
}

// With returns one stack per DPG that offers a feature: the first live
// pair of the DPG whose adapter lists it.
func With(snap topology.Snapshot, f backendv1.Feature) []Stack {
	return firstPerDpg(pairs(snap), func(s Stack) bool { return s.Has(f) })
}

// Name returns the display name of a stack, or the short name of the
// enum value when no live adapter of the stack answers.
func Name(snap topology.Snapshot, d configv1.Dpg) string {
	for _, s := range List(snap) {
		if s.Dpg == d {
			return s.Name
		}
	}
	return shortName(d)
}

// shortName turns DPG_CREDEBL into credebl.
func shortName(d configv1.Dpg) string {
	return strings.ToLower(strings.TrimPrefix(d.String(), "DPG_"))
}

// Snapshot returns the state of every peer of the deployment.
type Snapshot func(ctx context.Context) topology.Snapshot

// Directory reads the stacks of the deployment and builds clients for
// their adapters. A nil Directory offers no stack.
type Directory struct {
	snapshot Snapshot
	client   connect.HTTPClient
}

// New returns a directory over a snapshot source. A nil source offers
// no stack. A nil client selects http.DefaultClient.
func New(snapshot Snapshot, client connect.HTTPClient) *Directory {
	if client == nil {
		client = http.DefaultClient
	}
	return &Directory{snapshot: snapshot, client: client}
}

// List returns the stacks of the deployment now.
func (d *Directory) List(ctx context.Context) []Stack {
	if d == nil || d.snapshot == nil {
		return nil
	}
	return List(d.snapshot(ctx))
}

// With returns the stacks of the deployment now that offer a feature,
// each through the first live pair whose adapter lists it.
func (d *Directory) With(ctx context.Context, f backendv1.Feature) []Stack {
	if d == nil || d.snapshot == nil {
		return nil
	}
	return With(d.snapshot(ctx), f)
}

// Find returns the stack of a DPG through the first live pair whose
// adapter lists a feature. It returns ErrNotOffered otherwise.
func (d *Directory) Find(ctx context.Context, dpg configv1.Dpg, f backendv1.Feature) (Stack, error) {
	for _, s := range d.With(ctx, f) {
		if s.Dpg == dpg {
			return s, nil
		}
	}
	return Stack{}, fmt.Errorf("%w: %s, %s", ErrNotOffered, shortName(dpg), f)
}

// Tenants returns a client of the tenant service of a stack.
func (d *Directory) Tenants(s Stack) backendv1connect.TenantBackendServiceClient {
	return backendv1connect.NewTenantBackendServiceClient(d.client, s.Adapter)
}

// Notifications returns a client of the notification service of a stack.
func (d *Directory) Notifications(s Stack) backendv1connect.NotificationBackendServiceClient {
	return backendv1connect.NewNotificationBackendServiceClient(d.client, s.Adapter)
}
