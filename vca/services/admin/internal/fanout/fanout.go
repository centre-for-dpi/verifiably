// SPDX-License-Identifier: Apache-2.0

// Package fanout pushes a provider record from the admin service to the
// auth service of every live pair the record names (ADR-035 decision
// 5). The record names roles and stacks; the topology snapshot says
// which pairs run. The push carries the admin session token, which
// each auth service checks against the admin key set. A push is
// idempotent: a target that already holds the record gets an update.
// The report names the outcome at every target, so a partial failure
// is visible.
package fanout

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// DefaultTimeout bounds one call to an auth service.
const DefaultTimeout = 10 * time.Second

// ErrNoToken reports a push without an admin session token to forward.
// An API key opens the admin RPCs, but the auth services accept only a
// session the admin key set signed.
var ErrNoToken = errors.New("fanout: no admin session token to forward")

// Target is one live pair whose auth service takes the record.
type Target struct {
	// Pair is the pair name, for example issuer-waltid.
	Pair string
	// Role is the role of the pair.
	Role commonv1.Role
	// Dpg is the stack of the pair.
	Dpg configv1.Dpg
	// AuthURL is the internal URL of the auth service of the pair.
	AuthURL string
}

// Result is the outcome at one target.
type Result struct {
	// Target is the pair the push went to.
	Target Target
	// ProviderID is the id the auth service holds the record under.
	ProviderID string
	// Created says whether the push made a new record. False means the
	// target held the record and got an update.
	Created bool
	// Err says why the push failed. Nil means it succeeded.
	Err error
}

// Report is the outcome at every target, in target order.
type Report struct {
	Results []Result
}

// OK reports whether every target took the record.
func (r Report) OK() bool { return len(r.Failed()) == 0 }

// Failed returns the results with an error.
func (r Report) Failed() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Err != nil {
			out = append(out, res)
		}
	}
	return out
}

// String summarizes the report in one line for a log or an audit record.
func (r Report) String() string {
	failed := r.Failed()
	if len(failed) == 0 {
		return fmt.Sprintf("pushed to %d of %d targets", len(r.Results), len(r.Results))
	}
	parts := make([]string, 0, len(failed))
	for _, f := range failed {
		parts = append(parts, f.Target.Pair+": "+f.Err.Error())
	}
	return fmt.Sprintf("pushed to %d of %d targets; failed %s", len(r.Results)-len(failed), len(r.Results), strings.Join(parts, "; "))
}

// Snapshot gives the fan out the state of every peer.
type Snapshot func(ctx context.Context) topology.Snapshot

// Options configure a FanOut.
type Options struct {
	// Snapshot returns the current topology. Required.
	Snapshot Snapshot
	// Client calls the auth services. Nil means a client with Timeout.
	Client connect.HTTPClient
	// Timeout bounds one call when Client is nil. Zero means
	// DefaultTimeout.
	Timeout time.Duration
}

// FanOut pushes provider records to the auth services.
type FanOut struct {
	opts Options
}

// New returns a fan out. It checks the required options.
func New(opts Options) (*FanOut, error) {
	if opts.Snapshot == nil {
		return nil, errors.New("fanout: a topology snapshot is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	}
	return &FanOut{opts: opts}, nil
}

// Targets lists the live pairs a record names, in snapshot order: the
// pairs whose role is one of roles and whose stack is one of stacks,
// with an auth service URL. Empty stacks means every stack. Empty roles
// means no target. The admin role has no auth service, so it is never
// a target.
func Targets(snap topology.Snapshot, roles []string, stacks []string) []Target {
	var out []Target
	for _, status := range snap.Peers {
		peer := status.Peer
		if status.State != topology.Live || peer.Auth() == "" {
			continue
		}
		if !contains(roles, roleName(peer.Role)) {
			continue
		}
		if len(stacks) > 0 && !contains(stacks, stackName(peer.Dpg)) {
			continue
		}
		out = append(out, Target{Pair: peer.Pair, Role: peer.Role, Dpg: peer.Dpg, AuthURL: peer.Auth()})
	}
	return out
}

// Push sends p to the auth service of every target with token as the
// bearer credential, all targets at once, and reports the outcome at
// each one in target order.
func (f *FanOut) Push(ctx context.Context, token string, p oidcflow.Provider) Report {
	targets := Targets(f.opts.Snapshot(ctx), p.Roles, p.Stacks)
	report := Report{Results: make([]Result, len(targets))}
	var wg sync.WaitGroup
	for i, target := range targets {
		report.Results[i] = Result{Target: target}
		if token == "" {
			report.Results[i].Err = ErrNoToken
			continue
		}
		wg.Add(1)
		go func(i int, target Target) {
			defer wg.Done()
			res := &report.Results[i]
			res.ProviderID, res.Created, res.Err = f.pushOne(ctx, target, token, p)
		}(i, target)
	}
	wg.Wait()
	return report
}

// pushOne creates or updates the record at one target. A record with
// the same discovery URL and client id counts as the same record.
func (f *FanOut) pushOne(ctx context.Context, target Target, token string, p oidcflow.Provider) (string, bool, error) {
	client := adminv1connect.NewAdminServiceClient(f.opts.Client, target.AuthURL)
	list, err := client.ListAuthProviders(ctx, withToken(&adminv1.ListAuthProvidersRequest{}, token))
	if err != nil {
		return "", false, err
	}
	record := oidcflow.ToAdminProto(p)
	for _, held := range list.Msg.GetProviders() {
		if held.GetDiscoveryUrl() == p.DiscoveryURL && held.GetClientId() == p.ClientID {
			record.Id = held.GetId()
			updated, uerr := client.UpdateAuthProvider(ctx, withToken(&adminv1.UpdateAuthProviderRequest{Provider: record}, token))
			if uerr != nil {
				return "", false, uerr
			}
			return updated.Msg.GetProvider().GetId(), false, nil
		}
	}
	record.Id = ""
	created, err := client.CreateAuthProvider(ctx, withToken(&adminv1.CreateAuthProviderRequest{Provider: record}, token))
	if err != nil {
		return "", false, err
	}
	return created.Msg.GetProvider().GetId(), true, nil
}

// withToken wraps a message in a request that carries the token.
func withToken[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

// roleName returns the short name of a role, for example issuer.
func roleName(r commonv1.Role) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "ROLE_"))
}

// stackName returns the short name of a stack, for example waltid.
func stackName(d configv1.Dpg) string {
	return strings.ToLower(strings.TrimPrefix(d.String(), "DPG_"))
}

// contains reports whether list holds want, ignoring case.
func contains(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}
