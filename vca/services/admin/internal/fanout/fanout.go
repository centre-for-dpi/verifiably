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
	// Restored says whether a removal gave the target back the record
	// that the push of the removed provider had updated.
	Restored bool
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
	// Ledger keeps, per provider, the pairs that took it and the record
	// a push updated, so a removal can undo the push. Nil keeps the
	// ledger in memory.
	Ledger oidcflow.Persister
}

// ledgerDoc names the persisted ledger document.
const ledgerDoc = "provider-pushes"

// pushed is what one pair holds of one admin provider: the id of the
// record at the pair and, when the first push updated a record the pair
// held already, that record as it was.
type pushed struct {
	HeldID   string             `json:"held_id"`
	Replaced *oidcflow.Provider `json:"replaced,omitempty"`
}

// ledger maps an admin provider id to the pairs that hold it.
type ledger map[string]map[string]pushed

// FanOut pushes provider records to the auth services.
type FanOut struct {
	opts Options
	mu   sync.Mutex
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
	if opts.Ledger == nil {
		opts.Ledger = oidcflow.NewMemoryPersister()
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
// each one in target order. The ledger remembers each pair that took
// the record and the record a first push updated.
func (f *FanOut) Push(ctx context.Context, token string, p oidcflow.Provider) Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	book, err := f.load()
	targets := Targets(f.opts.Snapshot(ctx), p.Roles, p.Stacks)
	report := Report{Results: make([]Result, len(targets))}
	held := book[p.ID]
	replaced := make([]*oidcflow.Provider, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		report.Results[i] = Result{Target: target}
		switch {
		case err != nil:
			report.Results[i].Err = err
			continue
		case token == "":
			report.Results[i].Err = ErrNoToken
			continue
		}
		wg.Add(1)
		go func(i int, target Target, prior pushed) {
			defer wg.Done()
			res := &report.Results[i]
			res.ProviderID, res.Created, replaced[i], res.Err = f.pushOne(ctx, target, token, p, prior)
		}(i, target, held[target.Pair])
	}
	wg.Wait()
	if err != nil {
		return report
	}
	entry := book[p.ID]
	if entry == nil {
		entry = map[string]pushed{}
	}
	for i, res := range report.Results {
		if res.Err != nil {
			continue
		}
		prior, ok := entry[res.Target.Pair]
		if !ok {
			prior.Replaced = replaced[i]
		}
		prior.HeldID = res.ProviderID
		entry[res.Target.Pair] = prior
	}
	if len(entry) > 0 {
		book[p.ID] = entry
		if serr := f.opts.Ledger.Save(ledgerDoc, book); serr != nil {
			for i := range report.Results {
				if report.Results[i].Err == nil {
					report.Results[i].Err = serr
				}
			}
		}
	}
	return report
}

// load reads the ledger.
func (f *FanOut) load() (ledger, error) {
	book := ledger{}
	if err := f.opts.Ledger.Load(ledgerDoc, &book); err != nil {
		return nil, fmt.Errorf("fanout: read the push ledger: %w", err)
	}
	if book == nil {
		book = ledger{}
	}
	return book, nil
}

// pushOne creates or updates the record at one target. The record the
// ledger names comes first; else a record with the same discovery URL
// and client id counts as the same record. It returns the id at the
// target, whether the push made the record, and the record it updated
// when the ledger named none.
func (f *FanOut) pushOne(ctx context.Context, target Target, token string, p oidcflow.Provider, prior pushed) (string, bool, *oidcflow.Provider, error) {
	client := adminv1connect.NewAdminServiceClient(f.opts.Client, target.AuthURL)
	list, err := client.ListAuthProviders(ctx, withToken(&adminv1.ListAuthProvidersRequest{}, token))
	if err != nil {
		return "", false, nil, err
	}
	record := oidcflow.ToAdminProto(p)
	held, known := find(list.Msg.GetProviders(), p, prior.HeldID)
	if held != nil {
		record.Id = held.GetId()
		updated, uerr := client.UpdateAuthProvider(ctx, withToken(&adminv1.UpdateAuthProviderRequest{Provider: record}, token))
		if uerr != nil {
			return "", false, nil, uerr
		}
		var replaced *oidcflow.Provider
		if !known {
			was := oidcflow.FromAdminProto(held)
			replaced = &was
		}
		return updated.Msg.GetProvider().GetId(), false, replaced, nil
	}
	record.Id = ""
	created, err := client.CreateAuthProvider(ctx, withToken(&adminv1.CreateAuthProviderRequest{Provider: record}, token))
	if err != nil {
		return "", false, nil, err
	}
	return created.Msg.GetProvider().GetId(), true, nil, nil
}

// find returns the record of the list that stands for p: the one with
// the id the ledger names, else the one with the discovery URL and the
// client id of p. It reports whether the ledger named it.
func find(list []*adminv1.AuthProvider, p oidcflow.Provider, heldID string) (*adminv1.AuthProvider, bool) {
	if heldID != "" {
		for _, held := range list {
			if held.GetId() == heldID {
				return held, true
			}
		}
	}
	for _, held := range list {
		if held.GetDiscoveryUrl() == p.DiscoveryURL && held.GetClientId() == p.ClientID {
			return held, false
		}
	}
	return nil, false
}

// Remove takes p off every live pair that took it or that it names. A
// pair whose record a first push updated gets that record back, so a
// pair never loses its setup record to a provider the admin removed. A
// pair the ledger does not name loses a matching record, except its
// setup record, which nothing can restore. The ledger forgets the pairs
// that answered.
func (f *FanOut) Remove(ctx context.Context, token string, p oidcflow.Provider) Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	book, err := f.load()
	snap := f.opts.Snapshot(ctx)
	held := book[p.ID]
	targets := Targets(snap, p.Roles, p.Stacks)
	for _, t := range Targets(snap, allRoles(snap), nil) {
		if _, ok := held[t.Pair]; ok && !hasPair(targets, t.Pair) {
			targets = append(targets, t)
		}
	}
	report := Report{Results: make([]Result, len(targets))}
	var wg sync.WaitGroup
	for i, target := range targets {
		report.Results[i] = Result{Target: target}
		switch {
		case err != nil:
			report.Results[i].Err = err
			continue
		case token == "":
			report.Results[i].Err = ErrNoToken
			continue
		}
		wg.Add(1)
		go func(i int, target Target, prior pushed) {
			defer wg.Done()
			res := &report.Results[i]
			res.ProviderID, res.Restored, res.Err = f.removeOne(ctx, target, token, p, prior)
		}(i, target, held[target.Pair])
	}
	wg.Wait()
	if err != nil || held == nil {
		return report
	}
	for _, res := range report.Results {
		if res.Err == nil {
			delete(held, res.Target.Pair)
		}
	}
	if len(held) == 0 {
		delete(book, p.ID)
	}
	if serr := f.opts.Ledger.Save(ledgerDoc, book); serr != nil {
		for i := range report.Results {
			if report.Results[i].Err == nil {
				report.Results[i].Err = serr
			}
		}
	}
	return report
}

// removeOne restores or deletes the record of p at one target. It
// returns the id at the target and whether it restored a record.
func (f *FanOut) removeOne(ctx context.Context, target Target, token string, p oidcflow.Provider, prior pushed) (string, bool, error) {
	client := adminv1connect.NewAdminServiceClient(f.opts.Client, target.AuthURL)
	list, err := client.ListAuthProviders(ctx, withToken(&adminv1.ListAuthProvidersRequest{}, token))
	if err != nil {
		return "", false, err
	}
	held, known := find(list.Msg.GetProviders(), p, prior.HeldID)
	switch {
	case held == nil:
		return "", false, nil
	case known && prior.Replaced != nil:
		record := oidcflow.ToAdminProto(*prior.Replaced)
		record.Id = held.GetId()
		if _, uerr := client.UpdateAuthProvider(ctx, withToken(&adminv1.UpdateAuthProviderRequest{Provider: record}, token)); uerr != nil {
			return "", false, uerr
		}
		return held.GetId(), true, nil
	case !known && held.GetId() == oidcflow.SeedID:
		// The setup record without a ledger entry: nothing can restore
		// it, so it stays.
		return "", false, nil
	}
	if _, derr := client.DeleteAuthProvider(ctx, withToken(&adminv1.DeleteAuthProviderRequest{Id: held.GetId()}, token)); derr != nil {
		return "", false, derr
	}
	return held.GetId(), false, nil
}

// allRoles lists the short names of the roles of the snapshot.
func allRoles(snap topology.Snapshot) []string {
	var out []string
	for _, status := range snap.Peers {
		out = append(out, roleName(status.Peer.Role))
	}
	return out
}

// hasPair reports whether targets holds the pair.
func hasPair(targets []Target, pair string) bool {
	for _, t := range targets {
		if t.Pair == pair {
			return true
		}
	}
	return false
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
