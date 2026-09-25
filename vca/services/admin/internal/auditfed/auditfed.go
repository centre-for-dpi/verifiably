// SPDX-License-Identifier: Apache-2.0

// Package auditfed merges the audit stores of a deployment for the admin
// audit page (ADR-039 decision 2). The admin keeps its own store. Every
// live peer serves its stores as vca.audit.v1.AuditService, one per
// service that records changes. The package asks this store and every
// live peer at once with the admin session token, within one time
// budget, and merges the answers in time order. A peer that does not
// answer is named in the result, so the page shows the rest.
//
// No service reads the store of another (ADR-039 consequence 2): the
// package reads each store through its own service.
package auditfed

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

// DefaultBudget bounds the time one page waits for every store.
const DefaultBudget = 3 * time.Second

// LocalService names the store of this admin service.
const LocalService = "admin"

// Services lists the services that serve an audit store, in the order
// the page lists them (ADR-039 decision 1).
var Services = []string{
	LocalService, "issuer-auth", "wallet-auth", "verifier-auth",
	"issuance", "issued-credentials", "trust-registry", "verifier-results",
}

// Source is one audit store of the deployment.
type Source struct {
	// Pair is the pair of the service, for example issuer-waltid.
	Pair string
	// Role is the role of the pair.
	Role commonv1.Role
	// Dpg is the stack of the pair.
	Dpg configv1.Dpg
	// Stack is the display name the adapter of the stack reports, or the
	// short name of the stack until an adapter answers.
	Stack string
	// Service is the service that keeps the store.
	Service string
	// URL is the internal URL of the service. It is empty for the store
	// of this admin service.
	URL string
}

// Failure is a store that did not answer, with the reason.
type Failure struct {
	Source Source
	Err    error
}

// Filter selects events. An empty field filters nothing.
type Filter struct {
	// From and To bound the time, both inclusive.
	From, To time.Time
	// Before takes only events older than it. The page uses it to show
	// the next events.
	Before time.Time
	// Actor and Action match exactly.
	Actor, Action string
	// Outcome is the outcome filter.
	Outcome auditv1.Outcome
	// Service takes the stores of one service only.
	Service string
}

// Result is the merged answer.
type Result struct {
	// Events are the events, newest first, at most the limit.
	Events []*auditv1.AuditEvent
	// Sources are the stores the query asked, this store first.
	Sources []Source
	// Asked is the number of stores the query asked.
	Asked int
	// Failed names each store that did not answer.
	Failed []Failure
	// More reports that older events match the filter.
	More bool
}

// RetentionResult is the answer of SetRetention.
type RetentionResult struct {
	// Asked is the number of stores the call reached for.
	Asked int
	// Removed is the number of events the stores removed.
	Removed int64
	// Failed names each store that did not take the setting.
	Failed []Failure
}

// Options configure a Federation.
type Options struct {
	// Snapshot returns the state of every peer. Nil means no peer.
	Snapshot func(ctx context.Context) topology.Snapshot
	// Local serves the store of this admin service. Required.
	Local auditv1connect.AuditServiceClient
	// Self is the public URL of this admin pair. The pair with this URL
	// is this pair, so the query does not ask its admin service twice.
	Self string
	// Client calls the peers. Nil means a client that waits no longer
	// than the budget.
	Client connect.HTTPClient
	// Budget bounds one query of every store. Zero means DefaultBudget.
	Budget time.Duration
}

// Federation queries every audit store of a deployment.
type Federation struct {
	opts Options
}

// New returns a federation. It checks the options.
func New(opts Options) (*Federation, error) {
	if opts.Local == nil {
		return nil, errors.New("auditfed: the local audit store is required")
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Budget}
	}
	opts.Self = strings.TrimRight(opts.Self, "/")
	return &Federation{opts: opts}, nil
}

// Sources returns the source of this admin store and every audit store
// of a live peer, in snapshot order. The admin service of this pair is
// the local store, so the list leaves it out.
func Sources(snap topology.Snapshot, self string) (Source, []Source) {
	self = strings.TrimRight(self, "/")
	local := Source{Service: LocalService, Role: commonv1.Role_ROLE_ADMIN}
	var out []Source
	for _, st := range snap.Live() {
		peer := st.Peer
		mine := peer.Role == commonv1.Role_ROLE_ADMIN && strings.TrimRight(peer.PublicURL, "/") == self
		stack := stackName(snap, peer.Dpg)
		if mine {
			local.Pair, local.Dpg, local.Stack = peer.Pair, peer.Dpg, stack
		}
		for _, name := range Services {
			target := peer.Services[name]
			if target == "" || (mine && name == LocalService) {
				continue
			}
			out = append(out, Source{Pair: peer.Pair, Role: peer.Role, Dpg: peer.Dpg, Stack: stack, Service: name, URL: target})
		}
	}
	return local, out
}

// stackName returns the name the first live adapter of a stack reports,
// or the short name of the stack.
func stackName(snap topology.Snapshot, d configv1.Dpg) string {
	for _, st := range snap.Live() {
		if st.Peer.Dpg == d {
			if name := st.Capabilities.GetDpgInfo().GetDisplayName(); name != "" {
				return name
			}
		}
	}
	return strings.ToLower(strings.TrimPrefix(d.String(), "DPG_"))
}

// sources returns the stores one filter asks, this store first.
func (f *Federation) sources(ctx context.Context, service string) []Source {
	var snap topology.Snapshot
	if f.opts.Snapshot != nil {
		snap = f.opts.Snapshot(ctx)
	}
	local, peers := Sources(snap, f.opts.Self)
	all := append([]Source{local}, peers...)
	if service == "" {
		return all
	}
	var out []Source
	for _, s := range all {
		if s.Service == service {
			out = append(out, s)
		}
	}
	return out
}

// client returns the AuditService client of a source.
func (f *Federation) client(s Source) auditv1connect.AuditServiceClient {
	if s.URL == "" {
		return f.opts.Local
	}
	return auditv1connect.NewAuditServiceClient(f.opts.Client, s.URL)
}

// withToken wraps a message in a request that carries the token.
func withToken[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	return req
}

// request turns a filter into the request each store gets.
func request(fl Filter, limit int) *auditv1.QueryRequest {
	req := &auditv1.QueryRequest{
		Actor: fl.Actor, Action: fl.Action, Outcome: fl.Outcome,
		Page: &commonv1.Pagination{PageSize: int32(limit)}, //nolint:gosec // the page caps the limit far below 2^31
	}
	if !fl.From.IsZero() {
		req.From = timestamppb.New(fl.From)
	}
	to := fl.To
	if !fl.Before.IsZero() {
		if before := fl.Before.Add(-time.Nanosecond); to.IsZero() || before.Before(to) {
			to = before
		}
	}
	if !to.IsZero() {
		req.To = timestamppb.New(to)
	}
	return req
}

// Query asks every store the filter names at once with the admin
// session token, within the budget, and merges the answers newest
// first. It keeps at most limit events.
func (f *Federation) Query(ctx context.Context, token string, fl Filter, limit int) Result {
	ctx, cancel := context.WithTimeout(ctx, f.opts.Budget)
	defer cancel()
	sources := f.sources(ctx, fl.Service)
	req := request(fl, limit)
	type answer struct {
		events []*auditv1.AuditEvent
		more   bool
		err    error
	}
	answers := make([]answer, len(sources))
	var wg sync.WaitGroup
	for i, s := range sources {
		wg.Add(1)
		go func(i int, s Source) {
			defer wg.Done()
			res, err := f.client(s).Query(ctx, withToken(req, token))
			if err != nil {
				answers[i].err = err
				return
			}
			for _, e := range res.Msg.GetEvents() {
				if e.GetSourceService() == "" {
					e.SourceService = s.Service
				}
				if e.GetPair() == "" {
					e.Pair = s.Pair
				}
			}
			answers[i] = answer{events: res.Msg.GetEvents(), more: res.Msg.GetPage().GetNextPageToken() != ""}
		}(i, s)
	}
	wg.Wait()
	out := Result{Sources: sources, Asked: len(sources)}
	var lists [][]*auditv1.AuditEvent
	for i, a := range answers {
		if a.err != nil {
			out.Failed = append(out.Failed, Failure{Source: sources[i], Err: a.err})
			continue
		}
		out.More = out.More || a.more
		lists = append(lists, a.events)
	}
	out.Events = Merge(lists...)
	if limit > 0 && len(out.Events) > limit {
		out.Events, out.More = out.Events[:limit], true
	}
	return out
}

// SetRetention sets the retention days in this store and in every store
// of a live peer at once, within the budget.
func (f *Federation) SetRetention(ctx context.Context, token string, days int32) RetentionResult {
	ctx, cancel := context.WithTimeout(ctx, f.opts.Budget)
	defer cancel()
	sources := f.sources(ctx, "")
	removed := make([]int64, len(sources))
	errs := make([]error, len(sources))
	var wg sync.WaitGroup
	for i, s := range sources {
		wg.Add(1)
		go func(i int, s Source) {
			defer wg.Done()
			res, err := f.client(s).SetRetention(ctx, withToken(&auditv1.SetRetentionRequest{Days: days}, token))
			if err != nil {
				errs[i] = err
				return
			}
			removed[i] = res.Msg.GetRemoved()
		}(i, s)
	}
	wg.Wait()
	out := RetentionResult{Asked: len(sources)}
	for i, err := range errs {
		if err != nil {
			out.Failed = append(out.Failed, Failure{Source: sources[i], Err: err})
			continue
		}
		out.Removed += removed[i]
	}
	return out
}

// Merge returns the events of every list, newest first. Two events of
// the same time sort by pair, service, and id, so the order is stable.
func Merge(lists ...[]*auditv1.AuditEvent) []*auditv1.AuditEvent {
	var out []*auditv1.AuditEvent
	for _, l := range lists {
		out = append(out, l...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ta, tb := a.GetTime().AsTime(), b.GetTime().AsTime()
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
		if a.GetPair() != b.GetPair() {
			return a.GetPair() < b.GetPair()
		}
		if a.GetSourceService() != b.GetSourceService() {
			return a.GetSourceService() < b.GetSourceService()
		}
		return a.GetId() < b.GetId()
	})
	return out
}

// OutcomeName returns success, failure, or an empty string.
func OutcomeName(o auditv1.Outcome) string {
	switch o {
	case auditv1.Outcome_OUTCOME_SUCCESS:
		return "success"
	case auditv1.Outcome_OUTCOME_FAILURE:
		return "failure"
	default:
		return ""
	}
}

// csvHeader names the columns of the export.
var csvHeader = []string{"time", "pair", "service", "actor", "action", "target", "outcome", "detail", "request_id"}

// WriteCSV writes the events as RFC 4180 CSV with a header row. A cell
// that a spreadsheet would read as a formula gets a leading quote.
func WriteCSV(w io.Writer, events []*auditv1.AuditEvent) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, e := range events {
		row := []string{
			e.GetTime().AsTime().UTC().Format(time.RFC3339Nano), e.GetPair(), e.GetSourceService(),
			e.GetActor(), e.GetAction(), e.GetTarget(), OutcomeName(e.GetOutcome()), e.GetDetail(), e.GetRequestId(),
		}
		for i, cell := range row {
			row[i] = safeCell(cell)
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// safeCell puts a quote before a cell that starts like a formula.
func safeCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
