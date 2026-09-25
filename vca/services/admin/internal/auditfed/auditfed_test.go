// SPDX-License-Identifier: Apache-2.0

package auditfed_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/auditfed"
)

var base = time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)

// store is a fake AuditService with fixed events. It checks the token
// and records the requests.
type store struct {
	auditv1connect.UnimplementedAuditServiceHandler
	service string
	events  []*auditv1.AuditEvent
	delay   time.Duration
	fail    error
	mu      sync.Mutex
	seen    []*auditv1.QueryRequest
	days    int32
}

func (s *store) check(h http.Header) error {
	if h.Get("Authorization") != "Bearer admin-session" {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("no admin session"))
	}
	return s.fail
}

func (s *store) Query(ctx context.Context, req *connect.Request[auditv1.QueryRequest]) (*connect.Response[auditv1.QueryResponse], error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := s.check(req.Header()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.seen = append(s.seen, req.Msg)
	s.mu.Unlock()
	var out []*auditv1.AuditEvent
	for _, e := range s.events {
		if a := req.Msg.GetAction(); a != "" && e.GetAction() != a {
			continue
		}
		if to := req.Msg.GetTo(); to != nil && e.GetTime().AsTime().After(to.AsTime()) {
			continue
		}
		c := proto.CloneOf(e)
		c.SourceService = s.service
		out = append(out, c)
	}
	size := int(req.Msg.GetPage().GetPageSize())
	page := &commonv1.PageResult{TotalSize: int64(len(out))}
	if size > 0 && len(out) > size {
		out, page.NextPageToken = out[:size], "more"
	}
	return connect.NewResponse(&auditv1.QueryResponse{Events: out, Page: page}), nil
}

func (s *store) SetRetention(_ context.Context, req *connect.Request[auditv1.SetRetentionRequest]) (*connect.Response[auditv1.SetRetentionResponse], error) {
	if err := s.check(req.Header()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.days = req.Msg.GetDays()
	s.mu.Unlock()
	return connect.NewResponse(&auditv1.SetRetentionResponse{Days: req.Msg.GetDays(), Removed: 2}), nil
}

func serveStore(t *testing.T, s *store) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(auditv1connect.NewAuditServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func ev(minutes int, action, actor string) *auditv1.AuditEvent {
	return &auditv1.AuditEvent{
		Id: action + actor, Time: timestamppb.New(base.Add(time.Duration(minutes) * time.Minute)),
		Action: action, Actor: actor, Outcome: auditv1.Outcome_OUTCOME_SUCCESS,
	}
}

func caps(name string) *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: name}}
}

// deployment is this admin pair with its trust registry, a live issuer
// pair, a live verifier pair, and a starting holder pair.
type deployment struct {
	snap    topology.Snapshot
	local   *store
	trust   *store
	auth    *store
	issued  *store
	results *store
}

func newDeployment(t *testing.T) *deployment {
	t.Helper()
	d := &deployment{
		local:   &store{service: "admin", events: []*auditv1.AuditEvent{ev(5, "admin.CreateTenant", "kc|root")}},
		trust:   &store{service: "trust-registry", events: []*auditv1.AuditEvent{ev(6, "trust.UpsertEntry", "kc|root")}},
		auth:    &store{service: "issuer-auth", events: []*auditv1.AuditEvent{ev(1, "auth.Login", "kc|ada"), ev(9, "auth.Logout", "kc|ada")}},
		issued:  &store{service: "issued-credentials", events: []*auditv1.AuditEvent{ev(7, "issued.Revoke", "kc|ada")}},
		results: &store{service: "verifier-results", events: []*auditv1.AuditEvent{ev(3, "results.Store", "")}},
	}
	peer := func(pair string, role commonv1.Role, dpg configv1.Dpg, public string, services map[string]string) topology.Peer {
		return topology.Peer{Pair: pair, Role: role, Dpg: dpg, PublicURL: public, Services: services}
	}
	d.snap = topology.Snapshot{Peers: []topology.Status{
		{State: topology.Live, Capabilities: caps("walt.id Community Stack"), Peer: peer("admin-waltid", commonv1.Role_ROLE_ADMIN, configv1.Dpg_DPG_WALTID,
			"https://admin.vca.example", map[string]string{"admin": "http://admin.invalid", "trust-registry": serveStore(t, d.trust)})},
		{State: topology.Live, Capabilities: caps("walt.id Community Stack"), Peer: peer("issuer-waltid", commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID,
			"https://issuer.vca.example", map[string]string{
				"issuer-auth": serveStore(t, d.auth), "issued-credentials": serveStore(t, d.issued), "schema-registry": "http://schemas.invalid",
			})},
		{State: topology.Live, Capabilities: caps("MOSIP Inji"), Peer: peer("verifier-inji", commonv1.Role_ROLE_VERIFIER, configv1.Dpg_DPG_INJI,
			"https://verifier.vca.example", map[string]string{"verifier-results": serveStore(t, d.results)})},
		{State: topology.Starting, Peer: peer("holder-credebl", commonv1.Role_ROLE_HOLDER, configv1.Dpg_DPG_CREDEBL,
			"https://holder.vca.example", map[string]string{"wallet-auth": "http://wallet.invalid"})},
	}}
	return d
}

func (d *deployment) federation(t *testing.T, budget time.Duration) *auditfed.Federation {
	t.Helper()
	f, err := auditfed.New(auditfed.Options{
		Snapshot: func(context.Context) topology.Snapshot { return d.snap },
		Local:    d.local, Self: "https://admin.vca.example/", Budget: budget,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNewNeedsTheLocalStore(t *testing.T) {
	if _, err := auditfed.New(auditfed.Options{}); err == nil {
		t.Fatal("New took no local store")
	}
}

func TestSourcesListTheLiveServicesAndSkipThisAdmin(t *testing.T) {
	d := newDeployment(t)
	self, sources := auditfed.Sources(d.snap, "https://admin.vca.example")
	if self.Pair != "admin-waltid" || self.Stack != "walt.id Community Stack" || self.Service != "admin" {
		t.Fatalf("self = %+v", self)
	}
	var got []string
	for _, s := range sources {
		got = append(got, s.Pair+"/"+s.Service+"/"+s.Stack)
	}
	want := "admin-waltid/trust-registry/walt.id Community Stack issuer-waltid/issuer-auth/walt.id Community Stack " +
		"issuer-waltid/issued-credentials/walt.id Community Stack verifier-inji/verifier-results/MOSIP Inji"
	if strings.Join(got, " ") != want {
		t.Fatalf("sources = %q", strings.Join(got, " "))
	}
	if _, none := auditfed.Sources(topology.Snapshot{}, ""); len(none) != 0 {
		t.Fatal("an empty snapshot gave sources")
	}
}

// TestQueryMergesInTimeOrder merges this store and every live peer,
// newest first, and fills the pair of each event.
func TestQueryMergesInTimeOrder(t *testing.T) {
	d := newDeployment(t)
	res := d.federation(t, time.Second).Query(context.Background(), "admin-session", auditfed.Filter{}, 50)
	if len(res.Failed) != 0 {
		t.Fatalf("failed = %+v", res.Failed)
	}
	var got []string
	for _, e := range res.Events {
		got = append(got, e.GetAction()+"@"+e.GetPair())
	}
	want := "auth.Logout@issuer-waltid issued.Revoke@issuer-waltid trust.UpsertEntry@admin-waltid admin.CreateTenant@admin-waltid " +
		"results.Store@verifier-inji auth.Login@issuer-waltid"
	if strings.Join(got, " ") != want {
		t.Fatalf("order = %q", strings.Join(got, " "))
	}
	if res.More || res.Asked != 5 {
		t.Fatalf("more = %v asked = %d", res.More, res.Asked)
	}
	if len(res.Sources) != 5 || res.Sources[0].Service != "admin" {
		t.Fatalf("sources = %+v", res.Sources)
	}
}

func TestQueryPassesTheFiltersAndCutsTheList(t *testing.T) {
	d := newDeployment(t)
	f := d.federation(t, time.Second)
	res := f.Query(context.Background(), "admin-session", auditfed.Filter{
		Action: "auth.Login", Actor: "kc|ada", Outcome: auditv1.Outcome_OUTCOME_SUCCESS,
		From: base, To: base.Add(time.Hour),
	}, 50)
	if len(res.Events) != 1 || res.Events[0].GetAction() != "auth.Login" {
		t.Fatalf("events = %+v", res.Events)
	}
	q := d.auth.seen[len(d.auth.seen)-1]
	if q.GetActor() != "kc|ada" || q.GetOutcome() != auditv1.Outcome_OUTCOME_SUCCESS || !q.GetFrom().AsTime().Equal(base) || q.GetPage().GetPageSize() != 50 {
		t.Fatalf("query = %+v", q)
	}
	cut := f.Query(context.Background(), "admin-session", auditfed.Filter{}, 2)
	if len(cut.Events) != 2 || !cut.More {
		t.Fatalf("cut = %d more = %v", len(cut.Events), cut.More)
	}
	older := f.Query(context.Background(), "admin-session", auditfed.Filter{Before: cut.Events[1].GetTime().AsTime()}, 50)
	if len(older.Events) != 4 || older.Events[0].GetAction() != "trust.UpsertEntry" {
		t.Fatalf("older = %+v", older.Events)
	}
}

func TestQueryFiltersBySourceService(t *testing.T) {
	d := newDeployment(t)
	f := d.federation(t, time.Second)
	res := f.Query(context.Background(), "admin-session", auditfed.Filter{Service: "issuer-auth"}, 50)
	if len(res.Events) != 2 || res.Asked != 1 {
		t.Fatalf("events = %d asked = %d", len(res.Events), res.Asked)
	}
	own := f.Query(context.Background(), "admin-session", auditfed.Filter{Service: "admin"}, 50)
	if len(own.Events) != 1 || own.Asked != 1 {
		t.Fatalf("own = %d asked = %d", len(own.Events), own.Asked)
	}
}

// TestQueryNamesAPeerThatDoesNotAnswer keeps the page when a peer is
// slow or refuses, and names the peer.
func TestQueryNamesAPeerThatDoesNotAnswer(t *testing.T) {
	d := newDeployment(t)
	d.issued.delay = 2 * time.Second
	d.results.fail = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	start := time.Now()
	res := d.federation(t, 200*time.Millisecond).Query(context.Background(), "admin-session", auditfed.Filter{}, 50)
	if time.Since(start) > time.Second {
		t.Fatalf("the query took %s, beyond the budget", time.Since(start))
	}
	if len(res.Failed) != 2 {
		t.Fatalf("failed = %+v", res.Failed)
	}
	named := map[string]bool{}
	for _, f := range res.Failed {
		named[f.Source.Pair+"/"+f.Source.Service] = f.Err != nil
	}
	if !named["issuer-waltid/issued-credentials"] || !named["verifier-inji/verifier-results"] {
		t.Fatalf("named = %v", named)
	}
	if len(res.Events) != 4 {
		t.Fatalf("events = %d", len(res.Events))
	}
}

func TestQueryReportsTheLocalStore(t *testing.T) {
	d := newDeployment(t)
	res := d.federation(t, time.Second).Query(context.Background(), "someone", auditfed.Filter{}, 50)
	if len(res.Failed) != 5 || res.Failed[0].Source.Service != "admin" {
		t.Fatalf("failed = %+v", res.Failed)
	}
}

// TestSetRetentionReachesEveryStore sets the retention in this store
// and in every live peer, and names a peer that does not take it.
func TestSetRetentionReachesEveryStore(t *testing.T) {
	d := newDeployment(t)
	d.results.fail = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	res := d.federation(t, time.Second).SetRetention(context.Background(), "admin-session", 90)
	if res.Asked != 5 || len(res.Failed) != 1 || res.Failed[0].Source.Service != "verifier-results" || res.Removed != 8 {
		t.Fatalf("result = %+v", res)
	}
	for _, s := range []*store{d.local, d.trust, d.auth, d.issued} {
		if s.days != 90 {
			t.Errorf("%s days = %d", s.service, s.days)
		}
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	events := []*auditv1.AuditEvent{
		{Time: timestamppb.New(base), Actor: "kc|root", Action: "trust.UpsertEntry", Target: "did:web:moh.example",
			Outcome: auditv1.Outcome_OUTCOME_SUCCESS, Detail: "The entry is active now.", RequestId: "r1", SourceService: "trust-registry", Pair: "admin-waltid"},
		{Time: timestamppb.New(base), Actor: "=cmd()", Action: "auth.Login", Outcome: auditv1.Outcome_OUTCOME_FAILURE, Detail: "a, b"},
	}
	if err := auditfed.WriteCSV(&buf, events); err != nil {
		t.Fatal(err)
	}
	want := "time,pair,service,actor,action,target,outcome,detail,request_id\n" +
		"2026-09-25T08:00:00Z,admin-waltid,trust-registry,kc|root,trust.UpsertEntry,did:web:moh.example,success,The entry is active now.,r1\n" +
		"2026-09-25T08:00:00Z,,,'=cmd(),auth.Login,,failure,\"a, b\",\n"
	if buf.String() != want {
		t.Fatalf("csv =\n%s\nwant\n%s", buf.String(), want)
	}
	if err := auditfed.WriteCSV(failWriter{}, events); err == nil {
		t.Error("WriteCSV hid a write error")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
