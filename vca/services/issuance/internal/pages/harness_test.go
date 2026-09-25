// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Stack names the adapters report. The tests hold no vendor name
// (ADR-001 decision 4).
const (
	waltidName = "First stack"
	injiName   = "Second stack"
)

// fakeCapability answers as the adapter of the own pair.
type fakeCapability struct {
	caps *backendv1.GetCapabilitiesResponse
}

func (f *fakeCapability) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(f.caps), nil
}

// fakeSchemas answers SchemaService.List with a fixed count per state.
type fakeSchemas struct {
	published []*schemav1.Schema
	err       error
}

func (f *fakeSchemas) List(_ context.Context, req *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []*schemav1.Schema
	if st := req.Msg.GetState(); st == schemav1.State_STATE_PUBLISHED || st == schemav1.State_STATE_UNSPECIFIED {
		out = f.published
	}
	return connect.NewResponse(&schemav1.ListResponse{Schemas: out, Page: &commonv1.PageResult{TotalSize: int64(len(out))}}), nil
}

// fakeIssued answers IssuedService.List and records the actor header.
type fakeIssued struct {
	mu     sync.Mutex
	total  int64
	actors []string
	err    error
}

func (f *fakeIssued) List(_ context.Context, req *connect.Request[issuedv1.ListRequest]) (*connect.Response[issuedv1.ListResponse], error) {
	f.mu.Lock()
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&issuedv1.ListResponse{Page: &commonv1.PageResult{TotalSize: f.total}}), nil
}

// issuerCaps is the answer of an issuer adapter with the features
// the test names.
func issuerCaps(name string, features ...backendv1.Feature) *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{
		Adapter: "dpg-adapter", Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER},
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE},
		Features: features, DpgInfo: &backendv1.DpgInfo{DisplayName: name},
	}
}

// peerOf returns one pair of the deployment.
func peerOf(role commonv1.Role, dpg configv1.Dpg, services map[string]string) topology.Peer {
	pair := topology.PairName(role, dpg)
	if services == nil {
		services = map[string]string{}
	}
	if auth := topology.AuthService(role); auth != "" {
		services[auth] = "http://" + pair + "-auth:8081"
	}
	return topology.Peer{Pair: pair, Role: role, Dpg: dpg, PublicURL: "https://" + pair + ".labs.example", Services: services}
}

// harness holds the fakes and the pages of one test.
type harness struct {
	caps    *fakeCapability
	schemas *fakeSchemas
	issued  *fakeIssued
	snap    topology.Snapshot
	peers   []topology.Peer
	opts    pages.Options
	pages   *pages.Pages
	mux     *http.ServeMux
}

// newHarness builds the pages of the first issuer pair, with the second
// issuer pair live and the third issuer pair starting.
func newHarness(t *testing.T, features ...backendv1.Feature) *harness {
	t.Helper()
	h := &harness{
		caps:    &fakeCapability{caps: issuerCaps(waltidName, features...)},
		schemas: &fakeSchemas{},
		issued:  &fakeIssued{},
	}
	waltid := peerOf(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID, nil)
	inji := peerOf(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_INJI, nil)
	credebl := peerOf(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL, nil)
	h.peers = []topology.Peer{waltid, inji, credebl}
	h.snap = topology.Snapshot{Peers: []topology.Status{
		{Peer: waltid, State: topology.Live, Capabilities: h.caps.caps},
		{Peer: inji, State: topology.Live, Capabilities: issuerCaps(injiName)},
		{Peer: credebl, State: topology.Starting},
	}}
	h.opts = pages.Options{
		Capability: h.caps, Schemas: h.schemas, Issued: h.issued,
		PublicURL: waltid.PublicURL,
	}
	h.build(t)
	return h
}

// build makes the pages from the options and the snapshot of h.
func (h *harness) build(t *testing.T) {
	t.Helper()
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	h.opts.Kit = kit
	h.opts.Shell = staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_ISSUER, Peers: h.peers,
		Snapshot: func(context.Context) topology.Snapshot { return h.snap },
		JWKSURL:  h.peers[0].Auth() + staffshell.JWKSPath, SignOut: pages.SignOutPath,
	})
	p, err := pages.New(h.opts)
	if err != nil {
		t.Fatal(err)
	}
	h.pages = p
	h.mux = http.NewServeMux()
	p.Register(h.mux)
}

// session is the staff member of every request.
var session = staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", ID: "sid-1", CSRF: "csrf-1"}

// get answers one GET as a signed in staff member.
func (h *harness) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, httptest.NewRequest(http.MethodGet, path, nil))
}

func (h *harness) do(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	r = r.WithContext(staffsession.With(r.Context(), session))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec
}

// body returns the body of a 200 answer.
func body(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
