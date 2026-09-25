// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
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

// fakeIdentity answers the identity RPCs of the adapter and records
// what the pages asked.
type fakeIdentity struct {
	mu        sync.Mutex
	identity  *backendv1.IssuerIdentity
	err       error
	provision []*backendv1.ProvisionIssuerIdentityRequest
	imports   []*backendv1.ImportIssuerIdentityRequest
}

func (f *fakeIdentity) GetIssuerIdentity(context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest]) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&backendv1.GetIssuerIdentityResponse{Identity: f.identity}), nil
}

func (f *fakeIdentity) ProvisionIssuerIdentity(_ context.Context, req *connect.Request[backendv1.ProvisionIssuerIdentityRequest]) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.provision = append(f.provision, req.Msg)
	did := "did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js"
	if req.Msg.GetMethod() == "did:web" {
		did = "did:web:" + strings.ReplaceAll(req.Msg.GetDomain(), ":", "%3A")
	}
	f.identity = &backendv1.IssuerIdentity{
		Identifiers: []string{did}, Key: &backendv1.IssuerIdentity_Key{Type: req.Msg.GetKeyType(), Backend: "jwk"},
		Metadata:    &backendv1.IssuerIdentity_Metadata{DisplayName: req.Msg.GetDisplayName()},
		DidDocument: `{"id":"` + did + `"}`,
	}
	return connect.NewResponse(&backendv1.ProvisionIssuerIdentityResponse{Identity: f.identity}), nil
}

func (f *fakeIdentity) ImportIssuerIdentity(_ context.Context, req *connect.Request[backendv1.ImportIssuerIdentityRequest]) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.imports = append(f.imports, req.Msg)
	id := &backendv1.IssuerIdentity{Key: &backendv1.IssuerIdentity_Key{Backend: "tse"},
		Metadata: &backendv1.IssuerIdentity_Metadata{DisplayName: req.Msg.GetDisplayName(), LegalIdentifier: req.Msg.GetLegalIdentifier()}}
	switch s := req.Msg.GetSubject().(type) {
	case *backendv1.ImportIssuerIdentityRequest_Did:
		id.Identifiers = []string{s.Did}
	case *backendv1.ImportIssuerIdentityRequest_X509ChainPem:
		id.Identifiers = []string{"CN=Issuer One,O=Ministry of Agriculture,C=KE"}
		id.X5C = []string{"MIIB"}
	}
	f.identity = id
	return connect.NewResponse(&backendv1.ImportIssuerIdentityResponse{Identity: id}), nil
}

// fakeTrust stands in for the trust registry of the admin pair.
type fakeTrust struct {
	mu      sync.Mutex
	entries map[string]*trustv1.TrustEntry
	actors  []string
	err     error
}

func key(id *trustv1.TrustEntry_Identifier) string { return id.GetDid() + id.GetX509Subject() }

func (f *fakeTrust) GetEntry(_ context.Context, req *connect.Request[trustv1.GetEntryRequest]) (*connect.Response[trustv1.GetEntryResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	e, ok := f.entries[key(req.Msg.GetIdentifier())]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no entry"))
	}
	return connect.NewResponse(&trustv1.GetEntryResponse{Entry: e}), nil
}

func (f *fakeTrust) UpsertEntry(_ context.Context, req *connect.Request[trustv1.UpsertEntryRequest]) (*connect.Response[trustv1.UpsertEntryResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	if f.entries == nil {
		f.entries = map[string]*trustv1.TrustEntry{}
	}
	f.entries[key(req.Msg.GetEntry().GetIdentifier())] = req.Msg.GetEntry()
	return connect.NewResponse(&trustv1.UpsertEntryResponse{Entry: req.Msg.GetEntry()}), nil
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
	caps     *fakeCapability
	schemas  *fakeSchemas
	issued   *fakeIssued
	identity *fakeIdentity
	trust    *fakeTrust
	trustURL string
	audit    *auditlog.Log
	snap     topology.Snapshot
	peers    []topology.Peer
	opts     pages.Options
	pages    *pages.Pages
	mux      *http.ServeMux
}

// newHarness builds the pages of the first issuer pair, with the second
// issuer pair live and the third issuer pair starting.
func newHarness(t *testing.T, features ...backendv1.Feature) *harness {
	t.Helper()
	h := &harness{
		caps:     &fakeCapability{caps: issuerCaps(waltidName, features...)},
		schemas:  &fakeSchemas{},
		issued:   &fakeIssued{},
		identity: &fakeIdentity{},
		trust:    &fakeTrust{},
		trustURL: "http://admin-first-trust-registry:8080",
	}
	h.caps.caps.DidMethods = []string{"did:web", "did:key", "did:jwk"}
	h.caps.caps.KeyTypes = []string{"Ed25519", "secp256r1"}
	log, err := auditlog.New(store.Memory(), func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	h.audit = log
	waltid := peerOf(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID, nil)
	inji := peerOf(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_INJI, nil)
	credebl := peerOf(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_CREDEBL, nil)
	admin := peerOf(commonv1.Role_ROLE_ADMIN, configv1.Dpg_DPG_WALTID, map[string]string{"admin": "http://admin:8093", "trust-registry": h.trustURL})
	h.peers = []topology.Peer{waltid, inji, credebl, admin}
	h.snap = topology.Snapshot{Peers: []topology.Status{
		{Peer: waltid, State: topology.Live, Capabilities: h.caps.caps},
		{Peer: inji, State: topology.Live, Capabilities: issuerCaps(injiName)},
		{Peer: credebl, State: topology.Starting},
		{Peer: admin, State: topology.Live},
	}}
	h.opts = pages.Options{
		Capability: h.caps, Schemas: h.schemas, Issued: h.issued, Identity: h.identity, Audit: h.audit,
		Trust: func(url string) pages.Trust {
			if url != h.trustURL {
				t.Errorf("trust registry %q, want %q", url, h.trustURL)
			}
			return h.trust
		},
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

// fixedNow is the clock of the pages.
var fixedNow = time.Date(2026, 9, 25, 9, 30, 0, 0, time.UTC)

// withoutAdmin drops the admin pair from the deployment.
func (h *harness) withoutAdmin(t *testing.T) {
	t.Helper()
	h.snap.Peers = h.snap.Peers[:3]
	h.build(t)
}

// post answers one form POST as a signed in staff member.
func (h *harness) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(t, r)
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
