// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
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
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// stackName is the name the adapter of the pair reports. The tests hold
// no vendor name (ADR-001 decision 4).
const stackName = "First stack"

// fixedNow is the clock of the service.
var fixedNow = time.Date(2026, 9, 25, 9, 30, 0, 0, time.UTC)

// The records of the tests.
const (
	recWanjiku = "3f9a2c71e0b44d5a8c1b2d3e4f506172"
	recOtieno  = "8b1c77d2a0f94e6b9d2c3e4f5a6b7c8d"
	recAmina   = "c4e5f6a7b8c9d0e1f2a3b4c5d6e7f809"
)

// fakeStatus is the status service of VCA. It records each change.
type fakeStatus struct {
	statusv1connect.StatusServiceClient
	mu    sync.Mutex
	calls []*statusv1.SetStatusRequest
	err   error
}

func (f *fakeStatus) SetStatus(_ context.Context, req *connect.Request[statusv1.SetStatusRequest]) (*connect.Response[statusv1.SetStatusResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, req.Msg)
	return connect.NewResponse(&statusv1.SetStatusResponse{}), nil
}

// fakeStack is the DPG adapter of the pair: its features, its revokes,
// and the offers no wallet claimed.
type fakeStack struct {
	mu       sync.Mutex
	features map[backendv1.Feature]bool
	name     string
	revokes  []*backendv1.StatusListBinding
	pending  map[string]bool
	asked    []string
}

func (f *fakeStack) Has(_ context.Context, feature backendv1.Feature) bool {
	return f.features[feature]
}

func (f *fakeStack) Name(context.Context) string { return f.name }

func (f *fakeStack) Revoke(_ context.Context, binding *backendv1.StatusListBinding, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, binding)
	return nil
}

func (f *fakeStack) Pending(_ context.Context, offerID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, offerID)
	return f.pending[offerID]
}

// harness holds the pages of one test over a real service with a memory
// store.
type harness struct {
	svc    *service.Service
	status *fakeStatus
	stack  *fakeStack
	sess   staffsession.Session
	opts   pages.Options
	mux    *http.ServeMux
}

// operator is the staff member of most requests: an issuer operator.
var operator = staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", ID: "sid-1", CSRF: "csrf-1",
	Roles: []string{staffsession.IssuerOperatorRole}}

// viewer is an issuer viewer: it reads and changes nothing.
var viewer = staffsession.Session{Subject: "kc|viewer", Name: "Otieno Viewer", ID: "sid-2", CSRF: "csrf-2", Roles: []string{"issuer-viewer"}}

// newHarness builds the pages of the first issuer pair with three
// records. The features are those the adapter lists.
func newHarness(t *testing.T, features ...backendv1.Feature) *harness {
	t.Helper()
	h := newEmptyHarness(t, features...)
	h.seed(t)
	return h
}

// newEmptyHarness builds the pages over an empty log.
func newEmptyHarness(t *testing.T, features ...backendv1.Feature) *harness {
	t.Helper()
	st, err := store.Open(sharedstore.MemoryDoc())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{status: &fakeStatus{}, stack: &fakeStack{features: map[backendv1.Feature]bool{}, pending: map[string]bool{}, name: stackName}, sess: operator}
	for _, f := range features {
		h.stack.features[f] = true
	}
	h.svc, err = service.New(service.Options{Store: st, Status: h.status, Stack: h.stack, Salt: "pepper", Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	pair := topology.PairName(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	own := topology.Peer{Pair: pair, Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://" + pair + ".labs.example",
		Services: map[string]string{"issuer-auth": "http://" + pair + "-auth:8081"}}
	snap := topology.Snapshot{Peers: []topology.Status{{Peer: own, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{
		Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER}, DpgInfo: &backendv1.DpgInfo{DisplayName: stackName},
	}}}}
	h.opts = pages.Options{
		Kit: kit, Records: h.svc, Stack: h.stack,
		Shell: staffshell.New(staffshell.Options{
			Role: commonv1.Role_ROLE_ISSUER, Peers: []topology.Peer{own},
			Snapshot: func(context.Context) topology.Snapshot { return snap },
			JWKSURL:  own.Auth() + staffshell.JWKSPath, SignOut: pages.SignOutPath,
		}),
		SignOut: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/auth/", http.StatusSeeOther) }),
	}
	h.build(t)
	return h
}

// build makes the pages from the options of h.
func (h *harness) build(t *testing.T) {
	t.Helper()
	p, err := pages.New(h.opts)
	if err != nil {
		t.Fatal(err)
	}
	h.mux = http.NewServeMux()
	p.Register(h.mux)
}

// seed appends the three records of the tests.
func (h *harness) seed(t *testing.T) {
	t.Helper()
	for i, r := range []record.Record{
		{ID: recWanjiku, SchemaID: "farmer", SchemaVersion: 2, IssuedAt: fixedNow.AddDate(0, 0, -5), OfferID: "offer-1", DPGOfferID: "dpg-offer-1",
			SearchableClaims: map[string]string{"fullName": "Wanjiku Njeri", "farmerID": "FM-0042"}},
		{ID: recOtieno, SchemaID: "farmer", SchemaVersion: 2, IssuedAt: fixedNow.AddDate(0, 0, -15), OfferID: "offer-2", DPGOfferID: "dpg-offer-2",
			SearchableClaims: map[string]string{"fullName": "=Otieno Ouma", "farmerID": "FM-0043"}},
		{ID: recAmina, SchemaID: "nurse-licence", SchemaVersion: 1, IssuedAt: fixedNow.AddDate(0, -2, 0),
			SearchableClaims: map[string]string{"fullName": "Amina Hassan"}},
	} {
		r.SubjectRef = h.svc.SubjectRef(r.ID)
		r.Format = "dc+sd-jwt"
		r.DPG = "dpg-adapter"
		r.Binding = record.Binding{Kind: record.KindBitstring, ListID: "list-1", Index: int64(i + 10)}
		if _, err := h.svc.AppendRecord(r); err != nil {
			t.Fatal(err)
		}
	}
}

// do answers one request as the signed in staff member of h.
func (h *harness) do(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	r = r.WithContext(staffsession.With(r.Context(), h.sess))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec
}

// get answers one GET.
func (h *harness) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, httptest.NewRequest(http.MethodGet, path, nil))
}

// post answers one form POST.
func (h *harness) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(t, r)
}

// body returns the body of a 200 answer.
func body(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// listed reports whether the list of doc links to the record.
func listed(doc, id string) bool { return strings.Contains(doc, `href="/issued/`+id+`"`) }
