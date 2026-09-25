// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// fakeCache is the cache RPCs of the policy service.
type fakeCache struct {
	state  *policyv1.GetCacheStateResponse
	err    error
	synced []policyv1.CacheKind
	saved  *policyv1.CachePolicy
	setErr error
	failed int32
}

func (f *fakeCache) GetCacheState(context.Context, *connect.Request[policyv1.GetCacheStateRequest]) (*connect.Response[policyv1.GetCacheStateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.state), nil
}

func (f *fakeCache) SyncCache(_ context.Context, req *connect.Request[policyv1.SyncCacheRequest]) (*connect.Response[policyv1.SyncCacheResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.synced = append(f.synced, req.Msg.GetKind())
	for _, k := range f.state.GetKinds() {
		k.SyncedAt = timestamppb.New(testNow)
	}
	return connect.NewResponse(&policyv1.SyncCacheResponse{Kinds: f.state.GetKinds(), Sources: f.state.GetSources(), Failed: f.failed}), nil
}

func (f *fakeCache) SetCachePolicy(_ context.Context, req *connect.Request[policyv1.SetCachePolicyRequest]) (*connect.Response[policyv1.SetCachePolicyResponse], error) {
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.saved = req.Msg.GetPolicy()
	f.state.Policy = f.saved
	return connect.NewResponse(&policyv1.SetCachePolicyResponse{Policy: f.saved}), nil
}

// cacheState is a cache synced two hours ago, one source failing.
func cacheState() *policyv1.GetCacheStateResponse {
	synced := timestamppb.New(testNow.Add(-2 * time.Hour))
	return &policyv1.GetCacheStateResponse{
		Policy: &policyv1.CachePolicy{
			TrustListRefresh: durationpb.New(6 * time.Hour), KeysRefresh: durationpb.New(24 * time.Hour),
			StatusListRefresh: durationpb.New(time.Hour), AllowOffline: true, OfflineWindow: durationpb.New(24 * time.Hour),
			MarkStale: true, RefuseStaleStatus: true,
		},
		Kinds: []*policyv1.CacheKindState{
			{Kind: policyv1.CacheKind_CACHE_KIND_TRUST_LIST, SyncedAt: synced, Sources: 1, Items: 14, Issuers: 12},
			{Kind: policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS, SyncedAt: synced, Sources: 13, Items: 15, Issuers: 12},
			{Kind: policyv1.CacheKind_CACHE_KIND_STATUS_LIST, Sources: 0, Failed: 1},
		},
		Sources: []*policyv1.CacheSource{
			{Kind: policyv1.CacheKind_CACHE_KIND_TRUST_LIST, Source: "http://trust-registry:8085", SyncedAt: synced, SignedBy: "registry-key", ItemCount: 14},
			{Kind: policyv1.CacheKind_CACHE_KIND_REGISTRY_KEYS, Source: "x509:reg-ke", SyncedAt: synced, SignedBy: "CN=Kenya trust list anchor",
				ItemCount: 1, RegistryName: "Kenya trust registry"},
			{Kind: policyv1.CacheKind_CACHE_KIND_STATUS_LIST, Source: "https://issuer.labs.example/status/1",
				LastError: "ports: https://issuer.labs.example/status/1 returned 503"},
		},
	}
}

// withCache adds the cache client to the shell fixture.
func withCache(t *testing.T) (*shellFixture, *fakeCache) {
	t.Helper()
	f := newShellFixture(t)
	c := &fakeCache{state: cacheState()}
	f.portal.opts.Cache = c
	return f, c
}

// post answers one form POST as the staff member.
func (f *shellFixture) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(staffsession.With(r.Context(), staff))
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, r)
	return rec
}

// TestCachePageShowsTheState draws board Verifier-Caching with the real
// state: the age of each kind, the counts, the sources, and the policy.
func TestCachePageShowsTheState(t *testing.T) {
	f, _ := withCache(t)
	body := ok(t, f.get(t, DefaultPrefix+"/cache/"))
	a11ytest.AssertPage(t, body)
	for _, want := range []string{
		"Caching", "Sync now", "Save policy", `name="csrf_token"`,
		"Trust list", "Synced 2 h ago", "14 entries name 12 issuers.",
		"Registry keys", "15 keys and certificates from 13 sources.",
		"Status lists", "Not synced yet", "1 source failed at the last read.",
		"http://trust-registry:8085", "registry-key", "Kenya trust registry", "CN=Kenya trust list anchor", "the source returned 503",
		"Trust list every", "Registry keys every", "Status lists every",
		"Allow offline verification", "Mark stale results", "Refuse stale status lists",
		`<option value="6h" selected>`, `<option value="24h" selected>`, `<option value="1h" selected>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the cache page lacks %q", want)
		}
	}
	if strings.Contains(body, "Online checks") || strings.Contains(body, "None kept") {
		t.Error("the cache page still shows the online only text")
	}
	if strings.Count(body, "checked") < 3 {
		t.Error("want the three policy boxes checked")
	}
}

// TestCachePageSyncNow posts Sync now, reads every kind, and comes back
// to the page with the outcome.
func TestCachePageSyncNow(t *testing.T) {
	f, c := withCache(t)
	c.failed = 1
	rec := f.post(t, DefaultPrefix+"/cache/sync", url.Values{})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != DefaultPrefix+"/cache/?failed=1&synced=1" {
		t.Fatalf("Sync now = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if len(c.synced) != 1 || c.synced[0] != policyv1.CacheKind_CACHE_KIND_UNSPECIFIED {
		t.Fatalf("SyncCache calls = %v", c.synced)
	}
	body := ok(t, f.get(t, rec.Header().Get("Location")))
	a11ytest.AssertPage(t, body)
	for _, want := range []string{"The cache read every source. 1 source failed.", "Synced 0 min ago", "2 h ago", "Failed"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page after Sync now lacks %q", want)
		}
	}
	if rec := f.post(t, DefaultPrefix+"/cache/sync", url.Values{"kind": {"status"}}); rec.Code != http.StatusSeeOther ||
		c.synced[1] != policyv1.CacheKind_CACHE_KIND_STATUS_LIST {
		t.Fatalf("Sync of the status lists = %d %v", rec.Code, c.synced)
	}
	c.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	failed := f.post(t, DefaultPrefix+"/cache/sync", url.Values{})
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "The policy service did not answer.") {
		t.Fatalf("Sync now with the policy service down = %d", failed.Code)
	}
	a11ytest.AssertPage(t, failed.Body.String())
}

// TestCachePolicySaves stores the form as the cache policy and refuses
// a value the policy service refuses.
func TestCachePolicySaves(t *testing.T) {
	f, c := withCache(t)
	rec := f.post(t, DefaultPrefix+"/cache/policy", url.Values{
		"trust_refresh": {"3h"}, "keys_refresh": {"12h"}, "status_refresh": {"30m"}, "window": {"72h"},
		"offline": {"allow_offline", "refuse_stale_status"},
	})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != DefaultPrefix+"/cache/?saved=1" {
		t.Fatalf("Save policy = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	p := c.saved
	if p.GetTrustListRefresh().AsDuration() != 3*time.Hour || p.GetKeysRefresh().AsDuration() != 12*time.Hour ||
		p.GetStatusListRefresh().AsDuration() != 30*time.Minute || p.GetOfflineWindow().AsDuration() != 72*time.Hour ||
		!p.GetAllowOffline() || p.GetMarkStale() || !p.GetRefuseStaleStatus() {
		t.Fatalf("saved policy = %+v", p)
	}
	body := ok(t, f.get(t, rec.Header().Get("Location")))
	if !strings.Contains(body, "The policy service stored the cache policy.") || !strings.Contains(body, `<option value="72h" selected>`) {
		t.Error("the page after Save policy lacks the outcome or the new window")
	}
	bad := f.post(t, DefaultPrefix+"/cache/policy", url.Values{"trust_refresh": {"soon"}})
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "Choose one of the listed times.") {
		t.Fatalf("a bad interval = %d", bad.Code)
	}
	a11ytest.AssertPage(t, bad.Body.String())
	c.setErr = connect.NewError(connect.CodeInvalidArgument, errors.New("cache: the offline window must be at most 7 days"))
	refused := f.post(t, DefaultPrefix+"/cache/policy", url.Values{"window": {"24h"}})
	if refused.Code != http.StatusUnprocessableEntity || !strings.Contains(refused.Body.String(), "at most 7 days") {
		t.Fatalf("a refused policy = %d", refused.Code)
	}
	c.setErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if down := f.post(t, DefaultPrefix+"/cache/policy", url.Values{}); down.Code != http.StatusBadGateway {
		t.Fatalf("Save policy with the policy service down = %d", down.Code)
	}
}

// TestCachePageWithoutPolicyService says so when the policy service
// does not answer, and the overview card says the state is unknown.
func TestCachePageWithoutPolicyService(t *testing.T) {
	f, c := withCache(t)
	c.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	body := ok(t, f.get(t, DefaultPrefix+"/cache/"))
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "The policy service did not answer.") || strings.Contains(body, "Save policy") {
		t.Error("want the sentence and no policy form")
	}
	overview := ok(t, f.get(t, DefaultPrefix+"/"))
	if !strings.Contains(overview, "Trust cache") || strings.Count(overview, "Unknown now") < 1 {
		t.Error("want the cache card as unknown")
	}
	f.portal.opts.Cache = nil
	if rec := f.post(t, DefaultPrefix+"/cache/sync", url.Values{}); rec.Code != http.StatusBadGateway {
		t.Fatalf("Sync now without a policy service = %d", rec.Code)
	}
}

// TestOverviewCacheCard shows the age of the oldest kind and the window.
func TestOverviewCacheCard(t *testing.T) {
	f, c := withCache(t)
	body := ok(t, f.get(t, DefaultPrefix+"/"))
	a11ytest.AssertPage(t, body)
	for _, want := range []string{"Trust cache", "Synced 2 h ago", "The policy allows offline verification for 24 h."} {
		if !strings.Contains(body, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}
	c.state.Policy.AllowOffline = false
	c.state.Kinds = nil
	body = ok(t, f.get(t, DefaultPrefix+"/"))
	for _, want := range []string{"Not synced yet", "Offline verification is off. Each check needs the network."} {
		if !strings.Contains(body, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}
}
