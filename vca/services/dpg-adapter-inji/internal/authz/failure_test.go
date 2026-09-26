// SPDX-License-Identifier: Apache-2.0

package authz_test

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

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// brokenStore fails the operations whose key has one of the prefixes.
type brokenStore struct {
	store.KeyValue
	mu     sync.Mutex
	prefix map[string]bool
}

var errBroken = errors.New("the disk is gone")

func (b *brokenStore) fails(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for p := range b.prefix {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func (b *brokenStore) set(prefixes ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prefix = map[string]bool{}
	for _, p := range prefixes {
		b.prefix[p] = true
	}
}

func (b *brokenStore) Get(ctx context.Context, key string) ([]byte, error) {
	if b.fails(key) {
		return nil, errBroken
	}
	return b.KeyValue.Get(ctx, key)
}

func (b *brokenStore) Put(ctx context.Context, key string, value []byte) error {
	if b.fails(key) {
		return errBroken
	}
	return b.KeyValue.Put(ctx, key, value)
}

func (b *brokenStore) List(ctx context.Context, prefix string) ([]string, error) {
	if b.fails(prefix) {
		return nil, errBroken
	}
	return b.KeyValue.List(ctx, prefix)
}

func (b *brokenStore) CompareAndSwap(ctx context.Context, key string, old, value []byte) error {
	if b.fails(key) {
		return errBroken
	}
	return b.KeyValue.CompareAndSwap(ctx, key, old, value)
}

// brokenHarness is a harness whose store fails on demand.
func brokenHarness(t *testing.T) (*harness, *brokenStore) {
	t.Helper()
	h := newHarness(t)
	b := &brokenStore{KeyValue: store.Memory()}
	srv := h.build(t, b)
	mux := http.NewServeMux()
	mux.Handle("/authz/", http.StripPrefix("/authz", srv.Handler()))
	h.web.Config.Handler = mux
	h.srv = srv
	return h, b
}

func TestStoreFailuresAreServerErrors(t *testing.T) {
	h, b := brokenHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	// The login record cannot be kept.
	b.set("authz/logins/")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	wantError(t, anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location"))), "server_error", r.state)
	// The code cannot be kept.
	b.set("authz/codes/")
	wantError(t, h.signIn(r), "server_error", r.state)
	// The code cannot be read.
	b.set()
	h.addOffer("offer-2", "amina@example.org")
	r = newRequest(publicClient, walletCallback)
	r.issuerState = "offer-2"
	back := h.signIn(r)
	b.set("authz/codes/")
	status, answer := h.token(codeForm(r, back.Query().Get("code")))
	if status != http.StatusInternalServerError || answer["error"] != "server_error" {
		t.Fatalf("token = %d %v", status, answer)
	}
	// The sweep reports a store that cannot list.
	b.set("authz/logins")
	if _, err := h.srv.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep hid the failure")
	}
	// A callback whose login cannot be read is refused.
	b.set()
	r = newRequest(publicClient, walletCallback)
	res := h.authorize(r.query())
	callback, err := h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	b.set("authz/logins/")
	if res = h.get(callback); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback = %d", res.StatusCode)
	}
	// A sign in source that cannot be listed or stored.
	b.set("authz/signin")
	if serr := h.srv.SetSignInSource(context.Background(), authz.SignInSource{ConfigID: "c", SourceID: "s", Field: "f", TokenClaim: "email"}); serr == nil {
		t.Fatal("SetSignInSource hid the failure")
	}
	b.set()
	r = newRequest(publicClient, walletCallback)
	res = h.authorize(r.query())
	callback, err = h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	b.set("authz/signin")
	wantError(t, anyval.Must(url.Parse(h.get(callback).Header.Get("Location"))), "access_denied", r.state)
	// A client assertion whose id cannot be kept is refused.
	b.set("authz/jti/")
	h.addOffer("offer-3", "amina@example.org")
	r = newRequest(keyClient, keyRedirect)
	r.issuerState = "offer-3"
	b.set()
	back = h.signIn(r)
	b.set("authz/jti/")
	if status, _ := h.token(withAssertion(codeForm(r, back.Query().Get("code")), h.assertion(h.walletKey, nil))); status != http.StatusUnauthorized {
		t.Fatalf("token = %d", status)
	}
}

func TestNewFailsOnAStoreThatCannotKeepTheKey(t *testing.T) {
	for _, prefix := range []string{"authz/key"} {
		b := &brokenStore{KeyValue: store.Memory()}
		b.set(prefix)
		_, err := authz.New(context.Background(), authz.Options{
			Issuer: "https://issuer.example.org/authz", Audience: audience, Store: b, KeySecret: []byte(pairSeal),
			Registry: anyval.Must(oidcflow.NewRegistry(nil, nil)), Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
			Offers: &fakeIssuer{},
		})
		if err == nil {
			t.Fatalf("%s: New hid the failure", prefix)
		}
	}
	// A stored key that is not a sealed key stops the start.
	for _, raw := range []string{"{", `{"kid":"x","nonce":"AAAA","ciphertext":"AAAA"}`} {
		kv := store.Memory()
		if err := kv.Put(context.Background(), "authz/key", []byte(raw)); err != nil {
			t.Fatal(err)
		}
		_, err := authz.New(context.Background(), authz.Options{
			Issuer: "https://issuer.example.org/authz", Audience: audience, Store: kv, KeySecret: []byte(pairSeal),
			Registry: anyval.Must(oidcflow.NewRegistry(nil, nil)), Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
			Offers: &fakeIssuer{},
		})
		if err == nil || !strings.Contains(err.Error(), "open the token key") {
			t.Fatalf("stored %q: New = %v", raw, err)
		}
	}
}

// failingIssuer fails the writes of the issuer side.
type failingIssuer struct{ fakeIssuer }

func (f *failingIssuer) StageOffer(context.Context, string, string, time.Time) error {
	return errBroken
}

func (f *failingIssuer) StageSubject(context.Context, string, string, string, time.Time) error {
	return errBroken
}

// failingLookup cannot reach the data source.
type failingLookup struct{}

func (failingLookup) Lookup(context.Context, authz.SignInSource, string) (string, bool, error) {
	return "", false, errBroken
}

func TestIssuerSideFailuresDenyTheClaim(t *testing.T) {
	h := newHarness(t)
	fi := &failingIssuer{fakeIssuer{offers: map[string]authz.Offer{}, staged: map[string]string{}, claimed: map[string]bool{}}}
	fi.offers["offer-1"] = authz.Offer{ConfigID: "c", Subject: map[string]any{"email": "amina@example.org"},
		Binding: authz.Binding{TokenClaim: "email", SubjectClaim: "email"}}
	reg := anyval.Must(oidcflow.NewRegistry(nil, nil))
	if err := reg.Seed(oidcflow.SeedProvider(oidcflow.Seed{DiscoveryURL: h.idp.DiscoveryURL(), ClientID: "vca-inji-authz", Roles: []string{"holder"}})); err != nil {
		t.Fatal(err)
	}
	for _, lookup := range []authz.Lookup{h.lookup, failingLookup{}} {
		srv, err := authz.New(context.Background(), authz.Options{
			Issuer: h.web.URL + "/authz", Audience: audience, Store: store.Memory(), KeySecret: []byte(pairSeal),
			Clients:  []authz.Client{{ID: publicClient, RedirectURIs: []string{walletCallback}}},
			Registry: reg, Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Offers: fi, Lookup: lookup,
		})
		if err != nil {
			t.Fatal(err)
		}
		if srv.Issuer() != h.web.URL+"/authz" {
			t.Fatalf("Issuer = %s", srv.Issuer())
		}
		if err := srv.SetSignInSource(context.Background(), authz.SignInSource{
			ConfigID: "c", SourceID: "s", Field: "email", TokenClaim: "email",
		}); err != nil {
			t.Fatal(err)
		}
		h.lookup.rows["amina@example.org"] = `{"x":"y"}`
		mux := http.NewServeMux()
		mux.Handle("/authz/", http.StripPrefix("/authz", srv.Handler()))
		h.web.Config.Handler = mux
		for _, offer := range []string{"offer-1", ""} {
			r := newRequest(publicClient, walletCallback)
			r.issuerState = offer
			wantError(t, h.signIn(r), "access_denied", r.state)
		}
	}
}

func TestProviderFailuresDenyTheClaim(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	// The token endpoint of the provider refuses the code.
	h.idp.TokenError = "invalid_grant"
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	wantError(t, back, "access_denied", r.state)
	if back.Query().Get("error_description") != authz.DeniedSignIn {
		t.Fatalf("description = %q", back.Query().Get("error_description"))
	}
	// The provider is down when the request starts.
	h = newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	h.idp.Close()
	r = newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	wantError(t, anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location"))), "temporarily_unavailable", r.state)
}

func TestProviderRemovedDuringTheSignIn(t *testing.T) {
	h := newHarness(t)
	reg := anyval.Must(oidcflow.NewRegistry(nil, nil))
	if _, err := reg.Put(oidcflow.Provider{ID: "keycloak", DisplayName: "Keycloak", DiscoveryURL: h.idp.DiscoveryURL(),
		ClientID: "vca-inji-authz", Enabled: true, Roles: []string{"holder"}, Profile: oidcflow.Profile{Stacks: []string{"inji"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Put(oidcflow.Provider{ID: "another-stack", DisplayName: "Other", DiscoveryURL: "https://other.example.org/.well-known/openid-configuration",
		ClientID: "x", Enabled: true, Roles: []string{"holder"}, Profile: oidcflow.Profile{Stacks: []string{"waltid"}}}); err != nil {
		t.Fatal(err)
	}
	srv, err := authz.New(context.Background(), authz.Options{
		Issuer: h.web.URL + "/authz", Audience: audience, Store: store.Memory(), KeySecret: []byte(pairSeal),
		Clients:  []authz.Client{{ID: publicClient, RedirectURIs: []string{walletCallback}}},
		Registry: reg, Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Offers: h.issuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/authz/", http.StripPrefix("/authz", srv.Handler()))
	h.web.Config.Handler = mux
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	res := h.authorize(r.query())
	login := anyval.Must(url.Parse(res.Header.Get("Location")))
	if !strings.HasPrefix(login.String(), h.idp.Issuer()) {
		t.Fatalf("the holder went to %s, not the provider of the stack", login)
	}
	callback, err := h.idp.Authorize(login.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Delete("keycloak"); err != nil {
		t.Fatal(err)
	}
	wantError(t, anyval.Must(url.Parse(h.get(callback).Header.Get("Location"))), "temporarily_unavailable", r.state)
	// A claim without an offer and no lookup is for offers only.
	if _, err := reg.Put(oidcflow.Provider{ID: "keycloak", DisplayName: "Keycloak", DiscoveryURL: h.idp.DiscoveryURL(),
		ClientID: "vca-inji-authz", Enabled: true, Roles: []string{"holder"}}); err != nil {
		t.Fatal(err)
	}
	r = newRequest(publicClient, walletCallback)
	back := h.signIn(r)
	if back.Query().Get("error_description") != authz.DeniedOfferOnly {
		t.Fatalf("redirect = %s", back)
	}
}

func TestSmallerRulesOfTheRequest(t *testing.T) {
	h := newHarness(t)
	// A sign in source needs every field.
	if err := h.srv.SetSignInSource(context.Background(), authz.SignInSource{ConfigID: "c"}); err == nil {
		t.Fatal("a partial sign in source was stored")
	}
	// Authorization details of another type, or broken ones, need the scope.
	for _, details := range []string{"[", `[{"type":"other","credential_configuration_id":"c"}]`} {
		r := newRequest(publicClient, walletCallback)
		r.extra = url.Values{"scope": {""}, "authorization_details": {details}}
		wantError(t, anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location"))), "invalid_scope", r.state)
	}
	// A claim without an offer needs the token claim of the source.
	if err := h.srv.SetSignInSource(context.Background(), authz.SignInSource{
		ConfigID: "c", SourceID: "s", Field: "member", TokenClaim: "member_number",
	}); err != nil {
		t.Fatal(err)
	}
	r := newRequest(publicClient, walletCallback)
	if back := h.signIn(r); back.Query().Get("error_description") != authz.DeniedNoRecord {
		t.Fatalf("redirect = %s", back)
	}
	// The request names a credential without a source.
	r = newRequest(publicClient, walletCallback)
	r.extra = url.Values{"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"none"}]`}}
	if back := h.signIn(r); back.Query().Get("error_description") != authz.DeniedOfferOnly {
		t.Fatalf("redirect = %s", back)
	}
	// An email the token calls unverified in text does not bind.
	h.idp.Claims = map[string]any{"email": "amina@example.org", "email_verified": "false"}
	h.addOffer("offer-1", "amina@example.org")
	r = newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	wantError(t, h.signIn(r), "access_denied", r.state)
	// A binding rule without claims, or a subject claim that is not text,
	// binds nobody.
	h.idp.Claims = map[string]any{"email": "amina@example.org", "email_verified": true}
	h.idp.Subject = "7"
	h.issuer.mu.Lock()
	h.issuer.offers["offer-2"] = authz.Offer{ConfigID: "c", Subject: map[string]any{"number": 7}, Binding: authz.Binding{TokenClaim: "sub", SubjectClaim: "number"}}
	h.issuer.offers["offer-3"] = authz.Offer{ConfigID: "c", Subject: map[string]any{"number": "7"}}
	h.issuer.offers["offer-4"] = authz.Offer{ConfigID: "c", Subject: map[string]any{"number": "7"}, Binding: authz.Binding{TokenClaim: "sub", SubjectClaim: "number"}}
	h.issuer.mu.Unlock()
	for _, id := range []string{"offer-2", "offer-3"} {
		r = newRequest(publicClient, walletCallback)
		r.issuerState = id
		wantError(t, h.signIn(r), "access_denied", r.state)
	}
	// Another claim than email compares exactly.
	r = newRequest(publicClient, walletCallback)
	r.issuerState = "offer-4"
	if back := h.signIn(r); back.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", back)
	}
	// The offer is claimed between the request and the callback.
	h.addOffer("offer-5", "amina@example.org")
	r = newRequest(publicClient, walletCallback)
	r.issuerState = "offer-5"
	res := h.authorize(r.query())
	callback, err := h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	h.issuer.mu.Lock()
	h.issuer.claimed["offer-5"] = true
	h.issuer.mu.Unlock()
	wantError(t, anyval.Must(url.Parse(h.get(callback).Header.Get("Location"))), "access_denied", r.state)
}

func TestTokenEdges(t *testing.T) {
	h := newHarness(t)
	// A body that is not a form.
	res, err := http.Post(h.web.URL+"/authz/token", "application/x-www-form-urlencoded", strings.NewReader("%zz"))
	if err != nil {
		t.Fatal(err)
	}
	anyval.Discard(res.Body.Close())
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("token = %d", res.StatusCode)
	}
	// An assertion whose audience is a list that names the issuer works.
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(keyClient, keyRedirect)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	a := h.assertion(h.walletKey, map[string]any{"aud": []string{"https://other.example.org", h.web.URL + "/authz"}})
	if status, answer := h.token(withAssertion(codeForm(r, back.Query().Get("code")), a)); status != http.StatusOK {
		t.Fatalf("token = %d %v", status, answer)
	}
	// Only GET reaches the pages and only POST the token endpoint.
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authz.TokenPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET token = %d", rec.Code)
	}
}
