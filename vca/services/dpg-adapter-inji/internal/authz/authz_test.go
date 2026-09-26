// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The test wallet clients: a public client with PKCE, and the client of
// Inji Web that signs a client assertion.
const (
	publicClient   = "wallet"
	walletCallback = "https://wallet.example.org/callback"
	keyClient      = "vca-inji"
	keyRedirect    = "https://web.example.org/redirect"
	audience       = "http://inji-certify-nginx:8091/v1/certify/issuance/credential"
	pairSeal       = "0123456789abcdef0123456789abcdef"
)

// fakeIssuer is the service side of the server: the open offers and the
// rows it staged.
type fakeIssuer struct {
	mu       sync.Mutex
	offers   map[string]authz.Offer
	staged   map[string]string
	expires  map[string]time.Time
	unstaged []string
	claimed  map[string]bool
	finished []string
	reopened []string
	lookups  int
	// brokenReopen makes Reopen and Unstage fail.
	brokenReopen bool
}

func (f *fakeIssuer) Offer(_ context.Context, id string) (authz.Offer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	o, ok := f.offers[id]
	return o, ok && !f.claimed[id]
}

func (f *fakeIssuer) StageOffer(_ context.Context, id, key string, expires time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimed[id] {
		return errors.New("claimed")
	}
	f.claimed[id] = true
	f.staged[key] = "offer:" + id
	if f.expires != nil {
		f.expires[key] = expires
	}
	return nil
}

func (f *fakeIssuer) StageSubject(_ context.Context, configID, subject, key string, expires time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staged[key] = configID + ":" + subject
	if f.expires != nil {
		f.expires[key] = expires
	}
	return nil
}

func (f *fakeIssuer) Reopen(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.brokenReopen {
		return errBroken
	}
	f.reopened = append(f.reopened, id)
	delete(f.claimed, id)
	return nil
}

func (f *fakeIssuer) Finish(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished = append(f.finished, id)
	return nil
}

func (f *fakeIssuer) Unstage(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.brokenReopen {
		return errBroken
	}
	f.unstaged = append(f.unstaged, key)
	delete(f.staged, key)
	return nil
}

// fakeLookup is the data source of a wallet initiated claim.
type fakeLookup struct {
	mu    sync.Mutex
	rows  map[string]string
	calls []string
}

func (f *fakeLookup) Lookup(_ context.Context, src authz.SignInSource, value string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, src.SourceID+"/"+src.Field+"="+value)
	row, ok := f.rows[value]
	return row, ok, nil
}

type harness struct {
	t         *testing.T
	srv       *authz.Server
	web       *httptest.Server
	idp       *oidctest.Provider
	issuer    *fakeIssuer
	lookup    *fakeLookup
	kv        store.KeyValue
	now       time.Time
	nowMu     sync.Mutex
	walletKey *rsa.PrivateKey
	browser   *http.Client
	verified  []string
	limits    authz.Limits
	logs      lockedBuffer
}

// lockedBuffer collects the log of a server.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (h *harness) clock() time.Time {
	h.nowMu.Lock()
	defer h.nowMu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.nowMu.Lock()
	h.now = h.now.Add(d)
	h.nowMu.Unlock()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, harnessOptions{})
}

// newHarnessVouching is a harness whose holder provider record lists
// the claims it verifies beyond the standard ones.
func newHarnessVouching(t *testing.T, verified ...string) *harness {
	t.Helper()
	return newHarnessWith(t, harnessOptions{verified: verified})
}

// harnessOptions change the server a harness builds.
type harnessOptions struct {
	// verified lists the claims the provider record vouches for.
	verified []string
	// kv replaces the memory store.
	kv store.KeyValue
	// limits replaces the rate limits, which the harness lifts.
	limits *authz.Limits
}

// noLimits lets every test request through.
var noLimits = authz.Limits{
	Browser: authz.RateLimit{PerSecond: 1000, Burst: 100000}, Client: authz.RateLimit{PerSecond: 1000, Burst: 100000},
	Authorize: authz.RateLimit{PerSecond: 1000, Burst: 100000},
}

func newHarnessWith(t *testing.T, o harnessOptions) *harness {
	t.Helper()
	if o.kv == nil {
		o.kv = store.Memory()
	}
	if o.limits == nil {
		o.limits = &noLimits
	}
	h := &harness{
		verified: o.verified,
		limits:   *o.limits,
		t:        t,
		idp:      oidctest.New(),
		issuer: &fakeIssuer{offers: map[string]authz.Offer{}, staged: map[string]string{}, claimed: map[string]bool{},
			expires: map[string]time.Time{}},
		lookup: &fakeLookup{rows: map[string]string{}},
		kv:     o.kv,
		now:    time.Now().UTC().Truncate(time.Second),
		browser: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
	t.Cleanup(h.idp.Close)
	h.idp.ClientID = "vca-inji-authz"
	h.idp.Now = h.clock
	h.idp.Claims = map[string]any{"email": "amina@example.org", "email_verified": true}
	h.walletKey = anyval.Must(rsa.GenerateKey(rand.Reader, 2048))
	mux := http.NewServeMux()
	h.web = httptest.NewServer(mux)
	t.Cleanup(h.web.Close)
	h.srv = h.build(t, h.kv)
	mux.Handle("/authz/", http.StripPrefix("/authz", h.srv.Handler()))
	return h
}

// storeMemory is a memory store for a test that wraps one.
func storeMemory() store.KeyValue { return store.Memory() }

// build makes a server on one store, as a start of the adapter does.
func (h *harness) build(t *testing.T, kv store.KeyValue) *authz.Server {
	t.Helper()
	srv, err := authz.New(context.Background(), h.options(kv))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// options are the options of a server of the harness on one store.
func (h *harness) options(kv store.KeyValue) authz.Options {
	t := h.t
	t.Helper()
	reg := anyval.Must(oidcflow.NewRegistry(nil, nil))
	if err := reg.Seed(oidcflow.SeedProvider(oidcflow.Seed{
		DiscoveryURL: h.idp.DiscoveryURL(), ClientID: "vca-inji-authz", Roles: []string{"holder"},
		VerifiedClaims: h.verified,
	})); err != nil {
		t.Fatal(err)
	}
	pub := anyval.Must(jose.PublicJWK(h.walletKey, ""))
	raw := anyval.Must(json.Marshal(pub))
	return authz.Options{
		Issuer:    h.web.URL + "/authz",
		Audience:  audience,
		Store:     kv,
		KeySecret: []byte(pairSeal),
		Clients: []authz.Client{
			{ID: publicClient, RedirectURIs: []string{walletCallback}},
			{ID: "wallet-two", RedirectURIs: []string{walletCallback}},
			{ID: keyClient, RedirectURIs: []string{keyRedirect}, JWK: raw},
		},
		Registry: reg,
		Flow:     &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0), Now: h.clock},
		Offers:   h.issuer,
		Lookup:   h.lookup,
		Limits:   h.limits,
		Now:      h.clock,
		Log:      slog.New(slog.NewTextHandler(&h.logs, nil)),
	}
}

// reply is an answer that the harness read and closed.
type reply struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// get follows no redirect and returns the answer.
func (h *harness) get(raw string) reply {
	h.t.Helper()
	res, err := h.browser.Get(raw)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	raw2, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return reply{StatusCode: res.StatusCode, Header: res.Header, Body: string(raw2)}
}

// request is one authorization request of a wallet.
type request struct {
	client, redirect, state, verifier, issuerState string
	extra                                          url.Values
}

func (r request) query() url.Values {
	q := url.Values{
		"response_type": {"code"}, "client_id": {r.client}, "redirect_uri": {r.redirect},
		"state": {r.state}, "scope": {authz.Scope},
		"code_challenge": {oidc.Challenge(r.verifier)}, "code_challenge_method": {"S256"},
	}
	if r.issuerState != "" {
		q.Set("issuer_state", r.issuerState)
	}
	for k, v := range r.extra {
		q[k] = v
	}
	return q
}

func newRequest(client, redirect string) request {
	return request{client: client, redirect: redirect, state: oidc.NewState(), verifier: oidc.NewVerifier()}
}

func (h *harness) authorize(q url.Values) reply {
	return h.get(h.web.URL + "/authz/authorize?" + q.Encode())
}

// signIn runs the authorization request and the sign in at the holder
// provider and returns the redirect to the wallet.
func (h *harness) signIn(r request) *url.URL {
	h.t.Helper()
	res := h.authorize(r.query())
	if res.StatusCode != http.StatusFound {
		h.t.Fatalf("authorize = %d %s", res.StatusCode, res.Body)
	}
	callback, err := h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	res = h.get(callback)
	if res.StatusCode != http.StatusFound {
		h.t.Fatalf("callback = %d %s", res.StatusCode, res.Body)
	}
	return anyval.Must(url.Parse(res.Header.Get("Location")))
}

// token posts a token request and returns the status and the answer.
func (h *harness) token(form url.Values) (int, map[string]any) {
	h.t.Helper()
	res, err := http.PostForm(h.web.URL+"/authz/token", form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		h.t.Fatal(err)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		h.t.Errorf("the token answer lacks Cache-Control: no-store")
	}
	return res.StatusCode, out
}

func codeForm(r request, code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {r.redirect},
		"client_id": {r.client}, "code_verifier": {r.verifier},
	}
}

// assertion signs a client assertion with key.
func (h *harness) assertion(key *rsa.PrivateKey, claims map[string]any) string {
	h.t.Helper()
	now := h.clock()
	base := map[string]any{
		"iss": keyClient, "sub": keyClient, "aud": h.web.URL + "/authz/token",
		"jti": oidc.NewState(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return anyval.Must(jose.SignRS256(key, "", "JWT", base))
}

func withAssertion(form url.Values, assertion string) url.Values {
	form.Set("client_assertion_type", oidcflow.ClientAssertionType)
	form.Set("client_assertion", assertion)
	return form
}

func (h *harness) addOffer(id, email string) {
	h.issuer.mu.Lock()
	defer h.issuer.mu.Unlock()
	h.issuer.offers[id] = authz.Offer{
		ConfigID: "ResidencePermit",
		Subject:  map[string]any{"fullName": "Amina Njeri", "email": email},
		Binding:  authz.Binding{TokenClaim: "email", SubjectClaim: "email"},
	}
}

func wantError(t *testing.T, u *url.URL, code, state string) {
	t.Helper()
	q := u.Query()
	if q.Get("error") != code || q.Get("state") != state || q.Get("code") != "" {
		t.Fatalf("redirect = %s, want error %s with the state", u, code)
	}
}

func TestMetadataAndJwks(t *testing.T) {
	h := newHarness(t)
	res := h.get(h.web.URL + "/authz/.well-known/oauth-authorization-server")
	var meta map[string]any
	if err := json.Unmarshal([]byte(res.Body), &meta); err != nil {
		t.Fatal(err)
	}
	issuer := h.web.URL + "/authz"
	want := map[string]any{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"jwks_uri": issuer + "/.well-known/jwks.json",
	}
	for k, v := range want {
		if meta[k] != v {
			t.Errorf("%s = %v, want %v", k, meta[k], v)
		}
	}
	lists := map[string]string{
		"grant_types_supported": "authorization_code", "response_types_supported": "code",
		"code_challenge_methods_supported": "S256", "token_endpoint_auth_methods_supported": "none,private_key_jwt",
		"scopes_supported": authz.Scope,
	}
	for k, v := range lists {
		items, ok := meta[k].([]any)
		if !ok {
			t.Errorf("%s is not a list: %v", k, meta[k])
		}
		var got []string
		for _, i := range items {
			got = append(got, anyval.As[string](i))
		}
		if strings.Join(got, ",") != v {
			t.Errorf("%s = %v, want %s", k, got, v)
		}
	}
	res = h.get(issuer + "/.well-known/jwks.json")
	set, err := jose.ParseJWKS([]byte(res.Body))
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks = %v, %v", set, err)
	}
	k := set.Keys[0]
	if k.KeyID == "" || k.Algorithm != "RS256" || k.Use != "sig" || !k.IsPublic() {
		t.Fatalf("jwk = %+v", k)
	}
	if _, isRSA := k.Key.(*rsa.PublicKey); !isRSA {
		t.Fatalf("the key is %T, want RSA", k.Key)
	}
	thumb, err := jose.Thumbprint(k)
	if err != nil || thumb != k.KeyID {
		t.Fatalf("kid %s is not the thumbprint %s", k.KeyID, thumb)
	}
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	h := newHarness(t)
	r := newRequest("stranger", walletCallback)
	res := h.authorize(r.query())
	// An unknown client gets no redirect: the address may be an attacker's.
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
		t.Fatalf("authorize = %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if !strings.Contains(res.Body, "unknown client") {
		t.Error("the answer does not name the reason")
	}
	if h.idp.Requests["/authorize"] != 0 {
		t.Error("the holder went to the provider")
	}
}

func TestAuthorizeRejectsRedirectMismatch(t *testing.T) {
	h := newHarness(t)
	for _, redirect := range []string{
		"https://evil.example.org/callback", walletCallback + "/more", walletCallback + "?x=1",
		strings.ToUpper(walletCallback), "", keyRedirect,
	} {
		r := newRequest(publicClient, redirect)
		res := h.authorize(r.query())
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Errorf("redirect %q: authorize = %d to %q", redirect, res.StatusCode, res.Header.Get("Location"))
		}
	}
}

func TestAuthorizeNeedsS256(t *testing.T) {
	h := newHarness(t)
	cases := map[string]url.Values{
		"plain":        {"code_challenge_method": {"plain"}},
		"no method":    {"code_challenge_method": {""}},
		"no challenge": {"code_challenge": {""}},
		"short":        {"code_challenge": {"abc"}},
	}
	for name, extra := range cases {
		r := newRequest(publicClient, walletCallback)
		r.extra = extra
		res := h.authorize(r.query())
		if res.StatusCode != http.StatusFound {
			t.Fatalf("%s: authorize = %d", name, res.StatusCode)
		}
		wantError(t, anyval.Must(url.Parse(res.Header.Get("Location"))), "invalid_request", r.state)
	}
	// A request needs a state, the code response type, and the shared scope.
	r := newRequest(publicClient, walletCallback)
	r.state = ""
	res := h.authorize(r.query())
	if u := anyval.Must(url.Parse(res.Header.Get("Location"))); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("no state: %s", u)
	}
	r = newRequest(publicClient, walletCallback)
	r.extra = url.Values{"response_type": {"token"}}
	wantError(t, anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location"))), "unsupported_response_type", r.state)
	r = newRequest(publicClient, walletCallback)
	r.extra = url.Values{"scope": {"openid"}}
	wantError(t, anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location"))), "invalid_scope", r.state)
	if h.idp.Requests["/authorize"] != 0 {
		t.Error("a bad request reached the provider")
	}
}

func TestAuthorizeRejectsUnknownOffer(t *testing.T) {
	h := newHarness(t)
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "no-such-offer"
	res := h.authorize(r.query())
	wantError(t, anyval.Must(url.Parse(res.Header.Get("Location"))), "invalid_request", r.state)
}

// claimToken runs the offer bound claim to the token answer.
func (h *harness) claimToken(offer string) (request, map[string]any) {
	h.t.Helper()
	r := newRequest(publicClient, walletCallback)
	r.issuerState = offer
	back := h.signIn(r)
	if back.Query().Get("state") != r.state || back.Query().Get("iss") != h.web.URL+"/authz" {
		h.t.Fatalf("redirect = %s", back)
	}
	status, answer := h.token(codeForm(r, back.Query().Get("code")))
	if status != http.StatusOK {
		h.t.Fatalf("token = %d %v", status, answer)
	}
	return r, answer
}

func TestOfferBoundClaimAfterMatchingLogin(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "Amina@Example.org")
	_, answer := h.claimToken("offer-1")
	if answer["token_type"] != "Bearer" || answer["c_nonce"] == "" || answer["expires_in"] == nil {
		t.Fatalf("answer = %v", answer)
	}
	// The token verifies against the published key set.
	set, err := jose.ParseJWKS([]byte(h.get(h.web.URL + "/authz/.well-known/jwks.json").Body))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oidc.VerifyToken(anyval.As[string](answer["access_token"]), set, oidc.TokenOptions{
		Issuers: []string{h.web.URL + "/authz"}, ClientID: audience, Now: h.clock(),
	})
	if err != nil {
		t.Fatalf("the access token does not verify: %v", err)
	}
	sub := anyval.As[string](claims["sub"])
	if h.issuer.staged[sub] != "offer:offer-1" {
		t.Fatalf("sub %q names no staged row: %v", sub, h.issuer.staged)
	}
	if claims["scope"] != authz.Scope || claims["client_id"] != publicClient || claims["c_nonce"] != answer["c_nonce"] {
		t.Fatalf("claims = %v", claims)
	}
	hdr, err := jose.PeekHeader(anyval.As[string](answer["access_token"]))
	if err != nil || hdr.Alg != "RS256" || hdr.Kid != set.Keys[0].KeyID {
		t.Fatalf("header = %+v, %v", hdr, err)
	}
	// The offer is claimed once.
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	wantError(t, anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location"))), "invalid_request", r.state)
}

func TestOfferBoundClaimRefusesAnotherPerson(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "someone.else@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	wantError(t, back, "access_denied", r.state)
	if got := back.Query().Get("error_description"); got != "This offer is for another person." {
		t.Fatalf("description = %q", got)
	}
	if len(h.issuer.staged) != 0 {
		t.Fatalf("a row was staged: %v", h.issuer.staged)
	}
}

func TestOfferBoundClaimRefusesMissingOrUnverifiedClaim(t *testing.T) {
	cases := map[string]map[string]any{
		"unverified email":        {"email": "amina@example.org", "email_verified": false},
		"unverified email text":   {"email": "amina@example.org", "email_verified": "false"},
		"no email_verified":       {"email": "amina@example.org"},
		"email_verified not bool": {"email": "amina@example.org", "email_verified": 1},
		"no email":                {"name": "Amina"},
		"email not text":          {"email": 7},
		"a Kelvin sign":           {"email": "amina@example.org", "email_verified": true, "_subject": "amin\u212a@example.org"},
	}
	for name, claims := range cases {
		h := newHarness(t)
		subject := "amina@example.org"
		if v, ok := claims["_subject"].(string); ok {
			subject = v
			claims["email"] = "amink@example.org"
			delete(claims, "_subject")
		}
		h.idp.Claims = claims
		h.addOffer("offer-1", subject)
		r := newRequest(publicClient, walletCallback)
		r.issuerState = "offer-1"
		wantError(t, h.signIn(r), "access_denied", r.state)
		if len(h.issuer.staged) != 0 {
			t.Fatalf("%s: a row was staged", name)
		}
	}
}

func TestWalletInitiatedClaimUsesTheSource(t *testing.T) {
	h := newHarness(t)
	if err := h.srv.SetSignInSource(context.Background(), authz.SignInSource{
		ConfigID: "ResidencePermit", SourceID: "registry", Field: "email", TokenClaim: "email",
		SchemaID: "residence-permit", SchemaVersion: 2,
	}); err != nil {
		t.Fatal(err)
	}
	h.lookup.rows["amina@example.org"] = `{"fullName":"Amina Njeri"}`
	r := newRequest(publicClient, walletCallback)
	back := h.signIn(r)
	status, answer := h.token(codeForm(r, back.Query().Get("code")))
	if status != http.StatusOK {
		t.Fatalf("token = %d %v", status, answer)
	}
	claims := anyval.Must(jose.PeekPayload(anyval.As[string](answer["access_token"])))
	sub := anyval.As[string](claims["sub"])
	if h.issuer.staged[sub] != `ResidencePermit:{"fullName":"Amina Njeri"}` {
		t.Fatalf("staged = %v", h.issuer.staged)
	}
	if strings.Join(h.lookup.calls, ",") != "registry/email=amina@example.org" {
		t.Fatalf("lookups = %v", h.lookup.calls)
	}
	// A second source makes the request name its credential.
	if err := h.srv.SetSignInSource(context.Background(), authz.SignInSource{
		ConfigID: "Other", SourceID: "registry", Field: "email", TokenClaim: "email",
	}); err != nil {
		t.Fatal(err)
	}
	r = newRequest(publicClient, walletCallback)
	wantError(t, h.signIn(r), "access_denied", r.state)
	r = newRequest(publicClient, walletCallback)
	r.extra = url.Values{"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"ResidencePermit"}]`}}
	if back := h.signIn(r); back.Query().Get("code") == "" {
		t.Fatalf("authorization_details: %s", back)
	}
	// No row for the person is a refusal.
	h.idp.Claims = map[string]any{"email": "nobody@example.org", "email_verified": true}
	r = newRequest(publicClient, walletCallback)
	r.extra = url.Values{"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"ResidencePermit"}]`}}
	wantError(t, h.signIn(r), "access_denied", r.state)
}

func TestWalletInitiatedClaimWithoutSourceIsDenied(t *testing.T) {
	h := newHarness(t)
	r := newRequest(publicClient, walletCallback)
	back := h.signIn(r)
	wantError(t, back, "access_denied", r.state)
	if got := back.Query().Get("error_description"); got != authz.DeniedOfferOnly {
		t.Fatalf("description = %q", got)
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	res := h.authorize(r.query())
	callback, err := h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	u := anyval.Must(url.Parse(callback))
	q := u.Query()
	for _, state := range []string{"forged", ""} {
		q.Set("state", state)
		u.RawQuery = q.Encode()
		res = h.get(u.String())
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Fatalf("state %q: callback = %d to %q", state, res.StatusCode, res.Header.Get("Location"))
		}
	}
	// The real state works once, and a replay of the callback fails.
	res = h.get(callback)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("callback = %d", res.StatusCode)
	}
	res = h.get(callback)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a replayed callback = %d", res.StatusCode)
	}
	// An error of the provider goes back to the wallet as access_denied.
	r = newRequest(publicClient, walletCallback)
	res = h.authorize(r.query())
	login := anyval.Must(url.Parse(res.Header.Get("Location")))
	res = h.get(h.web.URL + "/authz/callback?error=access_denied&state=" + url.QueryEscape(login.Query().Get("state")))
	wantError(t, anyval.Must(url.Parse(res.Header.Get("Location"))), "access_denied", r.state)
	// A login that took too long ends.
	r = newRequest(publicClient, walletCallback)
	res = h.authorize(r.query())
	callback, err = h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	h.advance(11 * time.Minute)
	if res = h.get(callback); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a late callback = %d", res.StatusCode)
	}
}

func TestTokenChecksPkce(t *testing.T) {
	h := newHarness(t)
	for _, verifier := range []string{"", oidc.NewVerifier(), "short"} {
		h.addOffer("offer-"+verifier, "amina@example.org")
		r := newRequest(publicClient, walletCallback)
		r.issuerState = "offer-" + verifier
		back := h.signIn(r)
		form := codeForm(r, back.Query().Get("code"))
		form.Set("code_verifier", verifier)
		status, answer := h.token(form)
		if status != http.StatusBadRequest || answer["error"] != "invalid_grant" {
			t.Errorf("verifier %q: token = %d %v", verifier, status, answer)
		}
		// The failed try used the code up.
		if status, _ := h.token(codeForm(r, back.Query().Get("code"))); status != http.StatusBadRequest {
			t.Errorf("verifier %q: the code worked after a failed try", verifier)
		}
	}
}

func TestTokenChecksTheRequestBinding(t *testing.T) {
	h := newHarness(t)
	cases := map[string]func(url.Values){
		"another redirect":   func(f url.Values) { f.Set("redirect_uri", "https://evil.example.org/callback") },
		"no redirect":        func(f url.Values) { f.Del("redirect_uri") },
		"another client":     func(f url.Values) { f.Set("client_id", "stranger") },
		"no client":          func(f url.Values) { f.Del("client_id") },
		"another grant":      func(f url.Values) { f.Set("grant_type", "client_credentials") },
		"a forged code":      func(f url.Values) { f.Set("code", oidc.NewState()) },
		"no code":            func(f url.Values) { f.Del("code") },
		"a client secret":    func(f url.Values) { f.Set("client_secret", "guess") },
		"a stray assertion":  func(f url.Values) { withAssertion(f, "x.y.z") },
		"the client of Web":  func(f url.Values) { f.Set("client_id", keyClient) },
		"a doubled verifier": func(f url.Values) { f.Add("code_verifier", "second") },
		"a second wallet":    func(f url.Values) { f.Set("client_id", "wallet-two") },
	}
	want := map[string]string{
		"another redirect": "invalid_grant", "no redirect": "invalid_grant", "another client": "invalid_client",
		"no client": "invalid_client", "another grant": "unsupported_grant_type", "a forged code": "invalid_grant",
		"no code": "invalid_grant", "a client secret": "invalid_client", "a stray assertion": "invalid_client",
		"the client of Web": "invalid_client", "a doubled verifier": "invalid_request",
		"a second wallet": "invalid_grant",
	}
	for name, change := range cases {
		id := "offer-" + strings.ReplaceAll(name, " ", "-")
		h.addOffer(id, "amina@example.org")
		r := newRequest(publicClient, walletCallback)
		r.issuerState = id
		back := h.signIn(r)
		form := codeForm(r, back.Query().Get("code"))
		change(form)
		status, answer := h.token(form)
		if answer["error"] != want[name] || status < 400 {
			t.Errorf("%s: token = %d %v, want %s", name, status, answer, want[name])
		}
		if want[name] == "invalid_client" && status != http.StatusUnauthorized {
			t.Errorf("%s: invalid_client answers %d, want 401", name, status)
		}
	}
}

func TestTokenChecksPrivateKeyJwt(t *testing.T) {
	h := newHarness(t)
	other := anyval.Must(rsa.GenerateKey(rand.Reader, 2048))
	ecKey := anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	cases := map[string]func() string{
		"another key": func() string { return h.assertion(other, nil) },
		"another iss": func() string { return h.assertion(h.walletKey, map[string]any{"iss": publicClient}) },
		"another sub": func() string { return h.assertion(h.walletKey, map[string]any{"sub": publicClient}) },
		"another aud": func() string {
			return h.assertion(h.walletKey, map[string]any{"aud": "https://evil.example.org/token"})
		},
		"expired": func() string {
			return h.assertion(h.walletKey, map[string]any{"exp": h.clock().Add(-time.Minute).Unix()})
		},
		"too long":      func() string { return h.assertion(h.walletKey, map[string]any{"exp": h.clock().Add(time.Hour).Unix()}) },
		"no jti":        func() string { return h.assertion(h.walletKey, map[string]any{"jti": nil}) },
		"no exp":        func() string { return h.assertion(h.walletKey, map[string]any{"exp": nil}) },
		"an EC key":     func() string { return anyval.Must(jose.Sign(ecKey, "", "JWT", map[string]any{"iss": keyClient})) },
		"not a JWT":     func() string { return "not-a-jwt" },
		"alg none":      func() string { return "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ2Y2EtaW5qaSJ9." },
		"no assertion":  func() string { return "" },
		"wrong type":    func() string { return "" },
		"the right key": func() string { return h.assertion(h.walletKey, nil) },
	}
	for name, make := range cases {
		id := "offer-" + strings.ReplaceAll(name, " ", "-")
		h.addOffer(id, "amina@example.org")
		r := newRequest(keyClient, keyRedirect)
		r.issuerState = id
		back := h.signIn(r)
		form := codeForm(r, back.Query().Get("code"))
		if a := make(); a != "" {
			withAssertion(form, a)
		}
		if name == "wrong type" {
			withAssertion(form, h.assertion(h.walletKey, nil))
			form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
		}
		status, answer := h.token(form)
		if name == "the right key" {
			if status != http.StatusOK {
				t.Fatalf("the registered key: token = %d %v", status, answer)
			}
			continue
		}
		if status != http.StatusUnauthorized || answer["error"] != "invalid_client" {
			t.Errorf("%s: token = %d %v", name, status, answer)
		}
	}
}

func TestAssertionReplayIsRefused(t *testing.T) {
	h := newHarness(t)
	a := h.assertion(h.walletKey, nil)
	for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		id := "offer-" + string(rune('a'+i))
		h.addOffer(id, "amina@example.org")
		r := newRequest(keyClient, keyRedirect)
		r.issuerState = id
		back := h.signIn(r)
		status, answer := h.token(withAssertion(codeForm(r, back.Query().Get("code")), a))
		if status != want {
			t.Fatalf("use %d: token = %d %v", i, status, answer)
		}
	}
}

func TestCodeIsOneTime(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	form := codeForm(r, back.Query().Get("code"))
	status, answer := h.token(form)
	if status != http.StatusOK {
		t.Fatalf("first = %d %v", status, answer)
	}
	sub := anyval.As[string](anyval.Must(jose.PeekPayload(anyval.As[string](answer["access_token"])))["sub"])
	status, answer = h.token(form)
	if status != http.StatusBadRequest || answer["error"] != "invalid_grant" {
		t.Fatalf("second = %d %v", status, answer)
	}
	// A code that comes back removes the row of the first token, so a
	// stolen code issues nothing (RFC 6749 section 4.1.2).
	if len(h.issuer.unstaged) != 1 || h.issuer.unstaged[0] != sub {
		t.Fatalf("unstaged = %v, want %s", h.issuer.unstaged, sub)
	}
}

func TestCodesExpire(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	h.advance(authz.CodeTTL + time.Second)
	status, answer := h.token(codeForm(r, back.Query().Get("code")))
	if status != http.StatusBadRequest || answer["error"] != "invalid_grant" {
		t.Fatalf("token = %d %v", status, answer)
	}
	// The sweep removes the records of the ended requests.
	h.advance(time.Hour)
	removed, err := h.srv.Sweep(context.Background())
	if err != nil || removed == 0 {
		t.Fatalf("Sweep = %d, %v", removed, err)
	}
	keys, err := h.kv.List(context.Background(), "authz/")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "authz/key") {
			t.Errorf("the sweep left %s", k)
		}
	}
}

func TestTokenKeySurvivesRestart(t *testing.T) {
	h := newHarness(t)
	jwks := func(srv *authz.Server) string {
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
		return res.Body.String()
	}
	second := h.build(t, h.kv)
	if jwks(second) != jwks(h.srv) {
		t.Fatal("a second start made another key")
	}
	raw, err := h.kv.Get(context.Background(), "authz/keys")
	if err != nil {
		t.Fatal(err)
	}
	// The store holds the key sealed: no PEM and no JWK private part.
	for _, bad := range []string{"PRIVATE KEY", `"d":`, `"p":`} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("the stored key holds %q in the clear", bad)
		}
	}
	// Another pair key cannot open it, so the start fails.
	_, err = authz.New(context.Background(), authz.Options{
		Issuer: h.web.URL + "/authz", Audience: audience, Store: h.kv, KeySecret: []byte("another secret of 32 characters!"),
		Registry: anyval.Must(oidcflow.NewRegistry(nil, nil)), Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Offers: h.issuer,
	})
	if err == nil || !strings.Contains(err.Error(), "open the token key") {
		t.Fatalf("New with another secret = %v", err)
	}
}

func TestNewChecksTheOptions(t *testing.T) {
	good := authz.Options{
		Issuer: "https://issuer.example.org/authz", Audience: audience, Store: store.Memory(), KeySecret: []byte(pairSeal),
		Registry: anyval.Must(oidcflow.NewRegistry(nil, nil)), Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Offers: &fakeIssuer{},
	}
	cases := map[string]func(*authz.Options){
		"no issuer":         func(o *authz.Options) { o.Issuer = "" },
		"a relative issuer": func(o *authz.Options) { o.Issuer = "/authz" },
		"no audience":       func(o *authz.Options) { o.Audience = "" },
		"no store":          func(o *authz.Options) { o.Store = nil },
		"a short secret":    func(o *authz.Options) { o.KeySecret = []byte("short") },
		"no registry":       func(o *authz.Options) { o.Registry = nil },
		"no flow":           func(o *authz.Options) { o.Flow = nil },
		"no issuer side":    func(o *authz.Options) { o.Offers = nil },
		"a client without redirect": func(o *authz.Options) {
			o.Clients = []authz.Client{{ID: "x"}}
		},
		"a client with a bad JWK": func(o *authz.Options) {
			o.Clients = []authz.Client{{ID: "x", RedirectURIs: []string{walletCallback}, JWK: []byte(`{"kty":"oct","k":"AAAA"}`)}}
		},
		"a client with a small RSA key": func(o *authz.Options) {
			small := anyval.Must(rsa.GenerateKey(rand.Reader, 1024)) //nolint:gosec // G403: the case proves that the server refuses a small key
			raw := anyval.Must(json.Marshal(anyval.Must(jose.PublicJWK(small, ""))))
			o.Clients = []authz.Client{{ID: "x", RedirectURIs: []string{walletCallback}, JWK: raw}}
		},
		"a client with a private key": func(o *authz.Options) {
			raw := anyval.Must(json.Marshal(jose.JWK{Key: anyval.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))}))
			o.Clients = []authz.Client{{ID: "x", RedirectURIs: []string{walletCallback}, JWK: raw}}
		},
		"a client with no id": func(o *authz.Options) {
			o.Clients = []authz.Client{{RedirectURIs: []string{walletCallback}}}
		},
		"a client with a relative redirect": func(o *authz.Options) {
			o.Clients = []authz.Client{{ID: "x", RedirectURIs: []string{"/callback"}}}
		},
	}
	for name, change := range cases {
		o := good
		change(&o)
		if _, err := authz.New(context.Background(), o); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	if _, err := authz.New(context.Background(), good); err != nil {
		t.Fatalf("good options: %v", err)
	}
}

func TestParseClients(t *testing.T) {
	list, err := authz.ParseClients(`[{"client_id":"wallet","redirect_uris":["https://wallet.example.org/cb"]}]`)
	if err != nil || len(list) != 1 || list[0].ID != "wallet" {
		t.Fatalf("ParseClients = %v, %v", list, err)
	}
	if list, err = authz.ParseClients(""); err != nil || list != nil {
		t.Fatalf("empty = %v, %v", list, err)
	}
	if _, err = authz.ParseClients("{"); err == nil {
		t.Fatal("ParseClients accepted a broken list")
	}
}

func TestNoHolderProviderIsAServerError(t *testing.T) {
	h := newHarness(t)
	// A server whose registry holds no holder provider.
	reg := anyval.Must(oidcflow.NewRegistry(nil, nil))
	if _, err := reg.Put(oidcflow.Provider{ID: "staff", DisplayName: "Staff", DiscoveryURL: h.idp.DiscoveryURL(),
		ClientID: "x", Enabled: true, Roles: []string{"issuer"}}); err != nil {
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
	r := newRequest(publicClient, walletCallback)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+r.query().Encode(), nil))
	wantError(t, anyval.Must(url.Parse(rec.Header().Get("Location"))), "temporarily_unavailable", r.state)
}

// bindOffer adds an offer bound by the claim of the ID token to the
// member number of the subject.
func (h *harness) bindOffer(id, tokenClaim, number string) {
	h.issuer.mu.Lock()
	defer h.issuer.mu.Unlock()
	h.issuer.offers[id] = authz.Offer{
		ConfigID: "Membership",
		Subject:  map[string]any{"fullName": "Amina Njeri", "memberID": number},
		Binding:  authz.Binding{TokenClaim: tokenClaim, SubjectClaim: "memberID"},
	}
}

// TestBindingNeedsAClaimTheProviderVouchesFor is finding 2 of the review:
// a person who registers the user name 12345678 at a holder realm with
// self registration must not claim the offer of the member 12345678.
// A binding rule matches email and phone_number only when the provider
// calls them verified, and sub always. Any other claim matches only
// when the provider record lists it (ADR-056 decision 2).
func TestBindingNeedsAClaimTheProviderVouchesFor(t *testing.T) {
	cases := []struct {
		name     string
		claim    string
		idToken  map[string]any
		verified []string
		match    bool
	}{
		{"a chosen user name", "preferred_username", map[string]any{"preferred_username": "12345678"}, nil, false},
		{"a custom attribute", "national_id", map[string]any{"national_id": "12345678"}, nil, false},
		{"an unverified phone", "phone_number", map[string]any{"phone_number": "12345678"}, nil, false},
		{"a phone verified false", "phone_number", map[string]any{"phone_number": "12345678", "phone_number_verified": false}, nil, false},
		{"a verified phone", "phone_number", map[string]any{"phone_number": "12345678", "phone_number_verified": true}, nil, true},
		{"a verified phone as text", "phone_number", map[string]any{"phone_number": "12345678", "phone_number_verified": "true"}, nil, true},
		{"a listed claim", "national_id", map[string]any{"national_id": "12345678"}, []string{"national_id"}, true},
		{"a listed user name", "preferred_username", map[string]any{"preferred_username": "12345678"}, []string{"preferred_username"}, true},
	}
	for _, c := range cases {
		h := newHarnessVouching(t, c.verified...)
		h.idp.Claims = c.idToken
		h.bindOffer("offer-1", c.claim, "12345678")
		r := newRequest(publicClient, walletCallback)
		r.issuerState = "offer-1"
		back := h.signIn(r)
		if c.match != (back.Query().Get("code") != "") {
			t.Errorf("%s: redirect = %s, want a match %v", c.name, back, c.match)
		}
		if !c.match && back.Query().Get("error_description") != authz.DeniedAnotherPerson {
			t.Errorf("%s: description = %q", c.name, back.Query().Get("error_description"))
		}
	}
	// sub is the account at the provider, which the provider vouches for.
	h := newHarness(t)
	h.idp.Subject = "user-7"
	h.bindOffer("offer-1", "sub", "user-7")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	if back := h.signIn(r); back.Query().Get("code") == "" {
		t.Errorf("sub did not match: %s", back)
	}
}

// TestWalletInitiatedClaimNeedsAVouchedClaim: the sign in source finds
// the record by a claim of the ID token, so the same rule holds there.
func TestWalletInitiatedClaimNeedsAVouchedClaim(t *testing.T) {
	h := newHarness(t)
	if err := h.srv.SetSignInSource(context.Background(), authz.SignInSource{
		ConfigID: "ResidencePermit", SourceID: "registry", Field: "national_id", TokenClaim: "preferred_username",
	}); err != nil {
		t.Fatal(err)
	}
	h.lookup.rows["12345678"] = `{"fullName":"Amina Njeri"}`
	h.idp.Claims = map[string]any{"preferred_username": "12345678"}
	r := newRequest(publicClient, walletCallback)
	back := h.signIn(r)
	wantError(t, back, "access_denied", r.state)
	if len(h.issuer.staged) != 0 {
		t.Fatalf("a row was staged: %v", h.issuer.staged)
	}
}

// countingStore counts the walks of the store.
type countingStore struct {
	store.KeyValue
	mu    sync.Mutex
	lists int
}

func (c *countingStore) List(ctx context.Context, prefix string) ([]string, error) {
	c.mu.Lock()
	c.lists++
	c.mu.Unlock()
	return c.KeyValue.List(ctx, prefix)
}

func (c *countingStore) walks() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lists
}

// logins returns the number of stored sign ins.
func (h *harness) logins() int {
	h.t.Helper()
	keys, err := h.kv.List(context.Background(), "authz/logins")
	if err != nil {
		h.t.Fatal(err)
	}
	return len(keys)
}

// TestAuthorizeBoundsItsParametersBeforeAnyWrite is finding 4 of the
// review: an authorization request that anybody can send kept its whole
// state for ten minutes. The server now refuses an oversized parameter
// or an issuer_state that is no offer id before it reads or writes the
// store, and it does not echo such a value (ADR-056 decision 5).
func TestAuthorizeBoundsItsParametersBeforeAnyWrite(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	long := strings.Repeat("s", 513)
	r := newRequest(publicClient, walletCallback)
	r.state = long
	res := h.authorize(r.query())
	back := anyval.Must(url.Parse(res.Header.Get("Location")))
	if back.Query().Get("error") != "invalid_request" || back.Query().Has("state") || strings.Contains(res.Header.Get("Location"), long) {
		t.Errorf("a long state = %d %s", res.StatusCode, back)
	}
	for name, change := range map[string]func(*request){
		"an issuer_state with a slash": func(r *request) { r.issuerState = "../offer-1" },
		"a long issuer_state":          func(r *request) { r.issuerState = strings.Repeat("a", 65) },
		"long authorization_details": func(r *request) {
			r.extra = url.Values{"authorization_details": {`[{"type":"openid_credential","x":"` + strings.Repeat("d", 4096) + `"}]`}}
		},
		"a long scope": func(r *request) { r.extra = url.Values{"scope": {strings.Repeat("vca_credential ", 80)}} },
	} {
		r := newRequest(publicClient, walletCallback)
		change(&r)
		back := anyval.Must(url.Parse(h.authorize(r.query()).Header.Get("Location")))
		wantError(t, back, "invalid_request", r.state)
		if name != "long authorization_details" && name != "a long scope" && h.issuer.lookups != 0 {
			t.Errorf("%s: the server read the offers", name)
		}
	}
	// An oversized client id or query gets a page, and no echo.
	longClient := strings.Repeat("c", 129)
	res = h.authorize(url.Values{"client_id": {longClient}})
	if res.StatusCode != http.StatusBadRequest || strings.Contains(res.Body, longClient) {
		t.Errorf("a long client = %d %s", res.StatusCode, res.Body)
	}
	q := newRequest(publicClient, walletCallback).query()
	q.Set("padding", strings.Repeat("p", 8200))
	if res = h.authorize(q); res.StatusCode != http.StatusRequestURITooLong {
		t.Errorf("a long query = %d", res.StatusCode)
	}
	if n := h.logins(); n != 0 {
		t.Fatalf("%d sign ins were stored", n)
	}
}

// TestAuthzRoutesLimitTheRateOfASource: every public route limits the
// requests of one source, and authorize limits all sources together.
// A request over the limit gets 429 and writes nothing (ADR-056
// decision 5).
func TestAuthzRoutesLimitTheRateOfASource(t *testing.T) {
	limits := authz.Limits{
		Browser: authz.RateLimit{PerSecond: 1, Burst: 3}, Client: authz.RateLimit{PerSecond: 1, Burst: 2},
		Authorize: authz.RateLimit{PerSecond: 1, Burst: 5},
	}
	h := newHarnessWith(t, harnessOptions{limits: &limits})
	send := func(path, source string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.web.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if source != "" {
			req.Header.Set("X-Forwarded-For", "198.51.100.1, "+source)
		}
		res, err := h.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		anyval.Discard(res.Body.Close())
		if res.StatusCode == http.StatusTooManyRequests && res.Header.Get("Retry-After") == "" {
			t.Error("a 429 without Retry-After")
		}
		return res.StatusCode
	}
	authorize := "/authz/authorize?" + newRequest(publicClient, walletCallback).query().Encode()
	for i := range 3 {
		if got := send(authorize, "203.0.113.1"); got != http.StatusFound {
			t.Fatalf("request %d = %d", i, got)
		}
	}
	if got := send(authorize, "203.0.113.1"); got != http.StatusTooManyRequests {
		t.Fatalf("the fourth request = %d", got)
	}
	// Another source has its own bucket, until authorize as a whole runs dry.
	if got := send(authorize, "203.0.113.2"); got != http.StatusFound {
		t.Fatalf("another source = %d", got)
	}
	if got := send(authorize, "203.0.113.3"); got != http.StatusFound {
		t.Fatalf("a third source = %d", got)
	}
	if got := send(authorize, "203.0.113.4"); got != http.StatusTooManyRequests {
		t.Fatalf("authorize over the total = %d", got)
	}
	if n := h.logins(); n != 5 {
		t.Fatalf("%d sign ins, want 5", n)
	}
	// The client routes have their own budget per source.
	for i := range 2 {
		if got := send("/authz/.well-known/jwks.json", "203.0.113.1"); got != http.StatusOK {
			t.Fatalf("jwks %d = %d", i, got)
		}
	}
	if got := send("/authz/.well-known/jwks.json", "203.0.113.1"); got != http.StatusTooManyRequests {
		t.Fatalf("jwks over the limit = %d", got)
	}
	// Without a forwarded address the peer is the source. Time refills.
	h.advance(10 * time.Second)
	if got := send("/authz/.well-known/jwks.json", ""); got != http.StatusOK {
		t.Fatalf("the peer = %d", got)
	}
	if got := send(authorize, "203.0.113.1"); got != http.StatusFound {
		t.Fatalf("after a pause = %d", got)
	}
}

// TestAClaimWalksNoStore: a wallet initiated claim reads its sign in
// source from one document, so no request lists the store (ADR-056
// decision 5).
func TestAClaimWalksNoStore(t *testing.T) {
	kv := &countingStore{KeyValue: store.Memory()}
	h := newHarnessWith(t, harnessOptions{kv: kv})
	for _, src := range []authz.SignInSource{
		{ConfigID: "ResidencePermit", SourceID: "registry", Field: "email", TokenClaim: "email"},
		{ConfigID: "Other", SourceID: "registry", Field: "email", TokenClaim: "email"},
		{ConfigID: "ResidencePermit", SourceID: "registry-2", Field: "email", TokenClaim: "email"},
	} {
		if err := h.srv.SetSignInSource(context.Background(), src); err != nil {
			t.Fatal(err)
		}
	}
	h.lookup.rows["amina@example.org"] = `{"fullName":"Amina Njeri"}`
	before := kv.walks()
	r := newRequest(publicClient, walletCallback)
	r.extra = url.Values{"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"ResidencePermit"}]`}}
	back := h.signIn(r)
	if back.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", back)
	}
	if got := kv.walks() - before; got != 0 {
		t.Fatalf("the claim listed the store %d times", got)
	}
	if calls := strings.Join(h.lookup.calls, " "); calls != "registry-2/email=amina@example.org" {
		t.Fatalf("lookups = %s, want the last source of the configuration", calls)
	}
}

// TestTheRowLivesAsLongAsItsCodeAndToken is finding 7 of the review: the
// row of a claim lived as long as the offer, well past its token. The
// server now gives each row the life of its code and its token, and it
// ends the offer data once the token is out (ADR-056 decisions 3 and 4).
func TestTheRowLivesAsLongAsItsCodeAndToken(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	start := h.clock()
	_, answer := h.claimToken("offer-1")
	if answer["access_token"] == "" {
		t.Fatal("no token")
	}
	if len(h.issuer.expires) != 1 {
		t.Fatalf("expires = %v", h.issuer.expires)
	}
	for _, at := range h.issuer.expires {
		if !at.Equal(start.Add(authz.RowTTL)) {
			t.Fatalf("the row ends at %v, want %v", at, start.Add(authz.RowTTL))
		}
	}
	if authz.RowTTL < authz.CodeTTL+authz.TokenTTL || authz.RowTTL > authz.CodeTTL+authz.TokenTTL+2*time.Minute {
		t.Fatalf("RowTTL = %v", authz.RowTTL)
	}
	if strings.Join(h.issuer.finished, ",") != "offer-1" {
		t.Fatalf("finished = %v, want the offer after the token", h.issuer.finished)
	}
}

// TestABurntCodeReopensItsOffer is finding 6 of the review: a code that
// leaked without its verifier let an attacker end the claim of the
// holder. The code still works once, but a code that fails before any
// token reopens its offer and removes its row, and the server logs the
// attempt at Warn with the offer (ADR-056 decision 4).
func TestABurntCodeReopensItsOffer(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	sub := ""
	for key := range h.issuer.staged {
		sub = key
	}
	stolen := codeForm(r, back.Query().Get("code"))
	stolen.Set("code_verifier", oidc.NewVerifier())
	if status, answer := h.token(stolen); status != http.StatusBadRequest || answer["error"] != "invalid_grant" {
		t.Fatalf("the stolen code = %d %v", status, answer)
	}
	if strings.Join(h.issuer.reopened, ",") != "offer-1" || strings.Join(h.issuer.unstaged, ",") != sub {
		t.Fatalf("reopened = %v, unstaged = %v; want the offer and the row %s", h.issuer.reopened, h.issuer.unstaged, sub)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "offer=offer-1") {
		t.Fatalf("no warning names the offer:\n%s", logs)
	}
	// The holder's own trade now fails, but the offer is open again.
	if status, answer := h.token(codeForm(r, back.Query().Get("code"))); status != http.StatusBadRequest || answer["error"] != "invalid_grant" {
		t.Fatalf("the holder's trade = %d %v", status, answer)
	}
	if _, answer := h.claimToken("offer-1"); answer["access_token"] == "" {
		t.Fatal("the reopened offer gave no token")
	}
	if len(h.issuer.reopened) != 1 {
		t.Fatalf("reopened = %v", h.issuer.reopened)
	}
}

// TestAReplayedCodeIsLogged: a code that comes back after its token
// revokes the row and logs a warning that names the offer. The offer
// stays closed, because a token went out.
func TestAReplayedCodeIsLogged(t *testing.T) {
	h := newHarness(t)
	h.addOffer("offer-1", "amina@example.org")
	r := newRequest(publicClient, walletCallback)
	r.issuerState = "offer-1"
	back := h.signIn(r)
	form := codeForm(r, back.Query().Get("code"))
	if status, _ := h.token(form); status != http.StatusOK {
		t.Fatalf("first = %d", status)
	}
	h.token(form)
	if len(h.issuer.reopened) != 0 {
		t.Fatalf("a replay after a token reopened %v", h.issuer.reopened)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "offer=offer-1") {
		t.Fatalf("no warning names the offer:\n%s", logs)
	}
}

// TestClientAssertionTimesAreChecked: iat and nbf of a client assertion
// may not lie in the future, and an assertion lives ten minutes at most
// from iat to exp (RFC 7523 section 3, review finding 13).
func TestClientAssertionTimesAreChecked(t *testing.T) {
	h := newHarness(t)
	now := h.clock()
	for name, claims := range map[string]map[string]any{
		"nbf ahead":      {"nbf": now.Add(5 * time.Minute).Unix()},
		"iat ahead":      {"iat": now.Add(5 * time.Minute).Unix()},
		"a long life":    {"iat": now.Add(-time.Hour).Unix()},
		"iat not number": {"iat": "now"},
	} {
		id := "offer-" + strings.ReplaceAll(name, " ", "-")
		h.addOffer(id, "amina@example.org")
		r := newRequest(keyClient, keyRedirect)
		r.issuerState = id
		back := h.signIn(r)
		form := withAssertion(codeForm(r, back.Query().Get("code")), h.assertion(h.walletKey, claims))
		if status, answer := h.token(form); status != http.StatusUnauthorized || answer["error"] != "invalid_client" {
			t.Errorf("%s: token = %d %v", name, status, answer)
		}
	}
	// A skew of a few seconds and a missing iat pass.
	for name, claims := range map[string]map[string]any{
		"a small skew": {"iat": now.Add(20 * time.Second).Unix(), "nbf": now.Add(20 * time.Second).Unix()},
		"no iat":       {"iat": nil},
	} {
		id := "offer-" + strings.ReplaceAll(name, " ", "-")
		h.addOffer(id, "amina@example.org")
		r := newRequest(keyClient, keyRedirect)
		r.issuerState = id
		back := h.signIn(r)
		form := withAssertion(codeForm(r, back.Query().Get("code")), h.assertion(h.walletKey, claims))
		if status, answer := h.token(form); status != http.StatusOK {
			t.Errorf("%s: token = %d %v", name, status, answer)
		}
	}
}

// TestInvalidClientNamesTheSchemeUsed: RFC 6749 section 5.2 asks for
// the scheme of the failed authentication. Basic gets a Basic
// challenge, and a client of the form body gets none.
func TestInvalidClientNamesTheSchemeUsed(t *testing.T) {
	h := newHarness(t)
	post := func(form url.Values, basic bool) reply {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.web.URL+"/authz/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			req.SetBasicAuth(publicClient, "secret")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		anyval.Discard(res.Body.Close())
		return reply{StatusCode: res.StatusCode, Header: res.Header}
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {"nobody"}}
	if res := post(form, true); res.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("basic = %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	if res := post(form, false); res.StatusCode != http.StatusUnauthorized || res.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("form = %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
}
