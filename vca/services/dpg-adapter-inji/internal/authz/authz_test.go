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
	unstaged []string
	claimed  map[string]bool
}

func (f *fakeIssuer) Offer(_ context.Context, id string) (authz.Offer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.offers[id]
	return o, ok && !f.claimed[id]
}

func (f *fakeIssuer) StageOffer(_ context.Context, id, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimed[id] {
		return errors.New("claimed")
	}
	f.claimed[id] = true
	f.staged[key] = "offer:" + id
	return nil
}

func (f *fakeIssuer) StageSubject(_ context.Context, configID, subject, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staged[key] = configID + ":" + subject
	return nil
}

func (f *fakeIssuer) Unstage(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	return newHarnessVouching(t)
}

// newHarnessVouching is a harness whose holder provider record lists
// the claims it verifies beyond the standard ones.
func newHarnessVouching(t *testing.T, verified ...string) *harness {
	t.Helper()
	h := &harness{
		verified: verified,
		t:        t,
		idp:      oidctest.New(),
		issuer:   &fakeIssuer{offers: map[string]authz.Offer{}, staged: map[string]string{}, claimed: map[string]bool{}},
		lookup:   &fakeLookup{rows: map[string]string{}},
		kv:       store.Memory(),
		now:      time.Now().UTC().Truncate(time.Second),
		browser: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
	t.Cleanup(h.idp.Close)
	h.idp.ClientID = "vca-inji-authz"
	h.idp.Claims = map[string]any{"email": "amina@example.org", "email_verified": true}
	h.walletKey = anyval.Must(rsa.GenerateKey(rand.Reader, 2048))
	mux := http.NewServeMux()
	h.web = httptest.NewServer(mux)
	t.Cleanup(h.web.Close)
	h.srv = h.build(t, h.kv)
	mux.Handle("/authz/", http.StripPrefix("/authz", h.srv.Handler()))
	return h
}

// build makes a server on one store, as a start of the adapter does.
func (h *harness) build(t *testing.T, kv store.KeyValue) *authz.Server {
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
	srv, err := authz.New(context.Background(), authz.Options{
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
		Now:      h.clock,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
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
	raw, err := h.kv.Get(context.Background(), "authz/key")
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
