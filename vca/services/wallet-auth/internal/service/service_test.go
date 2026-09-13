// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	walletauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/grants"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/server"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/wallets"
)

type fakeBackend struct {
	backendv1connect.UnimplementedHolderBackendServiceHandler
	calls int
}

func (b *fakeBackend) Register(_ context.Context, req *connect.Request[backendv1.RegisterRequest]) (*connect.Response[backendv1.RegisterResponse], error) {
	b.calls++
	if strings.Contains(req.Msg.GetPairwiseSubject(), "|") {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("raw subject leaked"))
	}
	return connect.NewResponse(&backendv1.RegisterResponse{WalletId: "w-" + req.Msg.GetPairwiseSubject()[:8]}), nil
}

type fixture struct {
	idp     *oidctest.Provider
	svc     *service.Service
	srv     *httptest.Server
	client  walletauthv1connect.WalletAuthServiceClient
	backend *fakeBackend
	store   *oidcflow.MemoryPersister
	limiter *limits.Memory
}

func withBearer(tok string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+tok)
			return next(ctx, req)
		}
	}))
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	idp := oidctest.New()
	t.Cleanup(idp.Close)
	be := &fakeBackend{}
	bePath, beH := backendv1connect.NewHolderBackendServiceHandler(be)
	beMux := http.NewServeMux()
	beMux.Handle(bePath, beH)
	beSrv := httptest.NewServer(beMux)
	t.Cleanup(beSrv.Close)

	store := oidcflow.NewMemoryPersister()
	providers, _ := oidcflow.NewRegistry(store, nil)
	walletReg, _ := wallets.New(store, nil)
	key, _ := oidcflow.GenerateKey()
	signer, _ := oidcflow.NewSigner(key, "http://wallet.test", server.Audience, time.Minute, nil)
	csrf, _ := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	vault, _ := grants.New([]byte("0123456789abcdef0123456789abcdef"), store, nil)
	limiter := limits.NewMemory(100, time.Minute, time.Minute, nil)
	f := &fixture{idp: idp, backend: be, store: store, limiter: limiter}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	cfg := config.Config{
		PublicBaseURL:  f.srv.URL,
		RedirectURI:    f.srv.URL + "/wallet/auth/callback",
		AdminToken:     "admin-token",
		CookieName:     "wsess",
		InsecureCookie: true,
		SessionTTL:     time.Minute,
		Salt:           []byte("deployment-salt-0123456789"),
		GrantType:      config.DefaultGrantType,
		LogoutRedirect: "/bye",
	}
	f.svc = service.New(cfg, service.Deps{
		Flow:      &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Providers: providers,
		Wallets:   walletReg,
		Registrar: wallets.NewConnectRegistrar(beSrv.Client(), beSrv.URL),
		Grants:    vault,
		Limiter:   limiter,
		Signer:    signer,
		CSRF:      csrf,
	})
	mux.Handle("/", server.Handler(f.svc))
	_, _ = providers.Put(oidcflow.Provider{ID: "esignet", DisplayName: "National ID", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Scopes: []string{"openid"}, LogoURI: "https://idp/logo.png", Enabled: true})
	f.client = walletauthv1connect.NewWalletAuthServiceClient(f.srv.Client(), f.srv.URL)
	return f
}

func browser() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type callbackBody struct {
	SessionToken string          `json:"session_token"`
	CSRFToken    string          `json:"csrf_token"`
	Claims       oidcflow.Claims `json:"claims"`
}

func (f *fixture) login(t *testing.T) (callbackBody, *http.Cookie) {
	t.Helper()
	res, err := browser().Get(f.srv.URL + "/wallet/auth/login?provider=esignet")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", res.StatusCode)
	}
	loc, _ := f.idp.Authorize(res.Header.Get("Location"))
	if !strings.HasPrefix(loc, f.srv.URL+"/wallet/auth/callback?") {
		t.Fatalf("redirect uri: %s", loc)
	}
	res, err = browser().Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	var body callbackBody
	_ = json.NewDecoder(res.Body).Decode(&body)
	return body, res.Cookies()[0]
}

func TestBrowserFlow(t *testing.T) {
	f := newFixture(t)
	body, cookie := f.login(t)
	raw := oidcflow.PairwiseSubject(f.idp.Issuer(), "user-1")
	if body.Claims.Subject == raw || strings.Contains(body.Claims.Subject, "user-1") || body.Claims.Subject != oidcflow.HashSubject([]byte("deployment-salt-0123456789"), raw) {
		t.Fatalf("subject: %s", body.Claims.Subject)
	}
	if !strings.HasPrefix(body.Claims.WalletID, "w-") || body.Claims.HasHolderKey || f.backend.calls != 1 {
		t.Fatalf("wallet: %+v calls=%d", body.Claims, f.backend.calls)
	}
	if cookie.Name != "wsess" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie: %+v", cookie)
	}
	// The persisted store holds no iss, sub, or access token.
	for _, doc := range []string{"wallets", "grants"} {
		var v any
		_ = f.store.Load(doc, &v)
		enc, _ := json.Marshal(v)
		if strings.Contains(string(enc), "user-1") || strings.Contains(string(enc), f.idp.Issuer()) || strings.Contains(string(enc), "at-") {
			t.Fatalf("%s leaks personal data: %s", doc, enc)
		}
	}
	// A second login reuses the wallet.
	body2, _ := f.login(t)
	if body2.Claims.WalletID != body.Claims.WalletID || f.backend.calls != 1 {
		t.Fatal("wallet not reused")
	}
	// Logout goes to the provider with the post logout redirect.
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/wallet/auth/logout", nil)
	req.Header.Set(oidcflow.CSRFHeader, body.CSRFToken)
	req.AddCookie(cookie)
	out, _ := browser().Do(req)
	out.Body.Close()
	loc := out.Header.Get("Location")
	if out.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, f.idp.Issuer()+"/logout?") || !strings.Contains(loc, "id_token_hint=") || !strings.Contains(loc, url.QueryEscape(f.srv.URL+"/bye")) {
		t.Fatalf("logout: %d %s", out.StatusCode, loc)
	}
	intro, _ := f.client.Introspect(context.Background(), connect.NewRequest(&walletauthv1.IntrospectRequest{SessionToken: body.SessionToken}))
	if intro.Msg.GetActive() {
		t.Fatal("still active")
	}
	// The grant is gone with the session.
	if _, err := f.client.GetAuthorizationGrant(context.Background(), connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: body.SessionToken, CredentialIssuer: "https://issuer.example"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("grant after logout: %v", err)
	}
	for _, p := range []string{"/healthz", "/readyz", "/.well-known/jwks.json"} {
		r, _ := http.Get(f.srv.URL + p)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("%s: %d", p, r.StatusCode)
		}
	}
}

func TestRPCFlowAndGrant(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	list, err := f.client.ListProviders(ctx, connect.NewRequest(&walletauthv1.ListProvidersRequest{}))
	if err != nil || len(list.Msg.GetProviders()) != 1 || list.Msg.GetProviders()[0].GetLogoUri() == "" || list.Msg.GetProviders()[0].GetIssuer() != f.idp.Issuer() {
		t.Fatalf("list: %+v %v", list, err)
	}
	start, err := f.client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet", ReturnTo: "/wallet"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(start.Msg.GetAuthorizationUrl(), "scope=openid&") && !strings.HasSuffix(start.Msg.GetAuthorizationUrl(), "scope=openid") {
		t.Fatalf("scopes: %s", start.Msg.GetAuthorizationUrl())
	}
	loc, _ := f.idp.Authorize(start.Msg.GetAuthorizationUrl())
	u, _ := url.Parse(loc)
	cb, err := f.client.LoginCallback(ctx, connect.NewRequest(&walletauthv1.LoginCallbackRequest{State: u.Query().Get("state"), Code: u.Query().Get("code")}))
	if err != nil || !cb.Msg.GetNewWallet() || cb.Msg.GetReturnTo() != "/wallet" || cb.Msg.GetSession().GetWalletId() == "" || cb.Msg.GetSession().GetProviderId() != "esignet" {
		t.Fatalf("callback: %+v %v", cb, err)
	}
	tok := cb.Msg.GetSessionToken()
	// The grant is the IdP access token, bound to the first issuer.
	g, err := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: tok, CredentialIssuer: "https://issuer.example"}))
	if err != nil || !strings.HasPrefix(g.Msg.GetGrant(), "at-") || g.Msg.GetGrantType() != config.DefaultGrantType || g.Msg.GetExpiresAt() == nil {
		t.Fatalf("grant: %+v %v", g, err)
	}
	if _, err := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: tok, CredentialIssuer: "https://other.example"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("other issuer: %v", err)
	}
	if _, err := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: tok, CredentialIssuer: "issuer"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad issuer: %v", err)
	}
	// A session without a stored grant.
	other, _, _ := f.svc.Signer().Issue(oidcflow.Claims{Subject: "x", Provider: "esignet"})
	if _, err := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: other, CredentialIssuer: "https://issuer.example"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no grant: %v", err)
	}
	// Logout through the RPC.
	lo, err := f.client.Logout(ctx, connect.NewRequest(&walletauthv1.LogoutRequest{SessionToken: tok}))
	if err != nil || !strings.Contains(lo.Msg.GetProviderLogoutUrl(), "/logout?") {
		t.Fatalf("logout: %+v %v", lo, err)
	}
	if _, err := f.client.Logout(ctx, connect.NewRequest(&walletauthv1.LogoutRequest{SessionToken: tok})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("logout twice: %v", err)
	}
	// Failures.
	if _, err := f.client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "nope"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := f.client.LoginCallback(ctx, connect.NewRequest(&walletauthv1.LoginCallbackRequest{State: "nope", Code: "c"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("state: %v", err)
	}
	start, _ = f.client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"}))
	if _, err := f.client.LoginCallback(ctx, connect.NewRequest(&walletauthv1.LoginCallbackRequest{State: start.Msg.GetState(), Error: "access_denied"})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("provider error: %v", err)
	}
	r, _ := http.Get(f.srv.URL + "/vca.walletauth.v1.WalletAuthService/Introspect?session_token=x")
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("query token: %d", r.StatusCode)
	}
	// Providers come through the admin RPC with the holder role.
	admin := adminv1connect.NewAdminServiceClient(f.srv.Client(), f.srv.URL, withBearer("admin-token"))
	created, err := admin.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: &adminv1.AuthProvider{DisplayName: "Other", DiscoveryUrl: f.idp.DiscoveryURL(), ClientId: "client", Enabled: true}}))
	if err != nil || created.Msg.GetProvider().GetRoles()[0].String() != "ROLE_HOLDER" {
		t.Fatalf("admin: %+v %v", created, err)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	limited := limits.NewMemory(2, time.Minute, time.Minute, nil)
	cfg := f.svc.Config()
	svc := service.New(cfg, service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Wallets: f.svc.Wallets(), Signer: f.svc.Signer(), Limiter: limited})
	srv := httptest.NewServer(server.Handler(svc))
	defer srv.Close()
	client := walletauthv1connect.NewWalletAuthServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"})); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if _, err := client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("limit: %v", err)
	}
	res, _ := browser().Get(srv.URL + "/login?provider=esignet")
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("http limit: %d", res.StatusCode)
	}
	// The Redis stub makes login unavailable.
	stub := service.New(cfg, service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Wallets: f.svc.Wallets(), Signer: f.svc.Signer(), Limiter: &limits.RedisLimiter{}})
	if _, err := stub.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("stub: %v", err)
	}
	// No limiter at all allows.
	none := service.New(cfg, service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Wallets: f.svc.Wallets(), Signer: f.svc.Signer()})
	if _, err := none.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"})); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterHolderKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body, _ := f.login(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := jose.PublicJWK(priv, "")
	pubJSON, _ := json.Marshal(pub)
	proof, _ := jose.Sign(priv, "", "JWT", map[string]string{"sid": body.Claims.SID})
	res, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body.SessionToken, PublicJwk: string(pubJSON), Proof: proof}))
	if err != nil || res.Msg.GetThumbprint() == "" || !strings.HasPrefix(res.Msg.GetHolderDid(), "did:jwk:") {
		t.Fatalf("%+v %v", res, err)
	}
	w, _ := f.svc.Wallets().Get(body.Claims.Subject)
	if w.KeyThumbprint != res.Msg.GetThumbprint() || w.HolderDID != res.Msg.GetHolderDid() {
		t.Fatalf("wallet: %+v", w)
	}
	// The next session says the wallet has a key.
	body2, _ := f.login(t)
	if !body2.Claims.HasHolderKey {
		t.Fatal("has_holder_key")
	}
	// Ed25519 with a raw string payload.
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edJWK, _ := jose.PublicJWK(edPub, "")
	edJSON, _ := json.Marshal(edJWK)
	edProof, _ := jose.Sign(edPriv, "", "JWT", body2.Claims.SID)
	if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(edJSON), Proof: edProof})); err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	// Failures.
	cases := []struct {
		name string
		req  *walletauthv1.RegisterHolderKeyRequest
		code connect.Code
	}{
		{"bad session", &walletauthv1.RegisterHolderKeyRequest{SessionToken: "x"}, connect.CodeUnauthenticated},
		{"bad jwk", &walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: "{"}, connect.CodeInvalidArgument},
		{"bad proof", &walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(pubJSON), Proof: "x"}, connect.CodeInvalidArgument},
		{"wrong sid", &walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(pubJSON), Proof: proof}, connect.CodeInvalidArgument},
	}
	for _, c := range cases {
		if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(c.req)); connect.CodeOf(err) != c.code {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A private JWK and a P-384 key are refused.
	privJWK := jose.JWK{Key: priv}
	privJSON, _ := json.Marshal(privJWK)
	if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(privJSON), Proof: proof})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("private jwk: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384JWK := jose.JWK{Key: &p384.PublicKey}
	p384JSON, _ := json.Marshal(p384JWK)
	if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(p384JSON), Proof: proof})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("p384: %v", err)
	}
	// A session whose wallet record is gone.
	orphan, orphanClaims, _ := f.svc.Signer().Issue(oidcflow.Claims{Subject: "orphan", Provider: "esignet"})
	orphanProof, _ := jose.Sign(priv, "", "JWT", map[string]string{"sid": orphanClaims.SID})
	if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: orphan, PublicJwk: string(pubJSON), Proof: orphanProof})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("orphan: %v", err)
	}
}

type failingPending struct{}

func (failingPending) Put(oidcflow.Pending) error           { return errors.New("store down") }
func (failingPending) Take(string) (oidcflow.Pending, bool) { return oidcflow.Pending{}, false }

type failStore struct {
	oidcflow.Persister
	fail bool
}

func (s *failStore) Save(name string, v any) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.Persister.Save(name, v)
}

func TestFailurePaths(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cfg := f.svc.Config()
	base := service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Wallets: f.svc.Wallets(), Signer: f.svc.Signer()}
	d := base
	d.Pending = failingPending{}
	if _, err := service.New(cfg, d).Start(ctx, "esignet", ""); err == nil {
		t.Fatal("pending error hidden")
	}
	// A deleted provider between start and callback.
	mem := oidcflow.NewMemoryPending(nil)
	d = base
	d.Pending = mem
	svc := service.New(cfg, d)
	_ = mem.Put(oidcflow.Pending{State: "s", ProviderID: "gone", ExpiresAt: time.Now().Add(time.Minute)})
	if _, _, _, err := svc.Complete(ctx, "s", "code", ""); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("gone: %v", err)
	}
	_ = mem.Put(oidcflow.Pending{State: "s2", ProviderID: "esignet", RedirectURI: cfg.RedirectURI, Verifier: "v", Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)})
	if _, _, _, err := svc.Complete(ctx, "s2", "bogus", ""); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("bogus code: %v", err)
	}
	// The holder backend is down at first login.
	d = base
	d.Registrar = wallets.NewConnectRegistrar(nil, "http://127.0.0.1:1")
	d.Grants, _ = grants.New([]byte("0123456789abcdef0123456789abcdef"), nil, nil)
	down := service.New(cfg, d)
	if err := runLogin(t, f, down); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("backend down: %v", err)
	}
	// The grant vault cannot persist.
	fs := &failStore{Persister: oidcflow.NewMemoryPersister()}
	d = base
	d.Registrar = wallets.LocalRegistrar{}
	d.Grants, _ = grants.New([]byte("0123456789abcdef0123456789abcdef"), fs, nil)
	fs.fail = true
	if err := runLogin(t, f, service.New(cfg, d)); err == nil {
		t.Fatal("vault error hidden")
	}
	// The wallet store cannot persist.
	freshWallets, _ := wallets.New(fs, nil)
	d = base
	d.Wallets = freshWallets
	d.Registrar = wallets.LocalRegistrar{}
	d.Grants, _ = grants.New([]byte("0123456789abcdef0123456789abcdef"), nil, nil)
	if err := runLogin(t, f, service.New(cfg, d)); err == nil {
		t.Fatal("wallet error hidden")
	}
	// Logout of a session whose provider is gone or unreachable.
	d = base
	d.Grants, _ = grants.New([]byte("0123456789abcdef0123456789abcdef"), nil, nil)
	svc = service.New(cfg, d)
	tok, _, _ := f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "gone"})
	if u, err := svc.End(ctx, tok); err != nil || u != "" {
		t.Fatalf("gone provider: %q %v", u, err)
	}
	_, _ = f.svc.Providers().Put(oidcflow.Provider{ID: "down", DiscoveryURL: "http://127.0.0.1:1/x", ClientID: "c", Enabled: true})
	tok, _, _ = f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "down"})
	if u, err := svc.End(ctx, tok); err != nil || u != "" {
		t.Fatalf("down provider: %q %v", u, err)
	}
	if _, err := svc.Session(ctx, "bad"); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatal(err)
	}
	// A login whose provider returns no access token expiry uses the
	// session expiry for the grant.
	f.idp.ExpiresIn = 0
	body, _ := f.login(t)
	g, err := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: body.SessionToken, CredentialIssuer: "https://issuer.example"}))
	if err != nil || g.Msg.GetExpiresAt().AsTime().Unix() != body.Claims.ExpiresAt {
		t.Fatalf("grant expiry: %+v %v", g, err)
	}
}

// runLogin drives a full login against svc through its Logins methods.
func runLogin(t *testing.T, f *fixture, svc *service.Service) error {
	t.Helper()
	u, err := svc.Start(context.Background(), "esignet", "")
	if err != nil {
		t.Fatal(err)
	}
	loc, err := f.idp.Authorize(u)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(loc)
	_, _, _, err = svc.Complete(context.Background(), q.Query().Get("state"), q.Query().Get("code"), "")
	return err
}
