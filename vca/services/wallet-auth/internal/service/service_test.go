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
	"io"
	"log/slog"
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
	"github.com/centre-for-dpi/vc-adapters/services/internal/serve"
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
	providers, verr := oidcflow.NewRegistry(store, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	walletReg, verr := wallets.New(store, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	key, verr := oidcflow.GenerateKey()
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	signer, verr := oidcflow.NewSigner(key, "http://wallet.test", server.Audience, time.Minute, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	csrf, verr := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	vault, verr := grants.New([]byte("0123456789abcdef0123456789abcdef"), store, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	mux.Handle("/", serve.Handler(serve.Options{
		Handler:      server.Handler(f.svc),
		ReadyMessage: server.ReadyMessage(f.svc),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}))
	if _, putErr := providers.Put(oidcflow.Provider{ID: "esignet", DisplayName: "National ID", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Scopes: []string{"openid"}, LogoURI: "https://idp/logo.png", Enabled: true}); putErr != nil {
		t.Fatalf("unexpected error: %v", putErr)
	}
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
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", res.StatusCode)
	}
	loc, verr := f.idp.Authorize(res.Header.Get("Location"))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if !strings.HasPrefix(loc, f.srv.URL+"/wallet/auth/callback?") {
		t.Fatalf("redirect uri: %s", loc)
	}
	res, err = browser().Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	var body callbackBody
	if cerr := json.NewDecoder(res.Body).Decode(&body); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
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
		if cerr := f.store.Load(doc, &v); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		enc, verr := json.Marshal(v)
		if verr != nil {
			t.Fatalf("unexpected error: %v", verr)
		}
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
	req, verr := http.NewRequest(http.MethodPost, f.srv.URL+"/wallet/auth/logout", nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	req.Header.Set(oidcflow.CSRFHeader, body.CSRFToken)
	req.AddCookie(cookie)
	out, verr := browser().Do(req)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if cerr := out.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	loc := out.Header.Get("Location")
	if out.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, f.idp.Issuer()+"/logout?") || !strings.Contains(loc, "id_token_hint=") || !strings.Contains(loc, url.QueryEscape(f.srv.URL+"/bye")) {
		t.Fatalf("logout: %d %s", out.StatusCode, loc)
	}
	intro, verr := f.client.Introspect(context.Background(), connect.NewRequest(&walletauthv1.IntrospectRequest{SessionToken: body.SessionToken}))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if intro.Msg.GetActive() {
		t.Fatal("still active")
	}
	// The grant is gone with the session.
	if _, err := f.client.GetAuthorizationGrant(context.Background(), connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: body.SessionToken, CredentialIssuer: "https://issuer.example"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("grant after logout: %v", err)
	}
	for _, p := range []string{"/healthz", "/readyz", "/.well-known/jwks.json"} {
		r, verr := http.Get(f.srv.URL + p)
		if verr != nil {
			t.Fatalf("unexpected error: %v", verr)
		}
		if cerr := r.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
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
	loc, verr := f.idp.Authorize(start.Msg.GetAuthorizationUrl())
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	u, verr := url.Parse(loc)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	if _, serr := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: tok, CredentialIssuer: "https://other.example"})); connect.CodeOf(serr) != connect.CodePermissionDenied {
		t.Fatalf("other issuer: %v", serr)
	}
	if _, serr := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: tok, CredentialIssuer: "issuer"})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Fatalf("bad issuer: %v", serr)
	}
	// A session without a stored grant.
	other, _, verr := f.svc.Signer().Issue(oidcflow.Claims{Subject: "x", Provider: "esignet"})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, serr := f.client.GetAuthorizationGrant(ctx, connect.NewRequest(&walletauthv1.GetAuthorizationGrantRequest{SessionToken: other, CredentialIssuer: "https://issuer.example"})); connect.CodeOf(serr) != connect.CodeFailedPrecondition {
		t.Fatalf("no grant: %v", serr)
	}
	// Logout through the RPC.
	lo, err := f.client.Logout(ctx, connect.NewRequest(&walletauthv1.LogoutRequest{SessionToken: tok}))
	if err != nil || !strings.Contains(lo.Msg.GetProviderLogoutUrl(), "/logout?") {
		t.Fatalf("logout: %+v %v", lo, err)
	}
	if _, serr := f.client.Logout(ctx, connect.NewRequest(&walletauthv1.LogoutRequest{SessionToken: tok})); connect.CodeOf(serr) != connect.CodeUnauthenticated {
		t.Fatalf("logout twice: %v", serr)
	}
	// Failures.
	if _, serr := f.client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "nope"})); connect.CodeOf(serr) != connect.CodeNotFound {
		t.Fatalf("unknown: %v", serr)
	}
	if _, serr := f.client.LoginCallback(ctx, connect.NewRequest(&walletauthv1.LoginCallbackRequest{State: "nope", Code: "c"})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Fatalf("state: %v", serr)
	}
	start, loginStartErr := f.client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"}))
	if loginStartErr != nil {
		t.Fatalf("unexpected error: %v", loginStartErr)
	}
	if _, serr := f.client.LoginCallback(ctx, connect.NewRequest(&walletauthv1.LoginCallbackRequest{State: start.Msg.GetState(), Error: "access_denied"})); connect.CodeOf(serr) != connect.CodeUnavailable {
		t.Fatalf("provider error: %v", serr)
	}
	r, verr := http.Get(f.srv.URL + "/vca.walletauth.v1.WalletAuthService/Introspect?session_token=x")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if cerr := r.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
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
	res, verr := browser().Get(srv.URL + "/login?provider=esignet")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
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
	priv, verr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	pub, verr := jose.PublicJWK(priv, "")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	pubJSON, verr := json.Marshal(pub)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	proof, verr := jose.Sign(priv, "", "JWT", map[string]string{"sid": body.Claims.SID})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	res, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body.SessionToken, PublicJwk: string(pubJSON), Proof: proof}))
	if err != nil || res.Msg.GetThumbprint() == "" || !strings.HasPrefix(res.Msg.GetHolderDid(), "did:jwk:") {
		t.Fatalf("%+v %v", res, err)
	}
	w, verr := f.svc.Wallets().Get(body.Claims.Subject)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if w.KeyThumbprint != res.Msg.GetThumbprint() || w.HolderDID != res.Msg.GetHolderDid() {
		t.Fatalf("wallet: %+v", w)
	}
	// The next session says the wallet has a key.
	body2, _ := f.login(t)
	if !body2.Claims.HasHolderKey {
		t.Fatal("has_holder_key")
	}
	// Ed25519 with a raw string payload.
	edPub, edPriv, verr := ed25519.GenerateKey(rand.Reader)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	edJWK, verr := jose.PublicJWK(edPub, "")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	edJSON, verr := json.Marshal(edJWK)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	edProof, verr := jose.Sign(edPriv, "", "JWT", body2.Claims.SID)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	privJSON, verr := json.Marshal(privJWK)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(privJSON), Proof: proof})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("private jwk: %v", err)
	}
	p384, verr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	p384JWK := jose.JWK{Key: &p384.PublicKey}
	p384JSON, verr := json.Marshal(p384JWK)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := f.client.RegisterHolderKey(ctx, connect.NewRequest(&walletauthv1.RegisterHolderKeyRequest{SessionToken: body2.SessionToken, PublicJwk: string(p384JSON), Proof: proof})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("p384: %v", err)
	}
	// A session whose wallet record is gone.
	orphan, orphanClaims, verr := f.svc.Signer().Issue(oidcflow.Claims{Subject: "orphan", Provider: "esignet"})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	orphanProof, verr := jose.Sign(priv, "", "JWT", map[string]string{"sid": orphanClaims.SID})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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

// TestRegisterStartsARegistration is ADR-035 decision 3 for the holder:
// Register begins a pending login at the register action of the
// provider and the callback finishes it like a login. A generic provider
// without prompt=create gives ErrRegisterUnsupported, an unknown one
// ErrProviderNotFound, and a pending store fault surfaces.
func TestRegisterStartsARegistration(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Register(ctx, "esignet", "/wallet/"); !errors.Is(err, oidcflow.ErrRegisterUnsupported) {
		t.Fatalf("generic provider: %v", err)
	}
	if _, err := f.svc.Register(ctx, "nope", ""); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("unknown provider: %v", err)
	}
	create := oidctest.New()
	create.PromptValuesSupported = []string{"create"}
	t.Cleanup(create.Close)
	if _, err := f.svc.Providers().Put(oidcflow.Provider{ID: "create", DisplayName: "Create", DiscoveryURL: create.DiscoveryURL(), ClientID: create.ClientID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	u, err := f.svc.Register(ctx, "create", "/wallet/")
	if err != nil || !strings.Contains(u, "prompt=create") {
		t.Fatalf("Register = %q, %v", u, err)
	}
	back, err := create.Authorize(u)
	if err != nil {
		t.Fatal(err)
	}
	res, err := browser().Get(back)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/wallet/" {
		t.Errorf("callback after a registration: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	d := service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Wallets: f.svc.Wallets(), Signer: f.svc.Signer(), Pending: failingPending{}}
	if _, err := service.New(f.svc.Config(), d).Register(ctx, "create", ""); err == nil {
		t.Fatal("pending error hidden")
	}
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
	if cerr := mem.Put(oidcflow.Pending{State: "s", ProviderID: "gone", ExpiresAt: time.Now().Add(time.Minute)}); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if _, _, _, err := svc.Complete(ctx, "s", "code", ""); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("gone: %v", err)
	}
	if cerr := mem.Put(oidcflow.Pending{State: "s2", ProviderID: "esignet", RedirectURI: cfg.RedirectURI, Verifier: "v", Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)}); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if _, _, _, err := svc.Complete(ctx, "s2", "bogus", ""); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("bogus code: %v", err)
	}
	// The holder backend is down at first login.
	d = base
	d.Registrar = wallets.NewConnectRegistrar(nil, "http://127.0.0.1:1")
	value33, newErr3 := grants.New([]byte("0123456789abcdef0123456789abcdef"), nil, nil)
	if newErr3 != nil {
		t.Fatalf("unexpected error: %v", newErr3)
	}
	d.Grants = value33
	down := service.New(cfg, d)
	if err := runLogin(t, f, down); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("backend down: %v", err)
	}
	// The grant vault cannot persist.
	fs := &failStore{Persister: oidcflow.NewMemoryPersister()}
	d = base
	d.Registrar = wallets.LocalRegistrar{}
	value32, newErr2 := grants.New([]byte("0123456789abcdef0123456789abcdef"), fs, nil)
	if newErr2 != nil {
		t.Fatalf("unexpected error: %v", newErr2)
	}
	d.Grants = value32
	fs.fail = true
	if err := runLogin(t, f, service.New(cfg, d)); err == nil {
		t.Fatal("vault error hidden")
	}
	// The wallet store cannot persist.
	freshWallets, verr := wallets.New(fs, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	d = base
	d.Wallets = freshWallets
	d.Registrar = wallets.LocalRegistrar{}
	value31, newErr1 := grants.New([]byte("0123456789abcdef0123456789abcdef"), nil, nil)
	if newErr1 != nil {
		t.Fatalf("unexpected error: %v", newErr1)
	}
	d.Grants = value31
	if err := runLogin(t, f, service.New(cfg, d)); err == nil {
		t.Fatal("wallet error hidden")
	}
	// Logout of a session whose provider is gone or unreachable.
	d = base
	value30, newErr := grants.New([]byte("0123456789abcdef0123456789abcdef"), nil, nil)
	if newErr != nil {
		t.Fatalf("unexpected error: %v", newErr)
	}
	d.Grants = value30
	svc = service.New(cfg, d)
	tok, _, verr := f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "gone"})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if u, err := svc.End(ctx, tok); err != nil || u != "" {
		t.Fatalf("gone provider: %q %v", u, err)
	}
	if _, providersErr := f.svc.Providers().Put(oidcflow.Provider{ID: "down", DiscoveryURL: "http://127.0.0.1:1/x", ClientID: "c", Enabled: true}); providersErr != nil {
		t.Fatalf("unexpected error: %v", providersErr)
	}
	tok, _, signerErr := f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "down"})
	if signerErr != nil {
		t.Fatalf("unexpected error: %v", signerErr)
	}
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
	q, verr := url.Parse(loc)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	_, _, _, err = svc.Complete(context.Background(), q.Query().Get("state"), q.Query().Get("code"), "")
	return err
}
