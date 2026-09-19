// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuerauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/serve"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/roles"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/server"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/service"
)

type fixture struct {
	idp    *oidctest.Provider
	svc    *service.Service
	srv    *httptest.Server
	client issuerauthv1connect.IssuerAuthServiceClient
	admin  adminv1connect.AdminServiceClient
	cfg    config.Config
	store  *oidcflow.MemoryPersister
}

func withBearer(tok string) connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if tok != "" {
				req.Header().Set("Authorization", "Bearer "+tok)
			}
			return next(ctx, req)
		}
	}))
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	idp := oidctest.New()
	t.Cleanup(idp.Close)
	idp.Claims["realm_access"] = map[string]any{"roles": []any{"issuer-operator"}}
	idp.Claims["name"] = "Ada"
	store := oidcflow.NewMemoryPersister()
	providers, verr := oidcflow.NewRegistry(store, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	mappings, verr := roles.NewMappings(store)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	machine, verr := clients.New(store, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	key, verr := oidcflow.GenerateKey()
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	signer, verr := oidcflow.NewSigner(key, "http://issuer.test", server.Audience, time.Minute, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	csrf, verr := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	// The public base URL is only known once the test server runs, so
	// the fixture starts the server with a placeholder and rewires.
	f := &fixture{idp: idp, store: store}
	f.cfg = config.Config{
		PublicBaseURL:   "http://placeholder",
		TenantID:        "acme",
		AdminToken:      "admin-token",
		CookieName:      "sess",
		InsecureCookie:  true,
		SessionTTL:      time.Minute,
		MachineTokenTTL: time.Hour,
	}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.cfg.PublicBaseURL = f.srv.URL
	f.cfg.RedirectURI = f.srv.URL + "/auth/callback"
	f.svc = service.New(f.cfg, service.Deps{
		Flow:      &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Providers: providers,
		Mappings:  mappings,
		Clients:   machine,
		Signer:    signer,
		CSRF:      csrf,
	})
	mux.Handle("/", serve.Handler(serve.Options{
		Handler:      server.Handler(f.svc),
		ReadyMessage: server.ReadyMessage(f.svc),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}))
	if _, err := providers.Put(oidcflow.Provider{ID: "idp", DisplayName: "Fake", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Put(oidcflow.Provider{ID: "off", DisplayName: "Off", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	f.client = issuerauthv1connect.NewIssuerAuthServiceClient(f.srv.Client(), f.srv.URL)
	f.admin = adminv1connect.NewAdminServiceClient(f.srv.Client(), f.srv.URL, withBearer("admin-token"))
	return f
}

// browser returns a client that does not follow redirects.
func browser() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// login runs the browser flow and returns the callback response.
func (f *fixture) login(t *testing.T, returnTo string) *http.Response {
	t.Helper()
	q := url.Values{"provider": {"idp"}}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	res, err := browser().Get(f.srv.URL + "/auth/login?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login status %d", res.StatusCode)
	}
	loc, err := f.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc, f.srv.URL+"/auth/callback?") {
		t.Fatalf("redirect uri: %s", loc)
	}
	res, err = browser().Get(loc)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestBrowserFlow(t *testing.T) {
	f := newFixture(t)
	res := f.login(t, "")
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	var body struct {
		SessionToken string          `json:"session_token"`
		CSRFToken    string          `json:"csrf_token"`
		Claims       oidcflow.Claims `json:"claims"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Claims.Subject != f.idp.Issuer()+"|user-1" || body.Claims.Name != "Ada" || body.Claims.Tenant != "acme" || strings.Join(body.Claims.Roles, ",") != "issuer-operator" {
		t.Fatalf("claims: %+v", body.Claims)
	}
	cookie := res.Cookies()[0]
	if cookie.Name != "sess" || !cookie.HttpOnly || cookie.Secure {
		t.Fatalf("cookie: %+v", cookie)
	}
	// JWKS lets another service verify the token locally.
	jwks, err := http.Get(f.srv.URL + "/.well-known/jwks.json")
	if err != nil || jwks.StatusCode != 200 {
		t.Fatalf("jwks: %v", err)
	}
	if cerr := jwks.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	// Introspect through the RPC.
	intro, err := f.client.Introspect(context.Background(), connect.NewRequest(&issuerauthv1.IntrospectRequest{SessionToken: body.SessionToken}))
	if err != nil || !intro.Msg.GetActive() || intro.Msg.GetSession().GetRoles()[0] != issuerauthv1.IssuerRole_ISSUER_ROLE_OPERATOR || intro.Msg.GetSession().GetTenantId() != "acme" {
		t.Fatalf("introspect: %+v %v", intro, err)
	}
	// Logout redirects to the provider end session endpoint.
	req, verr := http.NewRequest(http.MethodPost, f.srv.URL+"/auth/logout", nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	req.Header.Set(oidcflow.CSRFHeader, body.CSRFToken)
	req.AddCookie(cookie)
	out, err := browser().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := out.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if out.StatusCode != http.StatusSeeOther || !strings.HasPrefix(out.Header.Get("Location"), f.idp.Issuer()+"/logout?") || !strings.Contains(out.Header.Get("Location"), "id_token_hint=") {
		t.Fatalf("logout: %d %s", out.StatusCode, out.Header.Get("Location"))
	}
	intro, introspectErr := f.client.Introspect(context.Background(), connect.NewRequest(&issuerauthv1.IntrospectRequest{SessionToken: body.SessionToken}))
	if introspectErr != nil {
		t.Fatalf("unexpected error: %v", introspectErr)
	}
	if intro.Msg.GetActive() {
		t.Fatal("session still active after logout")
	}
	// return_to redirects.
	res = f.login(t, "/schemas")
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/schemas" {
		t.Fatalf("return_to: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// Health endpoints.
	for _, p := range []string{"/healthz", "/readyz"} {
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

func TestRPCFlow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	list, err := f.client.ListProviders(ctx, connect.NewRequest(&issuerauthv1.ListProvidersRequest{}))
	if err != nil || len(list.Msg.GetProviders()) != 1 || list.Msg.GetProviders()[0].GetIssuer() != f.idp.Issuer() {
		t.Fatalf("list: %+v %v", list, err)
	}
	start, err := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "idp", ReturnTo: "/x"}))
	if err != nil || start.Msg.GetState() == "" || start.Msg.GetExpiresAt() == nil {
		t.Fatalf("start: %v", err)
	}
	loc, verr := f.idp.Authorize(start.Msg.GetAuthorizationUrl())
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	u, verr := url.Parse(loc)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	cb, err := f.client.LoginCallback(ctx, connect.NewRequest(&issuerauthv1.LoginCallbackRequest{State: u.Query().Get("state"), Code: u.Query().Get("code")}))
	if err != nil || cb.Msg.GetReturnTo() != "/x" || cb.Msg.GetSession().GetDisplayName() != "Ada" || cb.Msg.GetSession().GetProviderId() != "idp" {
		t.Fatalf("callback: %+v %v", cb, err)
	}
	// The state works once.
	if _, serr := f.client.LoginCallback(ctx, connect.NewRequest(&issuerauthv1.LoginCallbackRequest{State: u.Query().Get("state"), Code: "x"})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Fatalf("replay: %v", serr)
	}
	// Provider error.
	start, loginStartErr := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "idp"}))
	if loginStartErr != nil {
		t.Fatalf("unexpected error: %v", loginStartErr)
	}
	if _, serr := f.client.LoginCallback(ctx, connect.NewRequest(&issuerauthv1.LoginCallbackRequest{State: start.Msg.GetState(), Error: "access_denied"})); connect.CodeOf(serr) != connect.CodeUnavailable {
		t.Fatalf("provider error: %v", serr)
	}
	// Unknown and disabled providers, bad return_to.
	if _, serr := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "nope"})); connect.CodeOf(serr) != connect.CodeNotFound {
		t.Fatalf("unknown: %v", serr)
	}
	if _, serr := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "off"})); connect.CodeOf(serr) != connect.CodeFailedPrecondition {
		t.Fatalf("disabled: %v", serr)
	}
	if _, serr := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "idp", ReturnTo: "https://evil"})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Fatalf("return_to: %v", serr)
	}
	// Logout through the RPC and a bad token.
	lo, err := f.client.Logout(ctx, connect.NewRequest(&issuerauthv1.LogoutRequest{SessionToken: cb.Msg.GetSessionToken()}))
	if err != nil || !strings.Contains(lo.Msg.GetProviderLogoutUrl(), "/logout?") {
		t.Fatalf("logout: %+v %v", lo, err)
	}
	if _, err := f.client.Logout(ctx, connect.NewRequest(&issuerauthv1.LogoutRequest{SessionToken: "bad"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("logout bad: %v", err)
	}
	// Tokens in the query string are refused (RFC 9700).
	r, verr := http.Get(f.srv.URL + "/vca.issuerauth.v1.IssuerAuthService/Introspect?access_token=x")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if cerr := r.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("query token: %d", r.StatusCode)
	}
}

func TestRoleMappingAndDenied(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	anon := f.client
	if _, err := anon.GetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.GetRoleMappingRequest{ProviderId: "idp"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon get: %v", err)
	}
	if _, err := anon.SetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.SetRoleMappingRequest{ProviderId: "idp"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon set: %v", err)
	}
	admin := issuerauthv1connect.NewIssuerAuthServiceClient(f.srv.Client(), f.srv.URL, withBearer("admin-token"))
	got, err := admin.GetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.GetRoleMappingRequest{ProviderId: "idp"}))
	if err != nil || got.Msg.GetMapping().GetClaimPath() != roles.DefaultClaimPath || len(got.Msg.GetMapping().GetRules()) != 3 {
		t.Fatalf("default mapping: %+v %v", got, err)
	}
	if _, err := admin.GetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.GetRoleMappingRequest{ProviderId: "nope"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing: %v", err)
	}
	if _, err := admin.SetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.SetRoleMappingRequest{ProviderId: "nope"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("set missing: %v", err)
	}
	if _, err := admin.SetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.SetRoleMappingRequest{ProviderId: "idp", Mapping: &issuerauthv1.RoleMapping{}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("set invalid: %v", err)
	}
	// Map the groups claim to issuer-admin.
	f.idp.Claims["groups"] = []any{"staff"}
	mapping := &issuerauthv1.RoleMapping{ClaimPath: "groups", Rules: []*issuerauthv1.RoleMapping_Rule{{ClaimValue: "staff", Role: issuerauthv1.IssuerRole_ISSUER_ROLE_ADMIN}}}
	if _, err := admin.SetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.SetRoleMappingRequest{ProviderId: "idp", Mapping: mapping})); err != nil {
		t.Fatal(err)
	}
	res := f.login(t, "")
	var body struct {
		SessionToken string `json:"session_token"`
	}
	if cerr := json.NewDecoder(res.Body).Decode(&body); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	intro, verr := f.client.Introspect(ctx, connect.NewRequest(&issuerauthv1.IntrospectRequest{SessionToken: body.SessionToken}))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if intro.Msg.GetSession().GetRoles()[0] != issuerauthv1.IssuerRole_ISSUER_ROLE_ADMIN {
		t.Fatalf("roles: %+v", intro.Msg.GetSession())
	}
	// An issuer-admin session can read the mapping without the admin token.
	viaSession := issuerauthv1connect.NewIssuerAuthServiceClient(f.srv.Client(), f.srv.URL, withBearer(body.SessionToken))
	if _, err := viaSession.GetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.GetRoleMappingRequest{ProviderId: "idp"})); err != nil {
		t.Fatalf("session admin: %v", err)
	}
	// A subject with no matching claim is denied.
	f.idp.Claims["groups"] = []any{"guest"}
	res = f.login(t, "")
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("denied login: %d", res.StatusCode)
	}
	// An operator session cannot change mappings.
	f.idp.Claims["groups"] = []any{"ops"}
	mapping.Rules = append(mapping.Rules, &issuerauthv1.RoleMapping_Rule{ClaimValue: "ops", Role: issuerauthv1.IssuerRole_ISSUER_ROLE_OPERATOR})
	if _, setRoleMappingErr := admin.SetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.SetRoleMappingRequest{ProviderId: "idp", Mapping: mapping})); setRoleMappingErr != nil {
		t.Fatalf("unexpected error: %v", setRoleMappingErr)
	}
	res = f.login(t, "")
	if cerr := json.NewDecoder(res.Body).Decode(&body); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	ops := issuerauthv1connect.NewIssuerAuthServiceClient(f.srv.Client(), f.srv.URL, withBearer(body.SessionToken))
	if _, err := ops.SetRoleMapping(ctx, connect.NewRequest(&issuerauthv1.SetRoleMappingRequest{ProviderId: "idp", Mapping: mapping})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("operator set: %v", err)
	}
}

func TestClientCredentials(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	exp := timestamppb.New(time.Now().Add(time.Hour))
	created, err := f.admin.CreateApiKey(ctx, connect.NewRequest(&adminv1.CreateApiKeyRequest{DisplayName: "robot", Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_VERIFIER}, ExpiresAt: exp}))
	if err != nil || created.Msg.GetSecret() == "" || created.Msg.GetKey().GetTenantId() != "acme" || created.Msg.GetKey().GetExpiresAt() == nil {
		t.Fatalf("create: %+v %v", created, err)
	}
	if _, serr := f.admin.CreateApiKey(ctx, connect.NewRequest(&adminv1.CreateApiKeyRequest{})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Fatalf("invalid: %v", serr)
	}
	id, secret := created.Msg.GetKey().GetId(), created.Msg.GetSecret()
	post := func(form url.Values, basic bool) (int, map[string]any) {
		req, verr := http.NewRequest(http.MethodPost, f.srv.URL+"/token", strings.NewReader(form.Encode()))
		if verr != nil {
			t.Fatalf("unexpected error: %v", verr)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		}
		res, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		defer func() {
			if cerr := res.Body.Close(); cerr != nil {
				t.Errorf("the close failed: %v", cerr)
			}
		}()
		var body map[string]any
		if cerr := json.NewDecoder(res.Body).Decode(&body); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		return res.StatusCode, body
	}
	code, body := post(url.Values{"grant_type": {"client_credentials"}}, true)
	if code != 200 || body["token_type"] != "Bearer" || body["access_token"] == "" {
		t.Fatalf("basic: %d %v", code, body)
	}
	tok := mustAs[string](t, body["access_token"])
	claims, err := f.svc.Signer().Verify(tok)
	if err != nil || claims.ClientID != id || strings.Join(claims.Roles, ",") != "issuer-operator,issuer-viewer" || claims.Subject != "client:"+id {
		t.Fatalf("claims: %+v %v", claims, err)
	}
	if time.Until(claims.Expiry()) < 50*time.Minute {
		t.Fatal("machine token ttl")
	}
	code, _ = post(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, false)
	if code != 200 {
		t.Fatalf("form auth: %d", code)
	}
	code, body = post(url.Values{"grant_type": {"password"}}, true)
	if code != 400 || body["error"] != "unsupported_grant_type" {
		t.Fatalf("grant: %d %v", code, body)
	}
	code, body = post(url.Values{"grant_type": {"client_credentials"}}, false)
	if code != 401 || body["error"] != "invalid_client" {
		t.Fatalf("no auth: %d %v", code, body)
	}
	code, _ = post(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {"wrong"}}, false)
	if code != 401 {
		t.Fatalf("wrong secret: %d", code)
	}
	r, verr := http.Get(f.srv.URL + "/token")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if cerr := r.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET token: %d", r.StatusCode)
	}
	req, verr := http.NewRequest(http.MethodPost, f.srv.URL+"/token", strings.NewReader("%zz"))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		t.Fatalf("unexpected error: %v", doErr)
	}
	if cerr := r.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad form: %d", r.StatusCode)
	}
	// List and revoke.
	list, err := f.admin.ListApiKeys(ctx, connect.NewRequest(&adminv1.ListApiKeysRequest{}))
	if err != nil || len(list.Msg.GetKeys()) != 1 || list.Msg.GetKeys()[0].GetRoles()[0] != commonv1.Role_ROLE_ISSUER {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, serr := f.admin.RevokeApiKey(ctx, connect.NewRequest(&adminv1.RevokeApiKeyRequest{Id: id})); serr != nil {
		t.Fatal(serr)
	}
	if _, serr := f.admin.RevokeApiKey(ctx, connect.NewRequest(&adminv1.RevokeApiKeyRequest{Id: "nope"})); connect.CodeOf(serr) != connect.CodeNotFound {
		t.Fatalf("revoke missing: %v", serr)
	}
	if code, _ := post(url.Values{"grant_type": {"client_credentials"}}, true); code != 401 {
		t.Fatalf("revoked client got a token: %d", code)
	}
	list, listKeysErr := f.admin.ListApiKeys(ctx, connect.NewRequest(&adminv1.ListApiKeysRequest{}))
	if listKeysErr != nil {
		t.Fatalf("unexpected error: %v", listKeysErr)
	}
	if list.Msg.GetKeys()[0].GetRevokedAt() == nil {
		t.Fatal("revoked_at")
	}
	// Admin RPCs need the admin token.
	anon := adminv1connect.NewAdminServiceClient(f.srv.Client(), f.srv.URL)
	if _, serr := anon.CreateApiKey(ctx, connect.NewRequest(&adminv1.CreateApiKeyRequest{})); connect.CodeOf(serr) != connect.CodeUnauthenticated {
		t.Fatalf("anon create: %v", serr)
	}
	if _, serr := anon.ListApiKeys(ctx, connect.NewRequest(&adminv1.ListApiKeysRequest{})); connect.CodeOf(serr) != connect.CodeUnauthenticated {
		t.Fatalf("anon list: %v", serr)
	}
	if _, serr := anon.RevokeApiKey(ctx, connect.NewRequest(&adminv1.RevokeApiKeyRequest{})); connect.CodeOf(serr) != connect.CodeUnauthenticated {
		t.Fatalf("anon revoke: %v", serr)
	}
	// Providers can be registered through the admin RPC at runtime.
	res, err := f.admin.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: &adminv1.AuthProvider{DisplayName: "New", DiscoveryUrl: f.idp.DiscoveryURL(), ClientId: "client", Enabled: true}}))
	if err != nil || res.Msg.GetProvider().GetId() == "" {
		t.Fatalf("create provider: %v", err)
	}
	list2, verr := f.client.ListProviders(ctx, connect.NewRequest(&issuerauthv1.ListProvidersRequest{}))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if len(list2.Msg.GetProviders()) != 2 {
		t.Fatalf("providers: %+v", list2.Msg)
	}
	if got := service.MachineRoles([]commonv1.Role{commonv1.Role_ROLE_ADMIN, commonv1.Role_ROLE_HOLDER}); strings.Join(got, ",") != "issuer-admin,issuer-viewer" {
		t.Fatal(got)
	}
}

func TestEndWithoutProviderOrLogoutURL(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A session whose provider is gone still logs out, without a URL.
	tok, _, verr := f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "gone"})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	u, err := f.svc.End(ctx, tok)
	if err != nil || u != "" {
		t.Fatalf("gone provider: %q %v", u, err)
	}
	// A provider that is unreachable at logout gives no URL.
	if _, providersErr := f.svc.Providers().Put(oidcflow.Provider{ID: "down", DiscoveryURL: "http://127.0.0.1:1/x", ClientID: "c", Enabled: true}); providersErr != nil {
		t.Fatalf("unexpected error: %v", providersErr)
	}
	tok, _, signerErr1 := f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "down"})
	if signerErr1 != nil {
		t.Fatalf("unexpected error: %v", signerErr1)
	}
	if down, endErr := f.svc.End(ctx, tok); endErr != nil || down != "" {
		t.Fatalf("down provider: %q %v", down, endErr)
	}
	// Post logout redirect from config.
	cfg := f.svc.Config()
	cfg.LogoutRedirect = "/bye"
	svc2 := service.New(cfg, service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Signer: f.svc.Signer()})
	tok, _, signerErr := f.svc.Signer().Issue(oidcflow.Claims{Subject: "u", Provider: "idp"})
	if signerErr != nil {
		t.Fatalf("unexpected error: %v", signerErr)
	}
	u, err = svc2.End(ctx, tok)
	if err != nil || !strings.Contains(u, url.QueryEscape(f.srv.URL+"/bye")) {
		t.Fatalf("post logout: %q %v", u, err)
	}
	// Session errors surface.
	if _, err := f.svc.Session(ctx, "bad"); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatal(err)
	}
	start, verr := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "down"}))
	if verr == nil || start != nil {
		t.Fatal("the down provider started")
	}
}

type failingPending struct{}

func (failingPending) Put(oidcflow.Pending) error           { return errors.New("store down") }
func (failingPending) Take(string) (oidcflow.Pending, bool) { return oidcflow.Pending{}, false }

func TestPendingStoreFailure(t *testing.T) {
	f := newFixture(t)
	cfg := f.svc.Config()
	svc := service.New(cfg, service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Signer: f.svc.Signer(), Pending: failingPending{}})
	if _, err := svc.Start(context.Background(), "idp", ""); err == nil {
		t.Fatal("store error hidden")
	}
	// A pending login for a provider that no longer exists.
	mem := oidcflow.NewMemoryPending(nil)
	svc = service.New(cfg, service.Deps{Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}, Providers: f.svc.Providers(), Signer: f.svc.Signer(), Pending: mem})
	if cerr := mem.Put(oidcflow.Pending{State: "s", ProviderID: "deleted", ExpiresAt: time.Now().Add(time.Minute)}); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if _, _, _, err := svc.Complete(context.Background(), "s", "code", ""); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("deleted provider: %v", err)
	}
	// A pending login that the provider rejects at the token endpoint.
	if cerr := mem.Put(oidcflow.Pending{State: "s2", ProviderID: "idp", RedirectURI: cfg.RedirectURI, Verifier: "v", Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)}); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if _, _, _, err := svc.Complete(context.Background(), "s2", "bogus", ""); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("bogus code: %v", err)
	}
}
