// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1/walletportalv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/blobs"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// keys is a session signing key with the matching key set.
type keys struct {
	key *ecdsa.PrivateKey
	set jose.JWKS
	kid string
}

func newKeys(t *testing.T) keys {
	t.Helper()
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	kid, err := jose.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	pub.KeyID = kid
	return keys{key: key, set: jose.JWKS{Keys: []jose.JWK{pub}}, kid: kid}
}

func (k keys) token(t *testing.T) string {
	t.Helper()
	tok, err := jose.Sign(k.key, k.kid, "JWT", oidcflow.Claims{
		Issuer: "https://auth.example", Subject: "https://idp|abc", ID: "jti", SID: "sid",
		WalletID: "wallet-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (k keys) file(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(k.set)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// fakeHolder answers one holder RPC.
type fakeHolder struct {
	backendv1connect.HolderBackendServiceClient
}

func (fakeHolder) ListCredentials(_ context.Context, _ *connect.Request[backendv1.ListCredentialsRequest],
) (*connect.Response[backendv1.ListCredentialsResponse], error) {
	return connect.NewResponse(&backendv1.ListCredentialsResponse{}), nil
}

func settings(extra map[string]string) map[string]string {
	out := map[string]string{
		"VCA_WALLET_PORTAL_REQUEST_HOSTS": "verifier.example",
		"VCA_WALLET_PORTAL_CSRF_KEY":      strings.Repeat("k", 32),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func load(t *testing.T, extra map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(env(settings(extra)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildServesThePagesAndTheRPCs(t *testing.T) {
	k := newKeys(t)
	cfg := load(t, map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t),
		"VCA_WALLET_PORTAL_STATE_DIR":      t.TempDir(),
	})
	a, err := app.Build(cfg, app.Deps{
		Holder: fakeHolder{},
		Catalogue: ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
			return []*walletportalv1.Offering{{
				CredentialIssuer: "https://a.example",
				Schema:           &schemav1.PublicSchema{Id: "dl", Type: "DriverLicence"},
			}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Ready() || a.Service.KeepsBrowser(context.Background()) {
		t.Fatalf("app = %+v", a)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()

	page, err := http.Get(srv.URL + "/wallet/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := page.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if page.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session page = %d", page.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/discover", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body := make([]byte, 4096)
	n, verr := resp.Body.Read(body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body[:n]), "DriverLicence") {
		t.Fatalf("discover = %d %s", resp.StatusCode, body[:n])
	}

	client := walletportalv1connectClient(t, srv.URL)
	rpc := connect.NewRequest(&walletportalv1.ListDiscoverableRequest{})
	rpc.Header().Set("Authorization", "Bearer "+k.token(t))
	answer, err := client.ListDiscoverable(context.Background(), rpc)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Msg.GetOfferings()) != 1 {
		t.Fatalf("offerings = %+v", answer.Msg.GetOfferings())
	}
	noToken := connect.NewRequest(&walletportalv1.ListDiscoverableRequest{})
	if _, serr := client.ListDiscoverable(context.Background(), noToken); connect.CodeOf(serr) !=
		connect.CodeUnauthenticated {
		t.Fatalf("no token: %v", serr)
	}

	assets, err := http.Get(srv.URL + "/static/vca.css")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := assets.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if assets.StatusCode != http.StatusOK {
		t.Fatalf("assets = %d", assets.StatusCode)
	}
}

func TestBuildInBrowserStorageMode(t *testing.T) {
	k := newKeys(t)
	cfg := load(t, map[string]string{"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t)})
	a, err := app.Build(cfg, app.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Blobs == nil || !a.Service.BrowserStorage() {
		t.Fatal("want browser storage")
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/blobs", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blobs = %d", resp.StatusCode)
	}
	var body struct {
		Blobs []blobs.Record `json:"blobs"`
	}
	if serr := json.NewDecoder(resp.Body).Decode(&body); serr != nil {
		t.Fatal(serr)
	}
	if len(body.Blobs) != 0 {
		t.Fatalf("blobs = %+v", body.Blobs)
	}
	script, err := http.Get(srv.URL + "/wallet/wallet.js")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := script.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if script.StatusCode != http.StatusOK {
		t.Fatalf("script = %d", script.StatusCode)
	}
}

func TestBuildWithTheJWKSURL(t *testing.T) {
	k := newKeys(t)
	raw, err := json.Marshal(k.set)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, raw)
	}))
	defer jwks.Close()
	cfg := load(t, map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_URL":   jwks.URL + "/.well-known/jwks.json",
		"VCA_WALLET_PORTAL_DISCOVERY_URL":   "http://discovery.invalid",
		"VCA_WALLET_PORTAL_TRUST_URL":       "http://trust.invalid",
		"VCA_WALLET_PORTAL_DPG":             "one",
		"VCA_WALLET_PORTAL_DPG_ADAPTERS":    "one=http://adapter.invalid",
		"VCA_WALLET_PORTAL_ELIGIBILITY_URL": "http://hook.invalid",
	})
	a, err := app.Build(cfg, app.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Service.BrowserStorage() {
		t.Fatal("want the holder backend")
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page = %d", resp.StatusCode)
	}
}

func TestBuildRejects(t *testing.T) {
	k := newKeys(t)
	if _, err := app.Build(config.Config{}, app.Deps{}); err == nil {
		t.Fatal("want a config error")
	}
	cfg := load(t, nil)
	if _, err := app.Build(cfg, app.Deps{}); err == nil ||
		!strings.Contains(err.Error(), "AUTH_JWKS") {
		t.Fatalf("no key set: %v", err)
	}
	missing := load(t, map[string]string{"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": "/no/such/file"})
	if _, err := app.Build(missing, app.Deps{}); err == nil {
		t.Fatal("want a read error")
	}
	broken := load(t, map[string]string{"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": "any"})
	if _, err := app.Build(broken, app.Deps{
		ReadFile: func(string) ([]byte, error) { return []byte("{"), nil },
	}); err == nil {
		t.Fatal("want a parse error")
	}
	badDir := load(t, map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t),
		"VCA_WALLET_PORTAL_STATE_DIR":      "/proc/nope/state",
	})
	if _, err := app.Build(badDir, app.Deps{}); err == nil {
		t.Fatal("want a store error")
	}
	badHook := load(t, map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE":  k.file(t),
		"VCA_WALLET_PORTAL_ELIGIBILITY_URL": " ",
	})
	badHook.EligibilityURL = " "
	if _, err := app.Build(badHook, app.Deps{
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("down") },
	}); err == nil {
		t.Fatal("want an error")
	}
}

// walletportalv1connectClient returns a Connect client for the server.
func walletportalv1connectClient(t *testing.T, base string) walletportalv1connect.WalletPortalServiceClient {
	t.Helper()
	return walletportalv1connect.NewWalletPortalServiceClient(http.DefaultClient, base)
}

// fakeTrust answers the trust lookup.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
}

func (fakeTrust) TrustLookup(_ context.Context, _ *connect.Request[trustv1.TrustLookupRequest],
) (*connect.Response[trustv1.TrustLookupResponse], error) {
	return connect.NewResponse(&trustv1.TrustLookupResponse{
		Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}), nil
}

func TestBuildWithADefaultEligibilityAnswer(t *testing.T) {
	k := newKeys(t)
	cfg, err := config.Load(env(map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE":      k.file(t),
		"VCA_WALLET_PORTAL_ELIGIBILITY_DEFAULT": "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.Build(cfg, app.Deps{Trust: fakeTrust{}, Holder: fakeHolder{}})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Ready() {
		t.Fatal("want a ready app")
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page = %d", resp.StatusCode)
	}
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := load(t, map[string]string{"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": newKeys(t).file(t)})
	cfg.ThemeFile = path
	_, err := app.Build(cfg, app.Deps{})
	uikittest.AssertBadThemeError(t, err, path)
}

// fakeAuth answers the logout RPC of wallet-auth.
type fakeAuth struct {
	walletauthv1connect.UnimplementedWalletAuthServiceHandler
	token string
}

func (f *fakeAuth) Logout(_ context.Context, req *connect.Request[walletauthv1.LogoutRequest],
) (*connect.Response[walletauthv1.LogoutResponse], error) {
	f.token = req.Msg.GetSessionToken()
	return connect.NewResponse(&walletauthv1.LogoutResponse{ProviderLogoutUrl: "https://idp.example/logout"}), nil
}

// TestBuildWiresTheHolderFrame checks the frame of the pages: the probe
// of the peers names the stacks, and the sign out form ends the session
// at the wallet-auth service of the own pair.
func TestBuildWiresTheHolderFrame(t *testing.T) {
	k := newKeys(t)
	auth := &fakeAuth{}
	mux := http.NewServeMux()
	mux.Handle(walletauthv1connect.NewWalletAuthServiceHandler(auth))
	authSrv := httptest.NewServer(mux)
	defer authSrv.Close()
	peers := "holder-waltid|https://holder-waltid.example|wallet-auth=" + authSrv.URL + ",wallet-portal=http://portal:8092;" +
		"holder-inji|https://holder-inji.example|wallet-auth=http://inji-auth:8083,wallet-portal=http://inji-portal:8092"
	cfg := load(t, map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t),
		"VCA_WALLET_PORTAL_AUTH_JWKS_URL":  authSrv.URL + "/.well-known/jwks.json",
		"VCA_PEERS":                        peers,
	})
	a, err := app.Build(cfg, app.Deps{
		Holder: fakeHolder{},
		Snapshot: func(context.Context) topology.Snapshot {
			var s topology.Snapshot
			for i, p := range cfg.Peers {
				name := []string{"First stack", "Second stack"}[i]
				s.Peers = append(s.Peers, topology.Status{Peer: p, State: topology.Live,
					Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: name}}})
			}
			return s
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil || err != nil {
		t.Fatal(err, cerr)
	}
	body := string(raw)
	for _, want := range []string{"First stack", "Second stack", `action="/wallet/signout"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("home misses %s", want)
		}
	}
	token := between(body, `name="csrf_token" value="`, `"`)
	form := strings.NewReader("csrf_token=" + token)
	out, err := http.NewRequest(http.MethodPost, srv.URL+"/wallet/signout", form)
	if err != nil {
		t.Fatal(err)
	}
	out.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	done, err := noFollow.Do(out)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := done.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if done.StatusCode != http.StatusSeeOther || done.Header.Get("Location") != "https://idp.example/logout" || auth.token == "" {
		t.Fatalf("sign out = %d %q token %q", done.StatusCode, done.Header.Get("Location"), auth.token)
	}
}

// between returns the text between start and end.
func between(text, start, end string) string {
	_, rest, ok := strings.Cut(text, start)
	if !ok {
		return ""
	}
	out, _, _ := strings.Cut(rest, end)
	return out
}

// TestBuildCrawlsLiveIssuersWithoutDiscovery checks spec HO1 end to
// end: with no discovery service the discover page reads the metadata
// of the live issuer pair at its internal address.
func TestBuildCrawlsLiveIssuersWithoutDiscovery(t *testing.T) {
	k := newKeys(t)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		anyval.DiscardWrite(w.Write([]byte(`{"credential_issuer":"https://issuer-waltid.example","display":[{"name":"Ministry of Health"}],` +
			`"credential_configurations_supported":{"nurse":{"format":"dc+sd-jwt","vct":"NurseLicence"}}}`)))
	}))
	defer registry.Close()
	peers := "issuer-waltid|https://issuer-waltid.example|issuance=http://issuance:8080,schema-registry=" + registry.URL
	cfg := load(t, map[string]string{"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t), "VCA_PEERS": peers})
	a, err := app.Build(cfg, app.Deps{
		Holder: fakeHolder{},
		Snapshot: func(context.Context) topology.Snapshot {
			return topology.Snapshot{Peers: []topology.Status{{Peer: cfg.Peers[0], State: topology.Live,
				Capabilities: &backendv1.GetCapabilitiesResponse{Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH}}}}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/discover", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil || err != nil {
		t.Fatal(err, cerr)
	}
	for _, want := range []string{"NurseLicence", "Ministry of Health"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("discover misses %s\n%s", want, raw)
		}
	}
}

// TestBuildGatesTheBrowserStoreOfAStackWallet serves no blob route
// beside a stack wallet whose adapter does not list
// FEATURE_WALLET_CLAIM_IN_STACK.
func TestBuildGatesTheBrowserStoreOfAStackWallet(t *testing.T) {
	k := newKeys(t)
	cfg := load(t, map[string]string{
		"VCA_WALLET_PORTAL_AUTH_JWKS_FILE": k.file(t),
		"VCA_WALLET_PORTAL_STATE_DIR":      t.TempDir(),
	})
	a, err := app.Build(cfg, app.Deps{Holder: fakeHolder{}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/wallet/blobs", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: k.token(t)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if resp.StatusCode != http.StatusNotFound || a.Blobs == nil {
		t.Fatalf("blobs = %d", resp.StatusCode)
	}
}
