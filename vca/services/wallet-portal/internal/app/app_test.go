// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1/walletportalv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
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
	if !a.Ready() || a.Blobs != nil {
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
