// SPDX-License-Identifier: Apache-2.0

package onboard_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// idp is a fake provider with a registration endpoint (RFC 7591).
type idp struct {
	server *httptest.Server
	// noRegistration removes registration_endpoint from the metadata.
	noRegistration bool
	// device adds device_authorization_endpoint to the metadata.
	device bool
	// registerStatus is the status of the registration response.
	registerStatus int
	// registerBody replaces the registration response body.
	registerBody string
	// lastRequest is the body of the last registration request.
	lastRequest onboard.RegisterRequest
	// lastAuth is the Authorization header of the last request.
	lastAuth string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	p := &idp{registerStatus: http.StatusCreated}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 p.server.URL,
			"authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint":         p.server.URL + "/token",
			"jwks_uri":               p.server.URL + "/jwks",
			"scopes_supported":       []string{"openid", "profile"},
		}
		if !p.noRegistration {
			doc["registration_endpoint"] = p.server.URL + "/register"
		}
		if p.device {
			doc["device_authorization_endpoint"] = p.server.URL + "/device"
		}
		writeJSON(w, http.StatusOK, doc)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		p.lastAuth = r.Header.Get("Authorization")
		if cerr := json.NewDecoder(r.Body).Decode(&p.lastRequest); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		if p.registerBody != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(p.registerStatus)
			mustWrite(t, w, []byte(p.registerBody))
			return
		}
		writeJSON(w, p.registerStatus, map[string]string{"client_id": "new-client", "client_secret": "s3cret"})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if cerr := json.NewEncoder(w).Encode(v); cerr != nil {
		panic(cerr)
	}
}

func TestDiscoveryURLAddsTheWellKnownPath(t *testing.T) {
	if got := onboard.DiscoveryURL(" https://idp.example/ "); got != "https://idp.example/.well-known/openid-configuration" {
		t.Errorf("DiscoveryURL = %q", got)
	}
	known := "https://idp.example/.well-known/openid-configuration"
	if got := onboard.DiscoveryURL(known); got != known {
		t.Errorf("DiscoveryURL = %q", got)
	}
}

func TestDiscoverReadsEveryEndpoint(t *testing.T) {
	p := newIDP(t)
	p.device = true
	meta, err := onboard.Discover(context.Background(), http.DefaultClient, onboard.DiscoveryURL(p.server.URL))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !meta.SupportsDynamicRegistration() || !meta.SupportsDeviceGrant() {
		t.Fatalf("metadata = %+v", meta)
	}
	if meta.Issuer != p.server.URL {
		t.Errorf("issuer = %q", meta.Issuer)
	}
}

func TestDiscoverRejectsBadDocuments(t *testing.T) {
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("not json"))
	}))
	defer notJSON.Close()
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"issuer": "https://idp.example"})
	}))
	defer missing.Close()
	fails := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer fails.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()
	cases := map[string]string{
		"not a URL":    "idp.example",
		"not JSON":     notJSON.URL,
		"missing keys": missing.URL,
		"server error": fails.URL,
		"unreachable":  goneURL,
	}
	for name, u := range cases {
		if _, err := onboard.Discover(context.Background(), http.DefaultClient, u); err == nil {
			t.Errorf("%s: Discover returned no error", name)
		}
	}
}

func TestParseMetadataRejectsARelativeOptionalEndpoint(t *testing.T) {
	raw := `{"issuer":"https://i.example","authorization_endpoint":"https://i.example/a",
	"token_endpoint":"https://i.example/t","jwks_uri":"https://i.example/j",
	"registration_endpoint":"/register"}`
	if _, err := onboard.ParseMetadata([]byte(raw)); !errors.Is(err, onboard.ErrDiscovery) {
		t.Fatalf("ParseMetadata: %v", err)
	}
}

func TestRegisterSendsTheCodeGrantOnly(t *testing.T) {
	p := newIDP(t)
	meta, err := onboard.Discover(context.Background(), http.DefaultClient, onboard.DiscoveryURL(p.server.URL))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got, err := onboard.Register(context.Background(), http.DefaultClient, meta.RegistrationEndpoint,
		onboard.RegisterRequest{ClientName: "VCA admin", RedirectURIs: []string{"https://admin.example/auth/callback"}}, "initial-token")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got.ClientID != "new-client" || got.ClientSecret != "s3cret" {
		t.Fatalf("response = %+v", got)
	}
	if len(p.lastRequest.GrantTypes) != 1 || p.lastRequest.GrantTypes[0] != "authorization_code" {
		t.Errorf("grant types = %v", p.lastRequest.GrantTypes)
	}
	if len(p.lastRequest.ResponseTypes) != 1 || p.lastRequest.ResponseTypes[0] != "code" {
		t.Errorf("response types = %v", p.lastRequest.ResponseTypes)
	}
	if p.lastRequest.ApplicationType != "web" {
		t.Errorf("application type = %q", p.lastRequest.ApplicationType)
	}
	if p.lastAuth != "Bearer initial-token" {
		t.Errorf("authorization = %q", p.lastAuth)
	}
}

func TestRegisterRejectsBadInputAndBadAnswers(t *testing.T) {
	ctx := context.Background()
	p := newIDP(t)
	endpoint := p.server.URL + "/register"
	if _, err := onboard.Register(ctx, http.DefaultClient, "register", onboard.RegisterRequest{RedirectURIs: []string{"https://a.example/cb"}}, ""); err == nil {
		t.Error("Register accepted a relative endpoint")
	}
	if _, err := onboard.Register(ctx, http.DefaultClient, endpoint, onboard.RegisterRequest{}, ""); err == nil {
		t.Error("Register accepted a request without a redirect URI")
	}
	p.registerBody = `{"error":"invalid_redirect_uri","error_description":"no"}`
	p.registerStatus = http.StatusBadRequest
	if _, err := onboard.Register(ctx, http.DefaultClient, endpoint, onboard.RegisterRequest{RedirectURIs: []string{"https://a.example/cb"}}, ""); !errors.Is(err, onboard.ErrRegistration) {
		t.Errorf("error body: %v", err)
	}
	p.registerBody = "not json"
	if _, err := onboard.Register(ctx, http.DefaultClient, endpoint, onboard.RegisterRequest{RedirectURIs: []string{"https://a.example/cb"}}, ""); err == nil {
		t.Error("Register accepted a body that is not JSON")
	}
	p.registerBody = `{"client_id":"x"}`
	p.registerStatus = http.StatusTeapot
	if _, err := onboard.Register(ctx, http.DefaultClient, endpoint, onboard.RegisterRequest{RedirectURIs: []string{"https://a.example/cb"}}, ""); err == nil {
		t.Error("Register accepted a wrong status")
	}
	p.registerBody = `{}`
	p.registerStatus = http.StatusCreated
	if _, err := onboard.Register(ctx, http.DefaultClient, endpoint, onboard.RegisterRequest{RedirectURIs: []string{"https://a.example/cb"}}, ""); err == nil {
		t.Error("Register accepted a response without a client id")
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL + "/register"
	closed.Close()
	if _, err := onboard.Register(ctx, http.DefaultClient, closedURL, onboard.RegisterRequest{RedirectURIs: []string{"https://a.example/cb"}}, ""); err == nil {
		t.Error("Register accepted an unreachable endpoint")
	}
}

func TestRunRegistersTheClientAndStoresTheSecretInAFile(t *testing.T) {
	p := newIDP(t)
	dir := t.TempDir()
	vault := onboard.NewVault(dir)
	res, err := onboard.Run(context.Background(), http.DefaultClient, vault, onboard.Options{
		ID: "keycloak", DisplayName: "Keycloak", DiscoveryURL: p.server.URL, Dynamic: true,
		RedirectURI: "https://admin.example/auth/callback", Enabled: true, Roles: []string{"admin"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Registered || res.Provider.ClientID != "new-client" {
		t.Fatalf("result = %+v", res)
	}
	if res.Provider.ClientSecret.Store != oidcflow.SecretFile {
		t.Fatalf("secret ref = %+v", res.Provider.ClientSecret)
	}
	value, err := vault.Resolve(res.Provider.ClientSecret)
	if err != nil || value != "s3cret" {
		t.Fatalf("Resolve = %q, %v", value, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "client_secret_KEYCLOAK")) //nolint:gosec // the path is a test directory
	if err != nil || string(raw) != "s3cret" {
		t.Fatalf("file = %q, %v", raw, err)
	}
	if res.Provider.DiscoveryURL != onboard.DiscoveryURL(p.server.URL) {
		t.Errorf("discovery url = %q", res.Provider.DiscoveryURL)
	}
}

func TestRunKeepsTheSecretInMemoryWithoutADirectory(t *testing.T) {
	p := newIDP(t)
	vault := onboard.NewVault("")
	res, err := onboard.Run(context.Background(), http.DefaultClient, vault, onboard.Options{
		ID: "idp-1", DiscoveryURL: onboard.DiscoveryURL(p.server.URL), Dynamic: true,
		RedirectURI: "https://admin.example/auth/callback",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ref := res.Provider.ClientSecret
	if ref.Store != oidcflow.SecretEnv || !strings.HasPrefix(ref.Name, onboard.EnvPrefix) {
		t.Fatalf("secret ref = %+v", ref)
	}
	if value, err := vault.Resolve(ref); err != nil || value != "s3cret" {
		t.Fatalf("Resolve = %q, %v", value, err)
	}
}

func TestRunAcceptsAClientIDWhenTheProviderHasNoRegistration(t *testing.T) {
	p := newIDP(t)
	p.noRegistration = true
	res, err := onboard.Run(context.Background(), http.DefaultClient, onboard.NewVault(""), onboard.Options{
		ID: "wso2", DiscoveryURL: p.server.URL, ClientID: "given-client",
		ClientSecret: oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "VCA_TEST_SECRET"},
		RedirectURI:  "https://admin.example/auth/callback",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Registered || res.Provider.ClientID != "given-client" {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunRejectsBadOptions(t *testing.T) {
	ctx := context.Background()
	p := newIDP(t)
	vault := onboard.NewVault("")
	if _, err := onboard.Run(ctx, http.DefaultClient, vault, onboard.Options{DiscoveryURL: p.server.URL}); err == nil {
		t.Error("Run accepted an empty id")
	}
	if _, err := onboard.Run(ctx, http.DefaultClient, vault, onboard.Options{ID: "x", DiscoveryURL: "nowhere"}); err == nil {
		t.Error("Run accepted a bad discovery URL")
	}
	if _, err := onboard.Run(ctx, http.DefaultClient, vault, onboard.Options{ID: "x", DiscoveryURL: p.server.URL}); !errors.Is(err, onboard.ErrClientID) {
		t.Errorf("no client id: %v", err)
	}
	p.noRegistration = true
	_, err := onboard.Run(ctx, http.DefaultClient, vault, onboard.Options{
		ID: "x", DiscoveryURL: p.server.URL, Dynamic: true, RedirectURI: "https://admin.example/cb",
	})
	if !errors.Is(err, onboard.ErrRegistration) {
		t.Errorf("no registration endpoint: %v", err)
	}
	p.noRegistration = false
	p.registerBody = `{"error":"invalid_client_metadata"}`
	if _, err := onboard.Run(ctx, http.DefaultClient, vault, onboard.Options{
		ID: "x", DiscoveryURL: p.server.URL, Dynamic: true, RedirectURI: "https://admin.example/cb",
	}); !errors.Is(err, onboard.ErrRegistration) {
		t.Errorf("registration error: %v", err)
	}
}

func TestRunReportsAVaultThatCannotWrite(t *testing.T) {
	p := newIDP(t)
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := onboard.Run(context.Background(), http.DefaultClient, onboard.NewVault(file), onboard.Options{
		ID: "x", DiscoveryURL: p.server.URL, Dynamic: true, RedirectURI: "https://admin.example/cb",
	})
	if !errors.Is(err, onboard.ErrSecret) {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunRejectsAProviderThatFailsValidation(t *testing.T) {
	p := newIDP(t)
	p.noRegistration = true
	// The discovery URL is absolute, so the record fails only on the
	// internal authority, which Run does not set. Use a client id with
	// spaces to reach the record validation.
	_, err := onboard.Run(context.Background(), http.DefaultClient, onboard.NewVault(""), onboard.Options{
		ID: "x", DiscoveryURL: p.server.URL, ClientID: "   ",
	})
	if err == nil {
		t.Fatal("Run accepted a blank client id")
	}
}

func TestVaultStoreChecks(t *testing.T) {
	vault := onboard.NewVault("")
	ref, err := vault.Store("id", "")
	if err != nil || !ref.IsZero() {
		t.Fatalf("empty secret = %+v, %v", ref, err)
	}
	if _, err := vault.Store("  ", "value"); !errors.Is(err, onboard.ErrSecret) {
		t.Errorf("empty id: %v", err)
	}
	if _, err := vault.Resolve(oidcflow.SecretRef{Store: oidcflow.SecretKMS, Name: "unknown"}); err == nil {
		t.Error("Resolve accepted an unknown store")
	}
}

func TestSafeNameKeepsOnlySafeCharacters(t *testing.T) {
	if got := onboard.SafeName("ab-c_1.d"); got != "AB_C_1_D" {
		t.Fatalf("SafeName = %q", got)
	}
}
