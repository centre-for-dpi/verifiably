// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

const testdata = "../../testdata"

// build wires the adapter against the fake.
func build(t *testing.T, f *fake.Server, change func(*config.Config)) *app.App {
	t.Helper()
	cfg := config.Config{
		Listen:              ":0",
		CertifyURL:          f.URL(),
		VerifyURL:           f.URL(),
		PublicURL:           "https://adapter.example",
		AuthorizationServer: "https://esignet.example/v1/esignet",
		DpgVersion:          "0.14.0",
		OfferTTL:            15 * time.Minute,
		Timeout:             5 * time.Second,
		MaxBytes:            1 << 20,
	}
	if change != nil {
		change(&cfg)
	}
	a, err := app.Build(cfg, app.Deps{HTTP: f.Client()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return a
}

func TestBuildServesEveryBackendService(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a := build(t, f, nil)
	if !a.Service.Ready() {
		t.Fatal("the service is not ready")
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	paths := []string{
		"/vca.backend.v1.CapabilityService/GetCapabilities",
		"/vca.backend.v1.IssuerBackendService/GetIssuerMetadata",
		"/vca.backend.v1.HolderBackendService/Register",
		"/vca.backend.v1.VerifierBackendService/CreateRequest",
		"/vca.backend.v1.CatalogBackendService/ListCredentialTypes",
		"/vca.backend.v1.TenantBackendService/ListTenants",
		"/vca.backend.v1.NotificationBackendService/GetWebhook",
	}
	for _, path := range paths {
		resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("%s is not served", path)
		}
	}
}

func TestOfferEndpointServesTheHostedOffer(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a := build(t, f, nil)
	created, err := a.Service.CreateOffer(t.Context(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "FarmerCredential",
			SubjectData:     `{"fullName":"Ada"}`,
		},
		Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/offers/" + created.Msg.GetOfferId())
	if err != nil {
		t.Fatalf("get the offer: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q", resp.Header.Get("Cache-Control"))
	}
	body, verr := io.ReadAll(resp.Body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	var offer map[string]any
	if serr := json.Unmarshal(body, &offer); serr != nil {
		t.Fatalf("the offer is not JSON: %v", serr)
	}
	if offer["credential_issuer"] == nil {
		t.Fatalf("offer = %v", offer)
	}
	missing, err := srv.Client().Get(srv.URL + "/offers/does-not-exist")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() {
		if cerr := missing.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", missing.StatusCode)
	}
}

func TestBuildOpensAFileStore(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	dir := t.TempDir()
	a := build(t, f, func(c *config.Config) { c.StoreFile = filepath.Join(dir, "state") })
	if a.Mux == nil {
		t.Fatal("the mux is missing")
	}
}

func TestBuildWarnsWithoutAPublicUrl(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a := build(t, f, func(c *config.Config) { c.PublicURL = "" })
	if a.Service == nil {
		t.Fatal("the service is missing")
	}
}

func TestBuildReportsABadStoreDirectory(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	dir := t.TempDir()
	blocking := filepath.Join(dir, "file")
	if err := os.WriteFile(blocking, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := app.Build(config.Config{
		CertifyURL: f.URL(),
		StoreFile:  filepath.Join(blocking, "state"),
		OfferTTL:   time.Minute,
	}, app.Deps{HTTP: f.Client()})
	if err == nil {
		t.Fatal("Build accepted a store path inside a file")
	}
}

func TestBuildReportsAServiceWithoutARole(t *testing.T) {
	if _, err := app.Build(config.Config{OfferTTL: time.Minute}, app.Deps{}); err == nil {
		t.Fatal("Build accepted a service without a role")
	}
}

// TestBuildWiresTheHolderRole wires Mimoto alone, as the holder pair
// does. The capability answer then lists the holder role.
func TestBuildWiresTheHolderRole(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a, err := app.Build(config.Config{
		MimotoURL: f.URL(), WebURL: "http://localhost:17085", OfferTTL: time.Minute, Timeout: time.Second, MaxBytes: 1 << 20,
	}, app.Deps{HTTP: f.Client()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	caps, err := a.Service.GetCapabilities(t.Context(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil || len(caps.Msg.GetRoles()) != 1 || caps.Msg.GetRoles()[0].String() != "ROLE_HOLDER" {
		t.Fatalf("capabilities = %v %v", caps, err)
	}
}

// TestHolderPinPathOverConnect runs the PIN path of P6-I7c through the
// Connect handler, as wallet-auth and the wallet portal call it: the
// login, the lock state, the PIN the holder sets, the list, and a claim
// in Inji Web with the same PIN that then shows in the list.
func TestHolderPinPathOverConnect(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a, err := app.Build(config.Config{
		MimotoURL: f.URL(), WebURL: "http://localhost:17085", OfferTTL: time.Minute, Timeout: time.Second, MaxBytes: 1 << 20,
	}, app.Deps{HTTP: f.Client()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	holder := backendv1connect.NewHolderBackendServiceClient(srv.Client(), srv.URL)
	ctx := t.Context()
	reg, err := holder.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{PairwiseSubject: "iss|sub", IdToken: "id.token.of.the.login"}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	wallet := reg.Msg.GetWalletId()
	lock, err := holder.GetWalletLock(ctx, connect.NewRequest(&backendv1.GetWalletLockRequest{WalletId: wallet}))
	if err != nil || lock.Msg.GetState() != backendv1.WalletLock_WALLET_LOCK_NEEDS_NEW_PIN {
		t.Fatalf("lock = %v %v", lock, err)
	}
	if _, err = holder.UnlockWallet(ctx, connect.NewRequest(&backendv1.UnlockWalletRequest{WalletId: wallet, Pin: "271828"})); err != nil {
		t.Fatalf("UnlockWallet: %v", err)
	}
	if err = f.ClaimInInjiWeb("id.token.of.the.login", "271828"); err != nil {
		t.Fatalf("the claim in Inji Web: %v", err)
	}
	list, err := holder.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{WalletId: wallet}))
	if err != nil || len(list.Msg.GetCredentials()) != 3 {
		t.Fatalf("ListCredentials = %v %v", list, err)
	}
}

// get reads one path of the plain HTTP handler.
func get(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path) //nolint:noctx // a test call
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// TestPresentationDefinitionAbsentIs404: before the issuer names the
// credential to present, Certify finds no definition.
func TestPresentationDefinitionAbsentIs404(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	srv := httptest.NewServer(build(t, f, func(c *config.Config) { c.PresentationDuringIssuance = true }).Mux)
	defer srv.Close()
	if status, _ := get(t, srv, "/iar/presentation-definition.json"); status != http.StatusNotFound {
		t.Errorf("status = %d", status)
	}
}

// TestPresentationDefinitionServedFromSetting: the handler serves the
// definition of SetPresentationRequirement, the file Certify reads.
func TestPresentationDefinitionServedFromSetting(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a := build(t, f, func(c *config.Config) {
		c.PresentationDuringIssuance = true
		c.IARIdentityClaims = "vcaSubject"
	})
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := backendv1connect.NewIssuerBackendServiceClient(srv.Client(), srv.URL)
	set, err := client.SetPresentationRequirement(t.Context(), connect.NewRequest(&backendv1.SetPresentationRequirementRequest{
		CredentialType: "NationalIdentityCredential", RequiredClaims: []string{"vcaSubject"},
	}))
	if err != nil {
		t.Fatalf("SetPresentationRequirement: %v", err)
	}
	status, body := get(t, srv, "/iar/presentation-definition.json")
	if status != http.StatusOK || body != set.Msg.GetDefinitionJson() || !strings.Contains(body, "NationalIdentityCredential") {
		t.Errorf("status %d body %s", status, body)
	}
	if got := set.Msg.GetIdentityClaims(); len(got) != 1 || got[0] != "vcaSubject" {
		t.Errorf("identity claims = %v", got)
	}
}

// TestSweepRemovesExpiredRows: the sweep of the app runs until its
// context ends, and an app with no claims store returns at once.
func TestSweepRemovesExpiredRows(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	dir := t.TempDir()
	kv := store.Memory()
	a, err := app.Build(config.Config{
		CertifyURL: f.URL(), PublicURL: "https://adapter.example", Timeout: time.Second, MaxBytes: 1 << 20,
		ClaimsDir: dir, ClaimsSweep: time.Millisecond, OfferTTL: time.Millisecond,
		AuthzIssuer: "https://adapter.example/authz", AuthzKeySecret: "0123456789abcdef0123456789abcdef",
	}, app.Deps{HTTP: f.Client(), Store: kv, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if a.Claims == nil || a.Claims.Dir != dir {
		t.Fatalf("claims = %+v", a.Claims)
	}
	stale := filepath.Join(dir, "stale.csv")
	if werr := os.WriteFile(stale, []byte("not a row\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	// An expired offer goes with its subject (ADR-056 decision 4).
	if perr := kv.Put(t.Context(), "columns/"+hex.EncodeToString([]byte("FarmerCredential")),
		[]byte(`["fullName","farmerID","district","email"]`)); perr != nil {
		t.Fatal(perr)
	}
	offerID, err := a.Service.CreateOffer(t.Context(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential",
			SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001","district":"Nakuru","email":"ada@example.org"}`},
		Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		a.Sweep(ctx, slog.Default())
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, kept := kv.Get(t.Context(), "offer/"+offerID.Msg.GetOfferId())
		if _, err := os.Stat(stale); os.IsNotExist(err) && kept != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the sweep did not run")
		}
		time.Sleep(time.Millisecond)
	}
	// A store that is gone logs and goes on.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
	none := build(t, f, nil)
	none.Sweep(t.Context(), slog.Default())
}

// TestBuildServesTheHolderAuthorizationServer: with an issuer and a key
// secret, the adapter serves the metadata of the holder authorization
// server under the path of the issuer (ADR-052 decision 1), and an
// authorization code offer names it.
func TestBuildServesTheHolderAuthorizationServer(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a := build(t, f, func(c *config.Config) {
		c.AuthzIssuer = "https://adapter.example/authz/"
		c.AuthzKeySecret = "0123456789abcdef0123456789abcdef"
		c.OfferIssuer = "http://inji-certify-nginx:8091"
		c.WalletClients = `[{"client_id":"wallet","redirect_uris":["https://wallet.example.org/cb"]}]`
		c.HolderOIDCDiscoveryURL = "http://keycloak-inji:8080/realms/vca-holder-realm/.well-known/openid-configuration"
		c.HolderOIDCClientID = "vca-inji-authz"
		c.DataSourceURL = "http://data-source:8100"
	})
	if a.Authz == nil || a.Authz.Issuer() != "https://adapter.example/authz" {
		t.Fatalf("Authz = %v", a.Authz)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/authz/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta["token_endpoint"] != "https://adapter.example/authz/token" {
		t.Fatalf("metadata = %v", meta)
	}
	// The issuer page can name the data source of a claim without an
	// offer, because the server can ask one.
	caps, cerr := a.Service.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if cerr != nil || !slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_HOLDER_SIGN_IN_SOURCE) {
		t.Fatalf("features = %v %v", caps, cerr)
	}
	if _, serr := a.Service.SetHolderSignInSource(context.Background(), connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{
		ConfigurationIds: []string{"MemberCard"},
		Source:           &backendv1.HolderSignInSource{SourceId: "register", Field: "member_no", TokenClaim: "sub", SchemaId: "member"},
	})); serr != nil {
		t.Fatalf("set the sign in source: %v", serr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.ClaimsSweep = time.Millisecond
	a.Sweep(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestBuildRefusesAHolderServerWithoutItsSettings: the server needs the
// pair session key and a path, and a broken client list stops the start.
func TestBuildRefusesAHolderServerWithoutItsSettings(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	for name, change := range map[string]func(*config.Config){
		"no key secret": func(c *config.Config) { c.AuthzKeySecret = "" },
		"no path":       func(c *config.Config) { c.AuthzIssuer = "https://adapter.example" },
		"bad clients":   func(c *config.Config) { c.WalletClients = "[" },
	} {
		cfg := config.Config{
			CertifyURL: f.URL(), PublicURL: "https://adapter.example", OfferTTL: time.Minute, Timeout: time.Second, MaxBytes: 1 << 20,
			AuthzIssuer: "https://adapter.example/authz", AuthzKeySecret: "0123456789abcdef0123456789abcdef",
		}
		change(&cfg)
		if _, err := app.Build(cfg, app.Deps{HTTP: f.Client(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
			t.Errorf("%s: Build accepted it", name)
		}
	}
}

// TestBuildSeedsTheVerifiedClaimsOfTheHolderProvider: the setting lists
// the claims the holder provider verifies beyond email, phone_number
// and sub. It fills the list of the seeded record while the list is
// empty. Once the record holds a list, the admin portal owns it, so a
// restart keeps an edit of the admin (ADR-056 decision 2).
func TestBuildSeedsTheVerifiedClaimsOfTheHolderProvider(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	kv := store.Memory()
	start := func(verified string) []string {
		t.Helper()
		cfg := config.Config{
			CertifyURL: f.URL(), PublicURL: "https://adapter.example", OfferTTL: time.Minute, Timeout: time.Second, MaxBytes: 1 << 20,
			AuthzIssuer: "https://adapter.example/authz", AuthzKeySecret: "0123456789abcdef0123456789abcdef",
			HolderOIDCDiscoveryURL:   "http://keycloak-inji:8080/realms/vca-holder-realm/.well-known/openid-configuration",
			HolderOIDCClientID:       "vca-inji-authz",
			HolderOIDCVerifiedClaims: verified,
		}
		if _, err := app.Build(cfg, app.Deps{HTTP: f.Client(), Store: kv, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
			t.Fatalf("Build: %v", err)
		}
		raw, err := kv.Get(context.Background(), "providers")
		if err != nil {
			t.Fatal(err)
		}
		var records []struct {
			Verified []string `json:"verified_claims"`
		}
		if err := json.Unmarshal(raw, &records); err != nil || len(records) != 1 {
			t.Fatalf("providers = %s, %v", raw, err)
		}
		return records[0].Verified
	}
	if got := start(""); len(got) != 0 {
		t.Fatalf("an empty setting gave %v", got)
	}
	if got := start(" national_id, member_no ,"); len(got) != 2 || got[0] != "national_id" || got[1] != "member_no" {
		t.Fatalf("verified claims = %v", got)
	}
	if got := start(""); len(got) != 2 {
		t.Fatalf("an empty setting cleared the list of the record: %v", got)
	}
	if got := start("other"); len(got) != 2 || got[0] != "national_id" {
		t.Fatalf("the setting replaced the list of the record: %v", got)
	}
}

// TestBuildServesTheHolderProviderToTheAdmin: the admin portal edits the
// provider registry of the holder authorization server on the compose
// network with an admin session, and a restart keeps the edit. The
// proxy of the pair publishes no path to it (ADR-047).
func TestBuildServesTheHolderProviderToTheAdmin(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	key := anyval.Must(oidcflow.GenerateKey())
	signer := anyval.Must(oidcflow.NewSigner(key, "https://admin.test", oidcflow.AdminAudience, 15*time.Minute, nil))
	jwks := httptest.NewServer(signer.JWKSHandler())
	defer jwks.Close()
	kv := store.Memory()
	build := func(adminJWKS string) *httptest.Server {
		t.Helper()
		cfg := config.Config{
			CertifyURL: f.URL(), PublicURL: "https://adapter.example", OfferTTL: time.Minute, Timeout: time.Second, MaxBytes: 1 << 20,
			AuthzIssuer: "https://adapter.example/authz", AuthzKeySecret: "0123456789abcdef0123456789abcdef",
			HolderOIDCDiscoveryURL: "http://keycloak-inji:8080/realms/vca-holder-realm/.well-known/openid-configuration",
			HolderOIDCClientID:     "vca-inji-authz", AdminJWKSURL: adminJWKS,
		}
		a, err := app.Build(cfg, app.Deps{HTTP: f.Client(), Store: kv, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(a.Mux)
		t.Cleanup(srv.Close)
		return srv
	}
	srv := build(jwks.URL)
	client := adminv1connect.NewAdminServiceClient(srv.Client(), srv.URL)
	if _, err := client.ListAuthProviders(context.Background(), connect.NewRequest(&adminv1.ListAuthProvidersRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a call without a session: %v", err)
	}
	token, _, err := signer.Issue(oidcflow.Claims{Subject: "kc|admin"})
	if err != nil {
		t.Fatal(err)
	}
	withToken := func(req connect.AnyRequest) {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	list := connect.NewRequest(&adminv1.ListAuthProvidersRequest{})
	withToken(list)
	got, err := client.ListAuthProviders(context.Background(), list)
	if err != nil || len(got.Msg.GetProviders()) != 1 {
		t.Fatalf("list = %v %v", got, err)
	}
	record := got.Msg.GetProviders()[0]
	record.VerifiedClaims = []string{"national_id"}
	update := connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: record})
	withToken(update)
	if _, uerr := client.UpdateAuthProvider(context.Background(), update); uerr != nil {
		t.Fatalf("update: %v", uerr)
	}
	// A restart keeps the edit, and the server offers the claim.
	again := build("")
	resp, err := again.Client().Post(again.URL+"/vca.admin.v1.AdminService/ListAuthProviders", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	anyval.Discard(resp.Body.Close())
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("without an admin key set the adapter serves the provider RPCs: %d", resp.StatusCode)
	}
	raw, err := kv.Get(context.Background(), "providers")
	if err != nil || !strings.Contains(string(raw), `"national_id"`) {
		t.Fatalf("the edit did not stay: %s %v", raw, err)
	}
}

// refusingStore fails every write of a provider record that lists
// verified claims.
type refusingStore struct{ store.KeyValue }

func (r refusingStore) Put(ctx context.Context, key string, value []byte) error {
	if key == "providers" && strings.Contains(string(value), "verified_claims") {
		return errors.New("the disk is full")
	}
	return r.KeyValue.Put(ctx, key, value)
}

func TestBuildStopsWhenTheVerifiedClaimsDoNotStay(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cfg := config.Config{
		CertifyURL: f.URL(), PublicURL: "https://adapter.example", OfferTTL: time.Minute, Timeout: time.Second, MaxBytes: 1 << 20,
		AuthzIssuer: "https://adapter.example/authz", AuthzKeySecret: "0123456789abcdef0123456789abcdef",
		HolderOIDCDiscoveryURL: "http://keycloak-inji:8080/realms/vca-holder-realm/.well-known/openid-configuration",
		HolderOIDCClientID:     "vca-inji-authz", HolderOIDCVerifiedClaims: "national_id",
	}
	_, err := app.Build(cfg, app.Deps{HTTP: f.Client(), Store: refusingStore{store.Memory()}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err == nil || !strings.Contains(err.Error(), "verified claims") {
		t.Fatalf("Build = %v", err)
	}
}

// TestBuildServesTheKeyRotation: the adapter serves the rotation of the
// token key at its own path, outside the issuer path that the proxy
// publishes (ADR-056 decision 6).
func TestBuildServesTheKeyRotation(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	secret := "0123456789abcdef0123456789abcdef"
	a := build(t, f, func(c *config.Config) {
		c.AuthzIssuer = "https://adapter.example/authz"
		c.AuthzKeySecret = secret
	})
	if strings.HasPrefix(authz.RotatePath, "/authz/") {
		t.Fatalf("the rotation sits under the public path: %s", authz.RotatePath)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+authz.RotatePath+"?immediate=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+authz.RotationToken([]byte(secret)))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	var rot authz.Rotation
	if err := json.NewDecoder(resp.Body).Decode(&rot); err != nil || resp.StatusCode != http.StatusOK || rot.Kid == "" {
		t.Fatalf("rotation = %d %+v %v", resp.StatusCode, rot, err)
	}
}

// TestBuildServesTheMetadataWhereRfc8414PutsIt is finding 10 of the
// review: RFC 8414 section 3 puts the metadata of the issuer
// https://host/authz at https://host/.well-known/oauth-authorization-server/authz.
// The adapter serves it there and at the appended path, and it answers
// the openid-configuration names of both forms too.
func TestBuildServesTheMetadataWhereRfc8414PutsIt(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a := build(t, f, func(c *config.Config) {
		c.AuthzIssuer = "https://adapter.example/authz"
		c.AuthzKeySecret = "0123456789abcdef0123456789abcdef"
	})
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	for _, path := range []string{
		"/.well-known/oauth-authorization-server/authz", "/.well-known/openid-configuration/authz",
		"/authz/.well-known/oauth-authorization-server", "/authz/.well-known/openid-configuration",
	} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		derr := json.NewDecoder(resp.Body).Decode(&meta)
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
		if derr != nil || resp.StatusCode != http.StatusOK || meta["issuer"] != "https://adapter.example/authz" {
			t.Errorf("%s = %d %v %v", path, resp.StatusCode, meta, derr)
		}
	}
	if got := a.Authz.WellKnownPaths(); len(got) != 2 || got[0] != "/.well-known/oauth-authorization-server/authz" {
		t.Errorf("WellKnownPaths = %v", got)
	}
}
