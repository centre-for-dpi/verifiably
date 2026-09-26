// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
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
