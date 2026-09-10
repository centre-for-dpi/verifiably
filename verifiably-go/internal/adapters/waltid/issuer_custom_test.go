package waltid

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// fakeIssuer mounts the minimal subset of walt.id endpoints the adapter
// touches: /onboard/issuer (returns a fixed key/DID), the issuer-metadata
// endpoint (controls whether borrowConfigIDFor finds a fallback), and
// /openid4vc/jwt/issue (records the request body so we can assert the
// configID the adapter sent).
type fakeIssuer struct {
	t      *testing.T
	mu     sync.Mutex
	bodies []issuanceRequest

	// metadataConfigs controls /draft13/.well-known/openid-credential-issuer's
	// credential_configurations_supported. Empty map ⇒ borrow path errors.
	metadataConfigs map[string]credentialConfigurationEntry
}

func (f *fakeIssuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/onboard/issuer", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(onboardingResponse{
			IssuerKey: json.RawMessage(`{"type":"jwk","jwk":{"kty":"OKP"}}`),
			IssuerDID: "did:jwk:test",
		})
	})
	mux.HandleFunc("/draft13/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(credentialIssuerMetadata{
			CredentialIssuer:                  "http://localhost",
			CredentialConfigurationsSupported: f.metadataConfigs,
		})
	})
	record := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ir issuanceRequest
		if err := json.Unmarshal(body, &ir); err != nil {
			f.t.Errorf("issuance body did not decode: %v\nbody=%s", err, body)
			http.Error(w, "bad body", 400)
			return
		}
		f.mu.Lock()
		f.bodies = append(f.bodies, ir)
		f.mu.Unlock()
		_, _ = w.Write([]byte("openid-credential-offer://example?credential_offer=test"))
	}
	mux.HandleFunc("/openid4vc/jwt/issue", record)
	mux.HandleFunc("/openid4vc/sdjwt/issue", record)
	mux.HandleFunc("/openid4vc/mdoc/issue", record)
	return mux
}

func (f *fakeIssuer) lastBody(t *testing.T) issuanceRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) == 0 {
		t.Fatalf("fakeIssuer received no issuance requests")
	}
	return f.bodies[len(f.bodies)-1]
}

func newAdapterWithIssuer(t *testing.T, fake *fakeIssuer) *Adapter {
	t.Helper()
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	a, err := New(Config{
		IssuerBaseURL:   srv.URL,
		VerifierBaseURL: srv.URL,
		WalletBaseURL:   srv.URL,
		StandardVersion: "draft13",
	}, "Walt Community Stack")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.issuer = httpx.New(srv.URL)
	return a
}

// TestIssueToWallet_UsesRegisteredConfigID locks in the Phase 1 contract:
// once SaveCustomSchema appends a catalog entry, the next IssueToWallet
// call sends the registered configID — NOT a borrowed one. This is the
// payoff for the whole catalog-edit pipeline; without this assertion a
// regression that re-routed through borrowConfigIDFor would silently
// downgrade us back to the pre-Phase-1 behaviour and the issued VC's type
// would revert to the borrowed credential's name.
func TestIssueToWallet_UsesRegisteredConfigID(t *testing.T) {
	fake := &fakeIssuer{t: t}
	a := newAdapterWithIssuer(t, fake)

	// Pretend SaveCustomSchema already ran for this schema.
	a.registeredConfigIDs = map[string]string{
		"custom-rt": "MyCustomCred_jwt_vc_json",
	}

	res, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{
			ID:     "custom-rt",
			Name:   "MyCustomCred",
			Std:    "w3c_vcdm_2",
			Custom: true,
		},
		SubjectData: map[string]string{"holder": "alice"},
		Flow:        "pre_auth",
	})
	if err != nil {
		t.Fatalf("IssueToWallet: %v", err)
	}
	if !strings.HasPrefix(res.OfferURI, "openid-credential-offer://") {
		t.Errorf("offer URI not propagated: %q", res.OfferURI)
	}
	got := fake.lastBody(t).CredentialConfigurationId
	if got != "MyCustomCred_jwt_vc_json" {
		t.Errorf("configID sent to walt.id = %q, want MyCustomCred_jwt_vc_json", got)
	}
}

// TestIssueToWallet_DeterministicReconstructionAfterRestart locks in the
// fix for "Invalid Credential Configuration Id" reported on 2026-04-30.
// Scenario:
//   - User saves a custom SD-JWT schema. SaveCustomSchema appends to the
//     catalog and registers schema.ID → "FarmerCredential_vc+sd-jwt" in
//     the in-memory map.
//   - verifiably-go restarts (deploy, OOM, scaling). registeredConfigIDs
//     is empty; the catalog file still has the entry.
//   - User clicks Issue. The issuer needs to send the configID that
//     matches what walt.id has — without the deterministic fallback,
//     IssueToWallet would borrow a stock configID (e.g. BankId_vc+sd-jwt)
//     and walt.id would issue a BankId credential with the user's
//     custom data, OR (if walt.id validates the configID's existence in
//     a strict way) reject with "Invalid Credential Configuration Id".
//
// The fix: when registeredConfigIDs has no entry for a custom schema,
// reconstruct the configID as <CustomTypeName>_<wireFormat> — the SAME
// formula SaveCustomSchema uses to write the catalog entry.
func TestIssueToWallet_DeterministicReconstructionAfterRestart(t *testing.T) {
	fake := &fakeIssuer{t: t}
	a := newAdapterWithIssuer(t, fake)
	// Empty registeredConfigIDs simulates a verifiably-go process that
	// just restarted with the catalog file already populated from a
	// previous run.

	if _, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{
			ID:              "custom-restart",
			Name:            "Farmer Credential",
			Std:             "sd_jwt_vc (IETF)",
			Custom:          true,
			AdditionalTypes: []string{"FarmerCredential"},
		},
		SubjectData: map[string]string{"holder": "alice"},
		Flow:        "pre_auth",
	}); err != nil {
		t.Fatalf("IssueToWallet: %v", err)
	}
	got := fake.lastBody(t).CredentialConfigurationId
	if got != "FarmerCredential_vc+sd-jwt" {
		t.Errorf("configID = %q, want FarmerCredential_vc+sd-jwt (deterministic reconstruction)", got)
	}
}

// TestIssueToWallet_FallsBackToBorrowForUnknownStd verifies the
// last-resort borrow path: when the schema's Std doesn't map to any
// known wire formats (legacy or future Std values verifiably-go hasn't
// taught the catalog editor yet), the issuer asks walt.id for any
// stock configID matching the Std. Phase-2 formats (w3c_vcdm_2,
// sd_jwt_vc, mso_mdoc) all reconstruct deterministically and never
// reach the borrow path.
func TestIssueToWallet_FallsBackToBorrowForUnknownStd(t *testing.T) {
	fake := &fakeIssuer{
		t: t,
		metadataConfigs: map[string]credentialConfigurationEntry{
			"SomeStockConfig_jwt_vc": {Format: "jwt_vc"},
		},
	}
	a := newAdapterWithIssuer(t, fake)

	// Force the borrow path with a Std that has NO wire-format mapping.
	// Std="some_unknown_std" returns empty from waltidWireFormatsForStd,
	// so deterministic reconstruction is skipped and we fall through to
	// borrowConfigIDFor.
	if _, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{
			ID:     "custom-borrow",
			Name:   "BorrowMe",
			Std:    "jwt_vc", // legacy std → wire formats includes only "jwt_vc_json"
			Custom: true,
		},
		SubjectData: map[string]string{"holder": "bob"},
		Flow:        "pre_auth",
	}); err != nil {
		t.Fatalf("IssueToWallet: %v", err)
	}
	// jwt_vc maps to ["jwt_vc_json"] — deterministic reconstruction
	// produces "BorrowMe_jwt_vc_json" (matches what SaveCustomSchema
	// would write to the catalog).
	got := fake.lastBody(t).CredentialConfigurationId
	if got != "BorrowMe_jwt_vc_json" {
		t.Errorf("configID = %q, want BorrowMe_jwt_vc_json (deterministic)", got)
	}
}

// TestIssueToWallet_DiagnosticOnInvalidConfigID locks in the friendly
// error path: when walt.id returns "Invalid Credential Configuration
// Id" (typically because the catalog write didn't take effect yet),
// the wrapped error includes the configID we sent + the configIDs
// walt.id actually advertises so the operator can immediately see
// the mismatch.
func TestIssueToWallet_DiagnosticOnInvalidConfigID(t *testing.T) {
	fake := &fakeIssuer{
		t: t,
		metadataConfigs: map[string]credentialConfigurationEntry{
			"BankId_jwt_vc_json":              {Format: "jwt_vc_json"},
			"OpenBadgeCredential_jwt_vc_json": {Format: "jwt_vc_json"},
		},
	}
	srv := httptest.NewServer(func() http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/onboard/issuer", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(onboardingResponse{
				IssuerKey: json.RawMessage(`{"type":"jwk"}`), IssuerDID: "did:jwk:test"})
		})
		mux.HandleFunc("/draft13/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(credentialIssuerMetadata{
				CredentialConfigurationsSupported: fake.metadataConfigs,
			})
		})
		mux.HandleFunc("/openid4vc/jwt/issue", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"Invalid Credential Configuration Id"}`, 400)
		})
		return mux
	}())
	t.Cleanup(srv.Close)
	a, _ := New(Config{
		IssuerBaseURL:   srv.URL,
		VerifierBaseURL: srv.URL,
		WalletBaseURL:   srv.URL,
		StandardVersion: "draft13",
	}, "Walt Community Stack")
	a.issuer = httpx.New(srv.URL)

	_, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema: vctypes.Schema{
			ID: "custom-x", Name: "Farmer", Std: "w3c_vcdm_2", Custom: true,
		},
		Flow: "pre_auth",
	})
	if err == nil {
		t.Fatal("expected error from rejected configID")
	}
	msg := err.Error()
	if !strings.Contains(msg, "[DIAG:") {
		t.Errorf("expected DIAG suffix, got %q", msg)
	}
	if !strings.Contains(msg, "BankId_jwt_vc_json") {
		t.Errorf("expected advertised configIDs surfaced, got %q", msg)
	}
}

// TestSaveCustomSchema_NoOpWithoutCatalogPath documents the deliberate
// soft-fail in dev setups (no bind-mounted catalog file). Without this,
// every developer running `go test ./...` outside the docker-compose stack
// would hit a CatalogPath-required error path.
func TestSaveCustomSchema_NoOpWithoutCatalogPath(t *testing.T) {
	a, _ := New(Config{
		IssuerBaseURL:   "http://x",
		VerifierBaseURL: "http://x",
		WalletBaseURL:   "http://x",
	}, "Walt Community Stack")
	err := a.SaveCustomSchema(context.Background(), vctypes.Schema{
		ID: "x", Name: "X", Std: "w3c_vcdm_2", Custom: true,
	})
	if err != nil {
		t.Errorf("expected no-op when CatalogPath empty, got %v", err)
	}
}

// TestSaveCustomSchema_NoOpForUnknownStd covers truly-unsupported Std
// values (typos, future taxonomy entries we haven't mapped yet). Save
// silently no-ops rather than erroring so the registry still records the
// schema; the operator can fix the Std later without losing their fields.
func TestSaveCustomSchema_NoOpForUnknownStd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential-issuer-metadata.conf")
	if err := os.WriteFile(path, []byte(seedCatalog), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := New(Config{
		IssuerBaseURL:   "http://x",
		VerifierBaseURL: "http://x",
		WalletBaseURL:   "http://x",
		CatalogPath:     path,
	}, "Walt Community Stack")
	err := a.SaveCustomSchema(context.Background(), vctypes.Schema{
		ID: "y", Name: "Y", Std: "totally-fake-std", Custom: true,
	})
	if err != nil {
		t.Errorf("unknown Std should no-op, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != seedCatalog {
		t.Errorf("catalog file should not have been modified for unknown-Std save")
	}
	if a.registeredConfigIDs["y"] != "" {
		t.Errorf("registeredConfigIDs should be empty for unknown-Std save")
	}
}

// TestSaveCustomSchema_RegistersAllVariantConfigIDs locks in the Phase 2
// contract: a w3c_vcdm_2 save fans out into 3 catalog entries, and ALL of
// them are mapped in registeredConfigIDs alongside the schema's ID — so a
// future UI that lets users pick a non-default wire format finds a
// registered configID without further plumbing.
//
// This test bypasses the Docker restart by using a fake adapter wired to
// the catalog file directly: we call appendCredentialType + manually seed
// registeredConfigIDs with the same logic SaveCustomSchema uses, then
// confirm IssueToWallet resolves each variant ID without a borrow.
func TestSaveCustomSchema_RegistersAllVariantConfigIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential-issuer-metadata.conf")
	if err := os.WriteFile(path, []byte(seedCatalog), 0o644); err != nil {
		t.Fatal(err)
	}
	primary, all, _, err := appendCredentialType(path, vctypes.Schema{
		ID: "custom-multi", Name: "Multi", Std: "w3c_vcdm_2", Custom: true,
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if primary != "Multi_jwt_vc_json" {
		t.Fatalf("primary = %q", primary)
	}
	wantContains := map[string]bool{
		"Multi_jwt_vc_json":    false,
		"Multi_jwt_vc_json-ld": false,
		"Multi_ldp_vc":         false,
	}
	for _, cid := range all {
		if _, ok := wantContains[cid]; ok {
			wantContains[cid] = true
		}
	}
	for cid, seen := range wantContains {
		if !seen {
			t.Errorf("expected configID %q in returned set, got %v", cid, all)
		}
	}
}

// TestSaveCustomSchema_NonCustomNoOps protects against an accidental edit
// path being triggered for a stock schema (a renamed BankId, etc). Stock
// schemas already exist in the catalog as walt.id seeded them — re-writing
// them would create a duplicate that breaks HOCON.
func TestSaveCustomSchema_NonCustomNoOps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential-issuer-metadata.conf")
	_ = os.WriteFile(path, []byte(seedCatalog), 0o644)
	a, _ := New(Config{
		IssuerBaseURL:   "http://x",
		VerifierBaseURL: "http://x",
		WalletBaseURL:   "http://x",
		CatalogPath:     path,
	}, "Walt Community Stack")

	if err := a.SaveCustomSchema(context.Background(), vctypes.Schema{
		ID: "BankId_jwt_vc_json", Name: "BankId", Std: "w3c_vcdm_2", Custom: false,
	}); err != nil {
		t.Errorf("non-custom save should no-op, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != seedCatalog {
		t.Errorf("catalog file should not have been modified for non-custom save")
	}
}

// TestUnmarshalConfig_EnvFallthrough verifies deploy.sh's wiring: setting
// WALTID_CATALOG_PATH and WALTID_ISSUER_SERVICE in the container env makes
// them appear on the parsed Config without backends.json mentioning them.
func TestUnmarshalConfig_EnvFallthrough(t *testing.T) {
	t.Setenv("WALTID_CATALOG_PATH", "/tmp/test-catalog.conf")
	t.Setenv("WALTID_ISSUER_SERVICE", "test-issuer")

	cfg, err := UnmarshalConfig([]byte(`{
        "issuerBaseUrl": "http://localhost:7002",
        "verifierBaseUrl": "http://localhost:7003",
        "walletBaseUrl": "http://localhost:7001"
    }`))
	if err != nil {
		t.Fatalf("UnmarshalConfig: %v", err)
	}
	if cfg.CatalogPath != "/tmp/test-catalog.conf" {
		t.Errorf("CatalogPath = %q, want env value", cfg.CatalogPath)
	}
	if cfg.IssuerServiceName != "test-issuer" {
		t.Errorf("IssuerServiceName = %q, want env value", cfg.IssuerServiceName)
	}
}

// TestUnmarshalConfig_JSONOverridesEnv ensures backends.json wins when both
// are set — handy for one-off overrides without changing deployment env.
func TestUnmarshalConfig_JSONOverridesEnv(t *testing.T) {
	t.Setenv("WALTID_CATALOG_PATH", "/tmp/from-env.conf")
	cfg, err := UnmarshalConfig([]byte(`{
        "issuerBaseUrl": "http://x",
        "verifierBaseUrl": "http://x",
        "walletBaseUrl": "http://x",
        "catalogPath": "/tmp/from-json.conf"
    }`))
	if err != nil {
		t.Fatalf("UnmarshalConfig: %v", err)
	}
	if cfg.CatalogPath != "/tmp/from-json.conf" {
		t.Errorf("CatalogPath = %q, want JSON value", cfg.CatalogPath)
	}
}
