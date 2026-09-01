package waltid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// seedCatalog mirrors the production baseline at
// deploy/compose/stack/issuer-api/config/credential-issuer-metadata.conf
// in miniature. Tests don't need every walt.id stock entry — what matters
// is that the file ends with a closing brace so appendCredentialType has
// somewhere to splice into.
const seedCatalog = `supportedCredentialTypes = {
    BankId = [VerifiableCredential, BankId],
    UniversityDegree = [VerifiableCredential, UniversityDegree],
}
`

func writeSeed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credential-issuer-metadata.conf")
	if err := os.WriteFile(path, []byte(seedCatalog), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return path
}

func TestAppendCredentialType_w3cFansOutAcrossFormats(t *testing.T) {
	path := writeSeed(t)
	schema := vctypes.Schema{
		ID:     "custom-abc123",
		Name:   "Farmer Cred",
		Desc:   "Identity for verified farmers",
		Std:    "w3c_vcdm_2",
		Custom: true,
	}
	primary, all, changed, err := appendCredentialType(path, schema)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true on first save")
	}
	if primary != "FarmerCred_jwt_vc_json" {
		t.Fatalf("primary configID = %q, want FarmerCred_jwt_vc_json", primary)
	}
	wantAll := []string{
		"FarmerCred_jwt_vc_json",
		"FarmerCred_jwt_vc_json-ld",
		"FarmerCred_ldp_vc",
	}
	if got := strings.Join(all, ","); got != strings.Join(sortedCopy(wantAll), ",") {
		t.Errorf("all configIDs = %q, want %q", got, strings.Join(sortedCopy(wantAll), ","))
	}
	got, _ := os.ReadFile(path)
	gotStr := string(got)
	// Note: no simple-array form. We deliberately don't emit it because
	// dotted type names (mdoc) break HOCON's flat-key parser and the
	// shorthand is redundant once we have per-format blocks.
	for _, frag := range []string{
		`"FarmerCred_jwt_vc_json" = {`,
		`format = "jwt_vc_json"`,
		`"FarmerCred_jwt_vc_json-ld" = {`,
		`format = "jwt_vc_json-ld"`,
		`"FarmerCred_ldp_vc" = {`,
		`format = "ldp_vc"`,
		`"@context" = [`,
		`type = ["VerifiableCredential", "FarmerCred"]`,
		`name = "Farmer Cred"`,
		`description = "Identity for verified farmers"`,
	} {
		if !strings.Contains(gotStr, frag) {
			t.Errorf("expected file to contain %q\n--full file--\n%s", frag, gotStr)
		}
	}
	trimmed := strings.TrimRight(gotStr, " \t\r\n")
	if !strings.HasSuffix(trimmed, "}") {
		t.Errorf("file does not end with closing brace")
	}
}

func TestAppendCredentialType_sdJWT(t *testing.T) {
	path := writeSeed(t)
	// buildSDJWTEntry derives the vct from VERIFIABLY_PUBLIC_URL — pin it so the
	// assertion is deterministic (host-derived vct, matching the verifier).
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://verify.test")
	primary, all, changed, err := appendCredentialType(path, vctypes.Schema{
		ID: "custom-sd1", Name: "Health Card", Std: "sd_jwt_vc (IETF)", Custom: true,
	})
	if err != nil || !changed {
		t.Fatalf("append: changed=%v err=%v", changed, err)
	}
	if primary != "HealthCard_vc+sd-jwt" {
		t.Errorf("primary = %q, want HealthCard_vc+sd-jwt", primary)
	}
	if len(all) != 1 || all[0] != "HealthCard_vc+sd-jwt" {
		t.Errorf("all = %v, want [HealthCard_vc+sd-jwt]", all)
	}
	got, _ := os.ReadFile(path)
	for _, frag := range []string{
		`"HealthCard_vc+sd-jwt" = {`,
		`format = "vc+sd-jwt"`,
		`vct = "https://verify.test/credentials/custom-sd1"`, // host-derived — matches verifier CredentialVct
		`cryptographic_binding_methods_supported = ["jwk"]`,
	} {
		if !strings.Contains(string(got), frag) {
			t.Errorf("missing fragment %q\n%s", frag, got)
		}
	}
}

// TestAppendCredentialType_mDocIsANoOp pins that appendCredentialType writes
// NOTHING to the legacy issuer-api's catalog for mso_mdoc schemas.
//
// mdoc issuance never reaches the legacy issuer-api at all — IssueToWallet
// dispatches Std=="mso_mdoc" straight to issueMdocViaIssuer2 before it ever
// touches this catalog (see issuer.go's IssueToWallet: legacy issuer-api
// "cannot type CBOR at any version... would emit birth_date as text instead
// of tag 1004", so an mdoc offer through it is unusable even if the entry
// parsed). mdoc's real catalog lives in issuer-api2, pre-provisioned per
// docType and kept in sync by syncIssuer2DisplayName instead.
//
// A legacy-catalog mdoc entry is therefore dead weight that only a wallet
// misconfiguration could ever reach — and it actively crash-loops issuer-api
// at boot, because CredentialSupported.claims (the only field buildMDocEntry
// can target) requires a two-level namespaced map and buildMDocEntry writes
// the id.walt.openid4vci-style {path, display} array instead, which legacy
// issuer-api's decoder rejects (see the 2026-08-24 and 2026-08-25 incidents:
// POST /onboard/issuer and POST /openid4vc/sdjwt/issue both connection-
// refused because a JsonDecodingException on $.claims killed the process
// before its web server bound). See TestBuildClaimsBlockFlatObjectForW3C in
// catalog_labels_test.go for the fix that made non-mdoc entries no longer
// use that shape — mdoc's fix is to never reach the legacy catalog at all.
func TestAppendCredentialType_mDocIsANoOp(t *testing.T) {
	path := writeSeed(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	primary, all, changed, err := appendCredentialType(path, vctypes.Schema{
		ID: "custom-md1", Name: "Drivers License", Std: "mso_mdoc", Custom: true,
		AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if changed {
		t.Errorf("changed = true, want false — mdoc must not touch the legacy catalog")
	}
	if primary != "" {
		t.Errorf("primary = %q, want empty — mdoc has no legacy configID", primary)
	}
	if all != nil {
		t.Errorf("all = %v, want nil — mdoc registers nothing in the legacy catalog", all)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("catalog file was modified for an mso_mdoc schema:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestAppendCredentialType_displayBlocksAllFormats pins the display
// block onto every format's catalog entry. Earlier buildSDJWTEntry and
// buildMDocEntry skipped display entirely, so wallets rendered SD-JWT
// and mdoc cards with no title/description even when the schema-builder
// captured both. Empirically verified against waltid/issuer-api:0.18.2:
// the display block on a vc+sd-jwt entry round-trips into the
// /draft13/.well-known/openid-credential-issuer response unchanged.
func TestAppendCredentialType_displayBlocksAllFormats(t *testing.T) {
	cases := []struct {
		name         string
		schema       vctypes.Schema
		wantConfigID string
		wantName     string
		wantDesc     string
	}{
		{
			name: "W3C VCDM ldp_vc",
			schema: vctypes.Schema{
				ID: "custom-w3c", Name: "Pharma Credential",
				Desc: "Issued by Ministry of Health", Std: "w3c_vcdm_2", Custom: true,
			},
			wantConfigID: "PharmaCredential_jwt_vc_json",
			wantName:     "Pharma Credential",
			wantDesc:     "Issued by Ministry of Health",
		},
		{
			name: "SD-JWT (vc+sd-jwt)",
			schema: vctypes.Schema{
				ID: "custom-sd", Name: "Pharma Credential",
				Desc: "Issued by Ministry of Health", Std: "sd_jwt_vc (IETF)", Custom: true,
			},
			wantConfigID: "PharmaCredential_vc+sd-jwt",
			wantName:     "Pharma Credential",
			wantDesc:     "Issued by Ministry of Health",
		},
		// No mso_mdoc case here: appendCredentialType is a no-op for mdoc
		// schemas (TestAppendCredentialType_mDocIsANoOp) — it never writes to
		// the legacy catalog this test inspects. buildMDocEntry's own display
		// block is covered directly by
		// TestBuildMDocEntry_ClaimsUseCorrectNamespacePerDocType in
		// catalog_labels_test.go, and mdoc's real (issuer-api2) display name
		// is covered by TestSetIssuer2Display_* in catalog_issuer2_test.go.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSeed(t)
			if _, _, changed, err := appendCredentialType(path, tc.schema); err != nil || !changed {
				t.Fatalf("append: changed=%v err=%v", changed, err)
			}
			got, _ := os.ReadFile(path)
			gs := string(got)
			if !strings.Contains(gs, `"`+tc.wantConfigID+`"`) {
				t.Fatalf("missing entry %q in catalog", tc.wantConfigID)
			}
			// Each test case uses a unique schema name + description, so
			// fragment matches against the whole file are safe — they
			// can't collide with siblings the same writer added in other
			// formats. (W3C path writes three entries for one schema;
			// they share the same display block, so any of them
			// matching is sufficient.)
			for _, frag := range []string{
				`name = "` + tc.wantName + `"`,
				`description = "` + tc.wantDesc + `"`,
			} {
				if !strings.Contains(gs, frag) {
					t.Errorf("[%s] missing %q in catalog file", tc.name, frag)
				}
			}
		})
	}
}

// TestAppendCredentialType_issuerDisplayNameAppended confirms that a
// non-empty Schema.IssuerDisplayName composes into the catalog's
// description as " · Issued by <name>". walt.id 0.18.2's per-credential
// display block has no dedicated issuer field, so this composition is
// the only way an external wallet learns who stands behind the
// credential — a load-bearing behavior worth pinning.
func TestAppendCredentialType_issuerDisplayNameAppended(t *testing.T) {
	path := writeSeed(t)
	if _, _, _, err := appendCredentialType(path, vctypes.Schema{
		ID:                "custom-iss",
		Name:              "Pharma Credential",
		Desc:              "Authorisation to dispense controlled medicines",
		IssuerDisplayName: "Ministry of Health",
		Std:               "sd_jwt_vc (IETF)",
		Custom:            true,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, _ := os.ReadFile(path)
	want := `description = "Authorisation to dispense controlled medicines · Issued by Ministry of Health"`
	if !strings.Contains(string(got), want) {
		t.Errorf("missing composed description %q\n%s", want, got)
	}
}

func TestAppendCredentialType_idempotent(t *testing.T) {
	path := writeSeed(t)
	schema := vctypes.Schema{
		ID: "custom-x", Name: "Foo", Std: "w3c_vcdm_2", Custom: true,
	}
	if _, _, changed, err := appendCredentialType(path, schema); err != nil || !changed {
		t.Fatalf("first append: changed=%v err=%v", changed, err)
	}
	if _, _, changed, err := appendCredentialType(path, schema); err != nil || changed {
		t.Fatalf("second append: changed=%v (want false), err=%v", changed, err)
	}
	got, _ := os.ReadFile(path)
	for _, configID := range []string{"Foo_jwt_vc_json", "Foo_jwt_vc_json-ld", "Foo_ldp_vc"} {
		if c := strings.Count(string(got), `"`+configID+`"`); c != 1 {
			t.Errorf("expected 1 entry for %q, got %d", configID, c)
		}
	}
}

func TestAppendCredentialType_unsupportedFormat(t *testing.T) {
	path := writeSeed(t)
	if _, _, _, err := appendCredentialType(path, vctypes.Schema{
		ID: "custom-y", Name: "Bar", Std: "totally-fake-std", Custom: true,
	}); err == nil {
		t.Fatalf("expected error for unknown Std")
	}
}

func TestRemoveCredentialType_roundTrip(t *testing.T) {
	path := writeSeed(t)
	schema := vctypes.Schema{
		ID: "custom-z", Name: "Baz Bat", Desc: "test", Std: "w3c_vcdm_2", Custom: true,
	}
	if _, _, _, err := appendCredentialType(path, schema); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := removeCredentialType(path, schema); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, _ := os.ReadFile(path)
	gotStr := string(got)
	for _, fragment := range []string{
		"BazBat_jwt_vc_json",
		"BazBat_jwt_vc_json-ld",
		"BazBat_ldp_vc",
	} {
		if strings.Contains(gotStr, fragment) {
			t.Errorf("expected %q removed, but it survived\n%s", fragment, gotStr)
		}
	}
	for _, want := range []string{"BankId", "UniversityDegree"} {
		if !strings.Contains(gotStr, want) {
			t.Errorf("expected seed entry %q to survive removal\n%s", want, gotStr)
		}
	}
	trimmed := strings.TrimRight(gotStr, " \t\r\n")
	if !strings.HasSuffix(trimmed, "}") {
		t.Errorf("file lost its closing brace: %q", trimmed)
	}
}

func TestAppendCredentialType_extraTypeOverride(t *testing.T) {
	path := writeSeed(t)
	primary, _, _, err := appendCredentialType(path, vctypes.Schema{
		ID:              "custom-q",
		Name:            "doesnt matter",
		AdditionalTypes: []string{"FarmCertificate"},
		Std:             "w3c_vcdm_2",
		Custom:          true,
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if primary != "FarmCertificate_jwt_vc_json" {
		t.Errorf("configID = %q, want FarmCertificate_jwt_vc_json", primary)
	}
}

// sortedCopy returns a sorted copy without mutating the input — used to
// compare slice equality without imposing ordering on callers.
func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestSchemaAllowlistIncludesISOmDL(t *testing.T) {
	// Commit 6449f96 dropped mDL from the demo grid because its mso_mdoc
	// envelope was hard to round-trip through MOSIP / Inji Verify. The mDL
	// work verifies through its own path, so the entry comes back.
	want := "Iso18013 Drivers License Credential"
	for _, s := range schemaAllowlistDefault {
		if s == want {
			return
		}
	}
	t.Fatalf("expected %q in schemaAllowlistDefault, got %v", want, schemaAllowlistDefault)
}

