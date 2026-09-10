package waltid

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// TestSchemaAllowlistDefault_IncludesMdl is a regression test for a live
// finding on cdpi-vps: schemaAllowlistDefault's doc comment claimed a
// "five-credential demo set" but the array only ever had four entries, none
// of them mDL — so org.iso.18013.5.1.mDL (and every jwt/ldp/sd-jwt variant
// sharing its "Iso18013 Drivers License Credential" display-name bucket)
// 404'd from every discovery path, including APIIssue's schema_id lookup,
// with the default allowlist active. This is independent of the
// displayNameFor fix above — that fix makes the mdoc entry's name
// resolvable at all; this test is what actually keeps it visible.
func TestSchemaAllowlistDefault_IncludesMdl(t *testing.T) {
	found := false
	for _, name := range schemaAllowlistDefault {
		if name == "Iso18013 Drivers License Credential" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("schemaAllowlistDefault = %v, missing \"Iso18013 Drivers License Credential\" — mDL would 404 from APIIssue with the default allowlist active", schemaAllowlistDefault)
	}
}

// TestApplySchemaAllowlist_MdlSurvivesDefaultFilter confirms the schema
// actually survives applySchemaAllowlist's case-insensitive match against
// the default list — not just that the name string is present in the
// array, but that the filtering function genuinely keeps it.
func TestApplySchemaAllowlist_MdlSurvivesDefaultFilter(t *testing.T) {
	// Pin to the true default regardless of the ambient environment —
	// schemaAllowlistFromEnv reads this var directly via os.Getenv.
	t.Setenv("VERIFIABLY_WALTID_SCHEMA_ALLOWLIST", "")
	in := []vctypes.Schema{
		{ID: "org.iso.18013.5.1.mDL", Name: "Iso18013 Drivers License Credential"},
		{ID: "SomeOtherCredential_jwt_vc_json", Name: "Some Other Credential"},
	}
	out := applySchemaAllowlist(in)
	if len(out) != 1 || out[0].ID != "org.iso.18013.5.1.mDL" {
		t.Fatalf("applySchemaAllowlist(default) = %+v, want only the mDL schema to survive", out)
	}
}

// TestDisplayNameFor_MsoMdocDoctypeID reproduces a bug found live on
// cdpi-vps: displayNameFor("org.iso.18013.5.1.mDL", ...) produced the
// unreadable "org.iso.18013.5.1.m DL" — mso_mdoc config ids are keyed by
// doctype verbatim (no "_<format>" suffix to strip, unlike every other
// walt.id format), so step 2's suffix-stripping never fired and step 3's
// acronym-aware humaniser mangled the dotted string character-by-character.
// The practical consequence: the mangled name matched nothing in
// schemaAllowlistDefault, so the credential silently vanished from the
// default card grid — and from APIIssue's schema_id lookup, since
// ListSchemas (which applySchemaAllowlist filters) is what ListAllSchemas
// searches.
func TestDisplayNameFor_MsoMdocDoctypeID(t *testing.T) {
	cfg := credentialConfigurationEntry{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
	}
	got := displayNameFor("org.iso.18013.5.1.mDL", cfg)
	want := "mDL"
	if got != want {
		t.Errorf("displayNameFor(mdoc doctype) = %q, want %q", got, want)
	}
}

// TestDisplayNameFor_MsoMdocPrefersExplicitDisplay confirms priority 1
// (cfg.Display[0].Name) still wins over the mso_mdoc fallback when walt.id's
// catalog entry declares one — e.g. the stock org.iso.18013.5.1.mDL entry
// now carries an explicit display block precisely so it matches
// schemaAllowlistDefault's "Iso18013 Drivers License Credential" without
// relying on the mDL-only fallback in step 1.5.
func TestDisplayNameFor_MsoMdocPrefersExplicitDisplay(t *testing.T) {
	cfg := credentialConfigurationEntry{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Display: []struct {
			Name   string `json:"name"`
			Locale string `json:"locale,omitempty"`
		}{{Name: "Iso18013 Drivers License Credential"}},
	}
	got := displayNameFor("org.iso.18013.5.1.mDL", cfg)
	want := "Iso18013 Drivers License Credential"
	if got != want {
		t.Errorf("displayNameFor(mdoc with explicit display) = %q, want %q", got, want)
	}
}

// TestDisplayNameFor_MsoMdocNoDotFallsBackToID guards the edge case where a
// custom mdoc schema's doctype has no dot segment at all (schema.Vct/
// AdditionalTypes[0] left blank, buildMDocEntry's own typeName fallback
// produced a plain CamelCase string) — LastIndex returns -1, so the whole
// doctype string is used verbatim rather than an out-of-range slice.
func TestDisplayNameFor_MsoMdocNoDotFallsBackToID(t *testing.T) {
	cfg := credentialConfigurationEntry{
		Format:  "mso_mdoc",
		DocType: "SomeCustomDoctype",
	}
	got := displayNameFor("SomeCustomDoctype", cfg)
	want := "SomeCustomDoctype"
	if got != want {
		t.Errorf("displayNameFor(mdoc, no dot in doctype) = %q, want %q", got, want)
	}
}

// TestDisplayNameFor_NonMdocUnaffected confirms the new mso_mdoc branch
// (step 1.5) doesn't change behavior for every other format, which still
// goes through the existing suffix-strip + humanise path.
func TestDisplayNameFor_NonMdocUnaffected(t *testing.T) {
	cfg := credentialConfigurationEntry{Format: "jwt_vc_json"}
	got := displayNameFor("Iso18013DriversLicenseCredential_jwt_vc_json", cfg)
	want := "Iso18013 Drivers License Credential"
	if got != want {
		t.Errorf("displayNameFor(non-mdoc) = %q, want %q", got, want)
	}
}
