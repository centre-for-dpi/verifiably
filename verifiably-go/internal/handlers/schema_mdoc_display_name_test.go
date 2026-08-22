package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/adapters/waltid"
	"github.com/verifiably/verifiably-go/vctypes"
)

// This file lives in package handlers, and imports the waltid adapter, on
// purpose. The defect it guards against was invisible to every test that
// hand-rolled a vctypes.Schema: the wallet showed a hardcoded "Driving Licence"
// because nothing carried the OPERATOR's name, and only a schema produced by
// currentBuilderSchema — generated "custom-<nano>" ID, docType parked in
// AdditionalTypes[0], name in Name — exercises the path that has to bridge
// those. currentBuilderSchema is unexported, so the test has to be here; the
// adapter's SaveCustomSchema and New are exported, so the whole chain is
// reachable from here without loosening anything in waltid.

// realIssuer2Metadata is the shipped issuer-api2 catalog, read from the repo
// rather than reproduced inline. A miniature stand-in is exactly how this
// plan has shipped defects before: the real file has comments, ${?VAR}
// substitutions, duplicate keys, trailing commas, a nested per-claim display
// list inside Photo ID's credential_metadata, and the docType string repeated
// as scope/doctype/claim-path — every one of which is a way for a byte-level
// editor to go wrong, and none of which a hand-written fixture reproduces.
func realIssuer2Metadata(t *testing.T) string {
	t.Helper()
	// internal/handlers -> repo root is two levels up.
	src := filepath.Join("..", "..", "deploy", "k8s", "config", "issuer2",
		"credential-issuer-metadata.conf")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read shipped issuer2 metadata: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "credential-issuer-metadata.conf")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("copy issuer2 metadata: %v", err)
	}
	return dst
}

// seedLegacyCatalog writes a legacy issuer-api catalog that ALREADY contains
// the given docTypes' mso_mdoc entries.
//
// SaveCustomSchema returns early when CatalogPath is unset, so it has to point
// somewhere for the issuer2 hook to be reached at all. Pre-seeding the entries
// makes appendCredentialType return changed=false, which is what keeps the
// legacy path from attempting its own restartContainer("issuer-api") — that
// call fails under `go test` (no docker socket) and its error IS returned, so
// an empty catalog here would mask the thing these tests actually measure
// behind an unrelated failure. The issuer2 restart is separately best-effort,
// which is exactly what TestBuilderMdocSaveSurvivesUnmountedIssuer2Config pins.
func seedLegacyCatalog(t *testing.T, docTypes ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("supportedCredentialTypes = {\n")
	for _, dt := range docTypes {
		b.WriteString("    \"" + dt + "_mso_mdoc\" = {\n        format = \"mso_mdoc\"\n    }\n")
	}
	b.WriteString("}\n")
	path := filepath.Join(t.TempDir(), "credential-issuer-metadata.conf")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("seed legacy catalog: %v", err)
	}
	return path
}

// saveBuilderMdocSchema runs the real chain: builder form data ->
// currentBuilderSchema -> adapter.SaveCustomSchema -> the HOCON on disk.
//
// Issuer2ServiceName is left at its default and no docker socket exists under
// `go test`, so the issuer2 restart fails — deliberately: the save must still
// succeed, and the file edit must already be on disk by then.
func saveBuilderMdocSchema(t *testing.T, d builderData) (metadataPath, before, after string) {
	t.Helper()
	metadataPath = realIssuer2Metadata(t)
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	before = string(raw)

	catalogPath := seedLegacyCatalog(t, "org.iso.18013.5.1.mDL", "org.iso.23220.photoid.1")

	a, err := waltid.New(waltid.Config{
		VerifierBaseURL:     "http://verifier.invalid",
		IssuerBaseURL:       "http://issuer.invalid",
		Issuer2BaseURL:      "http://issuer2.invalid",
		CatalogPath:         catalogPath,
		Issuer2MetadataPath: metadataPath,
	}, "walt.id")
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}

	schema := currentBuilderSchema(&Session{IssuerDpg: "walt.id"}, d)
	if err := a.SaveCustomSchema(context.Background(), schema); err != nil {
		t.Fatalf("SaveCustomSchema returned an error — a schema save must never fail on the display-name sync: %v", err)
	}

	raw, err = os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	return metadataPath, before, string(raw)
}

// configBlockOf extracts the body of one `"<configID>" = { ... }` entry so a
// test can assert on one configuration without matching text that belongs to a
// sibling. Independent brace-counting implementation from the production one —
// if both were the same helper, a bug in the extractor would hide itself.
func configBlockOf(t *testing.T, content, configID string) string {
	t.Helper()
	key := "\"" + configID + "\" = {"
	i := strings.Index(content, key)
	if i == -1 {
		t.Fatalf("no configuration %q in metadata", configID)
	}
	open := i + len(key) - 1
	depth := 0
	for j := open; j < len(content); j++ {
		switch content[j] {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth == 0 {
			return content[open+1 : j]
		}
	}
	t.Fatalf("unbalanced braces for %q", configID)
	return ""
}

// TestBuilderMdocSchemaNamePublishedToIssuer2 is the headline guard. An
// operator names their schema "mDL"; the wallet must show "mDL", not the
// "Driving Licence" that was hardcoded into the shipped config, and not the
// raw docType that showed before that hardcoding.
func TestBuilderMdocSchemaNamePublishedToIssuer2(t *testing.T) {
	_, _, after := saveBuilderMdocSchema(t, builderData{
		Name:    "mDL",
		Desc:    "Licencia de conducir de la República Dominicana",
		Std:     "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Fields:  []vctypes.FieldSpec{{Name: "family_name", Datatype: "string"}},
	})

	block := configBlockOf(t, after, "org.iso.18013.5.1.mDL")
	if !strings.Contains(block, `name = "mDL"`) {
		t.Errorf("mDL configuration does not carry the operator's schema name.\n--- block ---\n%s", block)
	}
	if strings.Contains(block, "Driving Licence") {
		t.Errorf("mDL configuration still carries the hardcoded \"Driving Licence\" — the operator's name did not replace it.\n--- block ---\n%s", block)
	}
	if !strings.Contains(block, "Licencia de conducir de la República Dominicana") {
		t.Errorf("mDL configuration does not carry the operator's description.\n--- block ---\n%s", block)
	}
}

// TestBuilderMdocSaveLeavesOtherDocTypeUntouched: mDL and Photo ID share one
// file. Naming one must not perturb the other by a single byte — including
// Photo ID's nested credential_metadata display lists, which a naive
// "replace the first display block" edit would corrupt.
func TestBuilderMdocSaveLeavesOtherDocTypeUntouched(t *testing.T) {
	_, before, after := saveBuilderMdocSchema(t, builderData{
		Name:    "mDL",
		Std:     "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
	})

	for _, other := range []string{
		"org.iso.23220.photoid.1",
		"org.iso.18013.5.1.mDL.aamva",
		"eu.europa.ec.eudi.pid.1",
	} {
		if got, want := configBlockOf(t, after, other), configBlockOf(t, before, other); got != want {
			t.Errorf("saving an mDL schema modified the %q configuration.\n--- before ---\n%s\n--- after ---\n%s",
				other, want, got)
		}
	}
	// The issuer-level branding block is a different concern (per deployment,
	// not per schema) and must survive untouched too — it also contains the
	// word "display", which is what a careless matcher would trip on.
	if !strings.Contains(after, "issuerDisplay = [") ||
		!strings.Contains(after, `name = ${?VERIFIABLY_ISSUER_DISPLAY_NAME}`) {
		t.Error("the issuerDisplay block was damaged by the credential-level edit")
	}
}

// TestBuilderPhotoIDSchemaNameReplacesNestedDisplayCorrectly is the mirror
// case, and the harder one: Photo ID's configuration holds a top-level display
// block AND a credential_metadata block containing 24 per-claim display lists
// plus one of its own. The edit must land on the top-level one and leave every
// nested list intact.
func TestBuilderPhotoIDSchemaNameReplacesNestedDisplayCorrectly(t *testing.T) {
	_, before, after := saveBuilderMdocSchema(t, builderData{
		Name:    "Cédula",
		Std:     "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
	})

	block := configBlockOf(t, after, "org.iso.23220.photoid.1")
	if !strings.Contains(block, `name = "Cédula"`) {
		t.Errorf("Photo ID configuration does not carry the operator's name.\n--- block ---\n%s", block)
	}
	if strings.Contains(block, `name = "Photo ID"`) {
		t.Error("Photo ID configuration still carries the hardcoded \"Photo ID\" name")
	}
	// Nested per-claim labels are untouched: a claim label is a different
	// thing from the credential name, and clobbering them would silently
	// de-localise every field on the card.
	for _, claimLabel := range []string{
		`name= "Portrait Image"`,
		`name= "Family Name"`,
		`name= "Issuing Authority"`,
	} {
		if !strings.Contains(block, claimLabel) {
			t.Errorf("per-claim label %q was destroyed by the credential-name edit", claimLabel)
		}
	}
	// credential_metadata's own display block (name "Photo ID (MSO Mdoc)") is
	// nested and must also survive: it is not the block wallets read for the
	// configuration name, and rewriting it is out of scope for this change.
	if !strings.Contains(block, `name= "Photo ID (MSO Mdoc)"`) {
		t.Error("the nested credential_metadata display block was overwritten")
	}
	// And mDL is still exactly as shipped.
	if got, want := configBlockOf(t, after, "org.iso.18013.5.1.mDL"), configBlockOf(t, before, "org.iso.18013.5.1.mDL"); got != want {
		t.Error("saving a Photo ID schema modified the mDL configuration")
	}
}

// TestBuilderMdocSaveEmitsOneLocale pins the locale decision: a schema carries
// ONE name, so exactly one display entry is published rather than repeating
// that single string under a second locale it was never translated into.
func TestBuilderMdocSaveEmitsOneLocale(t *testing.T) {
	_, _, after := saveBuilderMdocSchema(t, builderData{
		Name:    "mDL",
		Std:     "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
	})
	block := configBlockOf(t, after, "org.iso.18013.5.1.mDL")
	if n := strings.Count(block, "locale ="); n != 1 {
		t.Errorf("mDL display carries %d locale entries, want exactly 1 — a schema has one name, so a second locale would be a fabricated translation.\n--- block ---\n%s", n, block)
	}
	if strings.Contains(block, "Licencia de Conducir") {
		t.Error("the hardcoded Spanish translation survived the operator's rename")
	}
}

// The idempotence guard that gates the issuer-api2 restart lives in
// internal/adapters/waltid/catalog_issuer2_test.go
// (TestSetIssuer2Display_ChangedGatesTheRestart). It belongs there because the
// thing that must be asserted is setIssuer2Display's `changed` RETURN VALUE,
// not the file: rewriting identical bytes leaves the file identical, so a
// file-comparison test here passed even when the flag was forced true and the
// restart would have fired on every save. Verified by mutation.

// TestBuilderMdocSaveSurvivesUnmountedIssuer2Config is the failure-mode guard.
// A deployment that never mounts issuer-api2's config must keep saving schemas
// exactly as it does today, not error.
func TestBuilderMdocSaveSurvivesUnmountedIssuer2Config(t *testing.T) {
	catalogPath := seedLegacyCatalog(t, "org.iso.18013.5.1.mDL")
	for _, tc := range []struct {
		name string
		path string
	}{
		{"unset", ""},
		{"points at a file that is not there", filepath.Join(t.TempDir(), "absent.conf")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := waltid.New(waltid.Config{
				VerifierBaseURL:     "http://verifier.invalid",
				IssuerBaseURL:       "http://issuer.invalid",
				Issuer2BaseURL:      "http://issuer2.invalid",
				CatalogPath:         catalogPath,
				Issuer2MetadataPath: tc.path,
			}, "walt.id")
			if err != nil {
				t.Fatalf("new adapter: %v", err)
			}
			schema := currentBuilderSchema(&Session{IssuerDpg: "walt.id"}, builderData{
				Name:    "mDL",
				Std:     "mso_mdoc",
				DocType: "org.iso.18013.5.1.mDL",
			})
			if err := a.SaveCustomSchema(context.Background(), schema); err != nil {
				t.Errorf("SaveCustomSchema failed with Issuer2MetadataPath=%q — an unmounted issuer2 config must degrade, not break the save: %v", tc.path, err)
			}
		})
	}
}
