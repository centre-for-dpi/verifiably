package injicertify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdoc"
)

// TestListSchemasResolvesMdocFieldFormats pins a real bug found during Task 6
// end-to-end verification: an operator created the mDL schema via the real
// builder (SaveCustomSchema wrote it correctly, with driving_privileges/
// portrait declared with their real ISO shapes), filled in a real driving
// category, submitted — and got "driving_privileges es obligatorio" anyway.
//
// Root cause: ListSchemas rebuilds each field's vctypes.FieldSpec from the
// wellknown's `order` array via fieldSpecFor, whose generic name-based
// heuristics have no case for "driving_privileges" or "portrait" — they fall
// through to plain string/required. SubmitIssue's isStructuredField/
// isImageField checks key ONLY on FieldSpec.Format
// (mdoc.FormatDrivingPrivileges / mdoc.FormatImage), so a mdoc schema
// round-tripped through ListSchemas silently lost the one property that
// routes driving_privileges into StructuredData instead of a scalar string
// in SubjectData — reproduced live against a real Inji Certify v0.14.0.
func TestListSchemasResolvesMdocFieldFormats(t *testing.T) {
	body := map[string]any{
		"credential_configurations_supported": map[string]any{
			"custom-dkyyyh7q0fnp": map[string]any{
				"format":  "mso_mdoc",
				"doctype": "org.iso.18013.5.1.mDL",
				"order": []string{
					"family_name", "given_name", "birth_date",
					"issue_date", "expiry_date", "issuing_country",
					"issuing_jurisdiction", "issuing_authority", "document_number",
					"portrait", "portrait_capture_date", "driving_privileges",
					"un_distinguishing_sign",
				},
				"display": []map[string]any{{"name": "Mobile Driving Licence", "locale": "en"}},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := a.ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 1 {
		t.Fatalf("expected 1 schema, got %d", len(schemas))
	}

	byName := map[string]string{} // field name -> Format
	for _, f := range schemas[0].FieldsSpec {
		byName[f.Name] = f.Format
	}

	if got := byName["driving_privileges"]; got != mdoc.FormatDrivingPrivileges {
		t.Errorf("driving_privileges Format = %q, want %q (mdoc.FormatDrivingPrivileges) — "+
			"without this, SubmitIssue's isStructuredField never routes it into StructuredData", got, mdoc.FormatDrivingPrivileges)
	}
	if got := byName["portrait"]; got != mdoc.FormatImage {
		t.Errorf("portrait Format = %q, want %q (mdoc.FormatImage)", got, mdoc.FormatImage)
	}
	// A plain scalar mandatory field should still resolve to a sensible
	// Format via the normal path (here: "date", from mdoc.MandatoryFields —
	// confirming the fix doesn't regress non-structured mdoc fields).
	if got := byName["birth_date"]; got != "date" {
		t.Errorf("birth_date Format = %q, want %q", got, "date")
	}
}

// TestListSchemasSetsAdditionalTypesForMdoc pins a second real bug found
// during Task 6 end-to-end verification, discovered only AFTER the field-
// Format fix above and the Velocity-template/claims-nesting fixes were
// already deployed: a real operator-created mDL, issued through this exact
// rebuilt-from-wellknown path, failed with
// "pre-authorized-data: unknown_claims" — Inji Certify's error log showed
// "Unknown claims provided: [custom-<nano-id>]", the schema's OWN ID, not a
// field name.
//
// Root cause: ListSchemas never set AdditionalTypes on the rebuilt
// vctypes.Schema. IssueToWallet's mdocDocTypeForSchema(req.Schema) reads
// AdditionalTypes[0] first and falls back to schema.ID only when empty —
// so the claims-nesting fix (mdocNamespaceForDocType(mdocDocTypeForSchema
// (...))) derived the namespace from the schema's own generated ID instead
// of the real ISO docType, nesting claims under completely the wrong key.
// SaveCustomSchema's schema (freshly submitted from the builder form) has
// always carried AdditionalTypes correctly; only the ListSchemas-rebuilt
// path (used at issuance time, once the schema already exists) had this
// gap — which is exactly why Task 2/3's own tests, built by hand with
// AdditionalTypes already set, never caught it.
func TestListSchemasSetsAdditionalTypesForMdoc(t *testing.T) {
	body := map[string]any{
		"credential_configurations_supported": map[string]any{
			"custom-dkzy5558eher": map[string]any{
				"format":  "mso_mdoc",
				"doctype": "org.iso.18013.5.1.mDL",
				"order":   []string{"family_name"},
				"display": []map[string]any{{"name": "Mobile Driving Licence", "locale": "en"}},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := a.ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 1 {
		t.Fatalf("expected 1 schema, got %d", len(schemas))
	}

	got := schemas[0].AdditionalTypes
	if len(got) != 1 || got[0] != "org.iso.18013.5.1.mDL" {
		t.Fatalf("AdditionalTypes = %v, want [\"org.iso.18013.5.1.mDL\"] (from the wellknown's doctype field) — "+
			"without this, IssueToWallet's mdocDocTypeForSchema falls back to schema.ID and nests claims under "+
			"the schema's own generated ID instead of the real ISO namespace", got)
	}
}

// TestListSchemasNonMdocUnaffected confirms the fix is scoped to
// format=="mso_mdoc" only — a non-mdoc schema (SD-JWT/ldp_vc) must keep
// using fieldSpecFor's generic heuristics exactly as before, since it has
// no doctype/mdoc.MandatoryFields concept at all.
func TestListSchemasNonMdocUnaffected(t *testing.T) {
	schemas, err := wellknownWith(t, []string{"entity_name", "testa_id"}).
		ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 1 {
		t.Fatalf("expected 1 schema, got %d", len(schemas))
	}
	for _, f := range schemas[0].FieldsSpec {
		if f.Format == mdoc.FormatDrivingPrivileges || f.Format == mdoc.FormatImage {
			t.Errorf("non-mdoc field %q unexpectedly got an mdoc-specific Format %q", f.Name, f.Format)
		}
	}
}
