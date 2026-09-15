package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// TestCurrentBuilderSchemaCarriesDocType is the C1 guard: the operator's
// selected docType must survive into the SAVED schema, not just into the
// preloaded field list.
//
// extractBuilderData parses d.DocType and uses it to preload mandatory
// fields, but currentBuilderSchema originally only ever read d.ExtraType into
// AdditionalTypes. The docType was therefore dropped on save, leaving the
// generated "custom-<nano>" ID as the schema's base type. Downstream that
// meant buildIssuer2Offer could not resolve an issuer-api2 profile
// (`no issuer-api2 profile for docType "custom-..."`) and buildMDocEntry fell
// back to typeName, emitting a garbage namespace in the claim paths — every
// builder-made mdoc schema was unissuable.
//
// BaseType() is the exact accessor mdocDocTypeFor uses, so asserting on it
// pins the real resolution path rather than the field it happens to read
// from. The companion half of this guard lives in
// internal/adapters/waltid/issuer2_test.go
// (TestBuilderSavedMdocSchemaResolvesProfile), which feeds the same string
// into profileIDForDocType.
func TestCurrentBuilderSchemaCarriesDocType(t *testing.T) {
	sess := &Session{IssuerDpg: "walt.id"}

	for _, docType := range []string{"org.iso.18013.5.1.mDL", "org.iso.23220.photoid.1"} {
		d := builderData{
			Name:    "Licencia",
			Std:     "mso_mdoc",
			DocType: docType,
			Fields:  []vctypes.FieldSpec{{Name: "family_name", Datatype: "string"}},
		}
		got := currentBuilderSchema(sess, d)

		if len(got.AdditionalTypes) == 0 {
			t.Fatalf("%s: AdditionalTypes is empty — the selected docType never reached the saved schema", docType)
		}
		if got.AdditionalTypes[0] != docType {
			t.Errorf("%s: AdditionalTypes[0] = %q, want the docType", docType, got.AdditionalTypes[0])
		}
		// The catalog turns AdditionalTypes[0] into "<docType>_mso_mdoc";
		// BaseType strips that suffix back off. Simulate that round-trip,
		// because BaseType is what mdocDocTypeFor actually calls.
		saved := got
		saved.ID = got.AdditionalTypes[0] + "_mso_mdoc"
		if bt := saved.BaseType(); bt != docType {
			t.Errorf("%s: BaseType() = %q, want the docType — issuance resolves the issuer-api2 profile from this", docType, bt)
		}
	}
}

// TestMdocDocTypeValidRejectsEmptyAdditionalTypesWithoutPanicking pins the
// ordering fix: a prior version indexed AdditionalTypes[0] inside the
// validation loop and only guarded len(...)==0 five lines later, so the
// guard could never prevent the index panic it was written for. It stayed
// unreachable only by an invariant established elsewhere (extractBuilderData
// back-fills DocType from mdoc.KnownDocTypes()[0]); this test exercises the
// function directly with the invariant broken, the way a future change to
// KnownDocTypes or the back-fill condition could.
func TestMdocDocTypeValidRejectsEmptyAdditionalTypesWithoutPanicking(t *testing.T) {
	schema := vctypes.Schema{Std: "mso_mdoc", AdditionalTypes: nil}
	if mdocDocTypeValid(schema) {
		t.Fatal("mdocDocTypeValid(empty AdditionalTypes) = true, want false")
	}
}

func TestMdocDocTypeValidAcceptsKnownDocType(t *testing.T) {
	schema := vctypes.Schema{Std: "mso_mdoc", AdditionalTypes: []string{"org.iso.18013.5.1.mDL"}}
	if !mdocDocTypeValid(schema) {
		t.Fatal("mdocDocTypeValid(org.iso.18013.5.1.mDL) = false, want true")
	}
}

func TestMdocDocTypeValidRejectsUnknownDocType(t *testing.T) {
	schema := vctypes.Schema{Std: "mso_mdoc", AdditionalTypes: []string{"custom-not-a-real-doctype"}}
	if mdocDocTypeValid(schema) {
		t.Fatal("mdocDocTypeValid(unknown docType) = true, want false")
	}
}

// TestExtractBuilderDataBlankLangRowsMatchesThePostMergeField pins a
// stale-index bug: BlankLangRows used to be computed against d.Fields as
// SUBMITTED, before the block below reorders d.Fields into "mandatory
// elements first, then the operator's extras" for mso_mdoc schemas.
// BlankLangRows is index-keyed (map[int]int) and was never remapped, so a
// key computed pre-merge could point at a different field once the reorder
// ran — exactly the operator-visible symptom this test targets: the blank
// row shows up under the wrong claim.
//
// This reproduces the steady-state case the builder template actually
// produces: on every re-render, the "field_lang_i_j" keys the browser posts
// back are indexed against the template's own {{range .Fields}} loop, which
// iterates the ALREADY-MERGED order (mandatory-first). So a real round trip
// keeps form-index and Fields-index in agreement — the guard is that
// BlankLangRows must be computed against that SAME final order, not an
// earlier, different one.
func TestExtractBuilderDataBlankLangRowsMatchesThePostMergeField(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	// parseFieldSpecsFromForm stops at the first index with no
	// field_name_<i> key at all, so every row before the custom one needs a
	// placeholder — matching the mandatory fields by NAME, exactly what the
	// builder template re-posts for its own already-merged rows, so the
	// merge recognizes them as mandatory (isMandatoryName) and folds them
	// into the curated entries instead of appending 11 blank "custom" rows
	// ahead of the real one.
	mandatory := mdoc.MandatoryFields("org.iso.18013.5.1.mDL")
	for i, m := range mandatory {
		form.Set(fmt.Sprintf("field_name_%d", i), m.Name)
		form.Set(fmt.Sprintf("field_datatype_%d", i), "string")
	}
	mandatoryCount := len(mandatory)
	// One custom field, submitted at the row right after the mandatory
	// placeholders. After the mandatory-first merge it lands at
	// mandatoryCount — its form keys mirror that post-merge position,
	// exactly as a real re-render posts.
	customIdx := mandatoryCount
	form.Set(fmt.Sprintf("field_name_%d", customIdx), "custom_extra")
	form.Set(fmt.Sprintf("field_datatype_%d", customIdx), "string")
	form.Set(fmt.Sprintf("field_lang_%d_0", customIdx), "en")
	form.Set(fmt.Sprintf("field_label_%d_0", customIdx), "Custom Extra")
	// A second, deliberately BLANK language row on the SAME field —
	// language left unset, label left unset. blankLangRowsFromForm keeps
	// counting past the first (implicit) row as long as either key is
	// present in the form at all.
	form.Set(fmt.Sprintf("field_lang_%d_1", customIdx), "")
	form.Set(fmt.Sprintf("field_label_%d_1", customIdx), "x")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	gotIdx := -1
	for i, f := range data.Fields {
		if f.Name == "custom_extra" {
			gotIdx = i
			break
		}
	}
	if gotIdx != customIdx {
		t.Fatalf("custom_extra landed at index %d after the mandatory-first merge, want %d — adjust the test's form indices to match; got fields=%+v", gotIdx, customIdx, data.Fields)
	}
	if data.BlankLangRows[customIdx] == 0 {
		t.Errorf("BlankLangRows[%d] (custom_extra's field) = 0, want its blank language row recorded there; got BlankLangRows=%v", customIdx, data.BlankLangRows)
	}
	if n := len(data.BlankLangRows); n != 1 {
		t.Errorf("BlankLangRows has %d entries, want exactly 1 (only custom_extra submitted a blank row); got %v", n, data.BlankLangRows)
	}
}

// The docType must WIN over the free-text "Extra Type" box for mdoc.
// ExtraType is unvalidated operator input; the docType is a validated
// selection from mdoc.KnownDocTypes() that is pinned against the profile
// table. If free text could land in AdditionalTypes[0] for an mdoc schema it
// would sit exactly where BaseType() looks, reintroducing the unresolvable
// profile failure C1 fixed.
func TestCurrentBuilderSchemaDocTypeBeatsExtraType(t *testing.T) {
	sess := &Session{IssuerDpg: "walt.id"}
	d := builderData{
		Name:      "Licencia",
		Std:       "mso_mdoc",
		DocType:   "org.iso.18013.5.1.mDL",
		ExtraType: "WhateverTheOperatorTyped",
		Fields:    []vctypes.FieldSpec{{Name: "family_name", Datatype: "string"}},
	}
	got := currentBuilderSchema(sess, d)

	if got.AdditionalTypes[0] != "org.iso.18013.5.1.mDL" {
		t.Errorf("AdditionalTypes[0] = %q, want the docType to win over the free-text ExtraType", got.AdditionalTypes[0])
	}
}

// Non-mdoc schemas must be untouched by the C1 fix: ExtraType still governs
// AdditionalTypes there, and a stale DocType value must not leak in.
func TestCurrentBuilderSchemaNonMdocKeepsExtraType(t *testing.T) {
	sess := &Session{IssuerDpg: "walt.id"}
	d := builderData{
		Name:      "Diploma",
		Std:       "sd_jwt_vc (IETF)",
		ExtraType: "UniversityDegree",
		DocType:   "org.iso.18013.5.1.mDL", // stale value from an earlier format pick
		Fields:    []vctypes.FieldSpec{{Name: "given_name", Datatype: "string"}},
	}
	got := currentBuilderSchema(sess, d)

	if got.AdditionalTypes[0] != "UniversityDegree" {
		t.Errorf("AdditionalTypes[0] = %q, want ExtraType to still govern non-mdoc schemas", got.AdditionalTypes[0])
	}
}

// TestMandatoryLabelOverlayKeepsCuratedEnglish is the I1 guard.
//
// mdoc.MandatoryFields ships curated English labels ("UN Distinguishing
// Sign"). The merge in extractBuilderData used to do `m.Labels =
// submitted.Labels`, replacing the whole map. Because the template re-posts
// every row on each re-render, a submitted row essentially always exists, so
// the curated English died the moment the operator touched anything. The
// catalog then fell through to DeriveLabel, degrading it to
// "Un Distinguishing Sign" in the holder's wallet — and an operator who
// filled in only a Spanish label silently lost English, the base-language
// fallback for every other locale.
//
// The fix overlays per key, so operator values win per locale while
// untouched locales survive.
func TestMandatoryLabelOverlayKeepsCuratedEnglish(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	// The operator supplies ONLY a Spanish label for un_distinguishing_sign.
	// The English language row's label is deliberately left blank — this is
	// the exact shape the template posts back when the operator types into a
	// Spanish row and never touches the English one.
	//
	// Row index 0 matters: parseFieldSpecsFromForm scans rows contiguously and
	// breaks at the first absent field_name_N, so a row posted at a higher
	// index with no rows beneath it is never parsed at all.
	form.Set("field_name_0", "un_distinguishing_sign")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "")
	form.Set("field_lang_0_1", "es")
	form.Set("field_label_0_1", "Signo Distintivo de la ONU")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	var got *vctypes.FieldSpec
	for i := range data.Fields {
		if data.Fields[i].Name == "un_distinguishing_sign" {
			got = &data.Fields[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("un_distinguishing_sign missing from merged fields: %+v", data.Fields)
	}
	if got.Labels["en"] != "UN Distinguishing Sign" {
		t.Errorf("Labels[en] = %q, want the curated %q — the operator supplied only Spanish, "+
			"so the curated English must survive (it is the base-language fallback for every other locale)",
			got.Labels["en"], "UN Distinguishing Sign")
	}
	if got.Labels["es"] != "Signo Distintivo de la ONU" {
		t.Errorf("Labels[es] = %q, want the operator's Spanish label", got.Labels["es"])
	}
}

// The overlay must not become the opposite bug: where the operator DID supply
// an English label, theirs wins over the curated one.
func TestMandatoryLabelOverlayOperatorEnglishWins(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Surname")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	for _, f := range data.Fields {
		if f.Name == "family_name" {
			if f.Labels["en"] != "Surname" {
				t.Errorf("Labels[en] = %q, want the operator's %q — operator values win per locale", f.Labels["en"], "Surname")
			}
			return
		}
	}
	t.Fatal("family_name missing from merged fields")
}

// The label overlay writes into the map mdoc.MandatoryFields returns. If that
// were aliased to package state (I2), one request's labels would leak into
// every later request process-wide. This asserts the leak does not happen
// through the handler path specifically — internal/mdoc's
// TestMandatoryFieldsLabelsAreNotAliased pins the same property at the source.
func TestMandatoryLabelOverlayDoesNotLeakAcrossRequests(t *testing.T) {
	post := func(esLabel string) []vctypes.FieldSpec {
		form := url.Values{}
		form.Set("std", "mso_mdoc")
		form.Set("doctype", "org.iso.18013.5.1.mDL")
		form.Set("field_name_0", "family_name")
		form.Set("field_datatype_0", "string")
		if esLabel != "" {
			form.Set("field_lang_0_0", "es")
			form.Set("field_label_0_0", esLabel)
		}
		req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return extractBuilderData(req).Fields
	}

	// Operator A supplies a Spanish label.
	post("Apellido de A")

	// Operator B supplies none. They must not inherit A's Spanish label.
	for _, f := range post("") {
		if f.Name != "family_name" {
			continue
		}
		if leaked, ok := f.Labels["es"]; ok {
			t.Errorf("Labels[es] = %q leaked from a previous request — MandatoryFields is sharing package-level state", leaked)
		}
		if f.Labels["en"] != "Family Name" {
			t.Errorf("Labels[en] = %q, want the curated %q", f.Labels["en"], "Family Name")
		}
		return
	}
	t.Fatal("family_name missing from merged fields")
}
