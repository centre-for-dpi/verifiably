package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestExtractBuilderDataDropsResidualFieldFromPreviousDocType reproduces a
// real bug found live: an operator built an mDL schema (whose mandatory
// fields include driving_privileges), then switched the docType selector to
// Photo ID (org.iso.23220.photoid.1, which has no such element) and saved.
// The builder form re-submits every currently-rendered field row on each
// change/save — so driving_privileges' row was still present in the POST
// body even though nothing about Photo ID asked for it.
//
// Before the fix: extractBuilderData's merge only checked "is this field
// mandatory for the CURRENT docType" (isMandatoryName against Photo ID's
// set) — false for driving_privileges — so it fell through to the "keep as
// a custom operator field" branch and survived into the saved schema.
// Confirmed directly against Inji Certify's own credential_config table: a
// freshly created Photo ID config's display_order included
// "driving_privileges", and issuance then refused with "driving_privileges
// es obligatorio en ISO 18013-5" — a guard that should never fire for a
// docType the standard doesn't define that element for at all.
//
// Fix: mdoc.IsMandatoryForAnyDocType additionally drops a field that is
// mandatory for SOME OTHER known docType, distinguishing a residual row
// left over from a docType switch (drop it) from a field the operator
// genuinely typed into their own extra-field row (keep it — covered by
// TestExtractBuilderDataRestoresCraftedMandatoryField's neighbor file,
// which uses a field name mdoc.MandatoryFields has never heard of).
func TestExtractBuilderDataDropsResidualFieldFromPreviousDocType(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	// The operator has just switched TO Photo ID — this is the docType this
	// submission is really for.
	form.Set("doctype", "org.iso.23220.photoid.1")
	// driving_privileges: still present as field_name_11 (or whatever index)
	// because it was mDL's mandatory row a moment ago and the form re-posts
	// every row currently on screen — this is the residual row under test.
	form.Set("field_name_0", "driving_privileges")
	form.Set("field_datatype_0", "string:driving_privileges")
	form.Set("field_required_0", "on")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Driving Privileges")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	for _, f := range data.Fields {
		if f.Name == "driving_privileges" {
			t.Fatalf("driving_privileges present in merged Fields for docType=%s — a residual mDL field leaked into a Photo ID schema; got fields=%+v", data.DocType, data.Fields)
		}
	}
}

// TestExtractBuilderDataKeepsResidualFieldWhenSwitchingBackToItsOwnDocType
// is the inverse safety check: driving_privileges must still appear (as the
// real, mandatory, Required:true entry — sourced from mdoc.MandatoryFields,
// per TestExtractBuilderDataRestoresCraftedMandatoryField's own pin) when
// the docType actually IS mDL. The fix must not blanket-drop every mdoc
// mandatory name regardless of docType — only when it doesn't belong to the
// CURRENT one.
func TestExtractBuilderDataKeepsResidualFieldWhenSwitchingBackToItsOwnDocType(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	form.Set("field_name_0", "driving_privileges")
	form.Set("field_datatype_0", "string:driving_privileges")
	form.Set("field_required_0", "on")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	found := false
	for _, f := range data.Fields {
		if f.Name == "driving_privileges" {
			found = true
			if !f.Required {
				t.Errorf("driving_privileges.Required = false, want true for its own docType (mDL)")
			}
		}
	}
	if !found {
		t.Fatalf("driving_privileges missing from merged Fields for docType=mDL — the fix over-dropped a field that IS mandatory for the current docType; got fields=%+v", data.Fields)
	}
}
