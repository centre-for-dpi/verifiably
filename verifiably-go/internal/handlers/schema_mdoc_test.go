package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// TestExtractBuilderDataRestoresCraftedMandatoryField pins the mdoc
// preload-and-lock behaviour against a hostile form post: a crafted request
// (bypassing the template's readonly attribute — e.g. via curl or devtools)
// renames a mandatory mDL field's row and unchecks its Required box.
//
// What this actually pins (verified against the real merge logic in
// extractBuilderData, not assumed): the mandatory set is matched by NAME,
// not by row position, so a renamed row does not overwrite or suppress its
// canonical field — the canonical family_name/Required:true entry is always
// present, sourced fresh from mdoc.MandatoryFields regardless of what index
// 0 said. The side effect is that the tampered row survives too, as its own
// extra field, carrying whatever label was submitted alongside it; it does
// NOT inherit Required:true or displace the canonical entry. So a crafted
// rename cannot remove or weaken a mandatory ISO field, but it can leave a
// stray non-mandatory field behind — a data-hygiene wart, not a conformance
// break, and NOT something this test asks to be fixed (no new server-side
// enforcement was requested; this only pins what exists today).
func TestExtractBuilderDataRestoresCraftedMandatoryField(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	// field_name_0 is mandatory (family_name) but the crafted post renames
	// it and drops Required.
	form.Set("field_name_0", "renamed_by_attacker")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Family Name")
	// field_required_0 deliberately omitted (unchecked checkbox)

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/doctype", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	var got *vctypes.FieldSpec
	for i := range data.Fields {
		if data.Fields[i].Name == "family_name" {
			got = &data.Fields[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("family_name missing from merged fields — crafted rename removed the mandatory field entirely; got fields=%+v", data.Fields)
	}
	if !got.Required {
		t.Errorf("family_name.Required = false, want true — mandatory field must stay Required regardless of the submitted checkbox")
	}
	if got.Datatype != "string" {
		t.Errorf("family_name.Datatype = %q, want %q — the canonical entry must come from mdoc.MandatoryFields, not the submitted row", got.Datatype, "string")
	}
}
