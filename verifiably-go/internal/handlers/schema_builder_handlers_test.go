package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// builderH is an H wired with just what the schema-builder fragment handlers
// touch: a session store and the real issuer_schema_builder.html templates.
func builderH(t *testing.T) *H {
	t.Helper()
	return &H{Sessions: NewStore(), Templates: loadSchemaBuilderTemplate(t)}
}

// postBuilder drives a builder handler the way htmx does: a urlencoded POST
// carrying the whole form.
func postBuilder(t *testing.T, handler http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func twoFieldForm() url.Values {
	return url.Values{
		"name":             {"Test Credential"},
		"std":              {"w3c_vcdm_2"},
		"field_name_0":     {"alpha"},
		"field_datatype_0": {"string"},
		"field_name_1":     {"beta"},
		"field_datatype_1": {"string"},
	}
}

func TestBuildStdChangeToMdocRevealsDocTypeAndMandatoryFields(t *testing.T) {
	h := builderH(t)
	rr := postBuilder(t, h.BuildStdChange, url.Values{
		"name":    {"Licence"},
		"std":     {"mso_mdoc"},
		"doctype": {"org.iso.18013.5.1.mDL"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="doctype"`) {
		t.Error("switching the format to mso_mdoc must reveal the docType selector")
	}
	if !strings.Contains(body, `value="family_name"`) {
		t.Error("switching to mso_mdoc must preload the standard's mandatory fields")
	}
	if !strings.Contains(body, "readonly") {
		t.Error("the ISO-mandated field names must render read-only (locked)")
	}
}

func TestBuildDocTypeChangeReloadsTheFieldRows(t *testing.T) {
	h := builderH(t)
	rr := postBuilder(t, h.BuildDocTypeChange, url.Values{
		"std":     {"mso_mdoc"},
		"doctype": {"org.iso.18013.5.1.mDL"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `value="family_name"`) {
		t.Error("changing the docType must re-render the mandatory field rows, not only the JSON preview")
	}
}

func TestBuildDelegationToggleAppliesThePresetOnlyWhenOn(t *testing.T) {
	h := builderH(t)

	on := twoFieldForm()
	on.Set("delegation", "on")
	rrOn := postBuilder(t, h.BuildDelegationToggle, on)
	if rrOn.Code != http.StatusOK {
		t.Fatalf("on: status = %d, body=%s", rrOn.Code, rrOn.Body.String())
	}

	rrOff := postBuilder(t, h.BuildDelegationToggle, twoFieldForm())
	if rrOff.Code != http.StatusOK {
		t.Fatalf("off: status = %d, body=%s", rrOff.Code, rrOff.Body.String())
	}
	if rrOn.Body.String() == rrOff.Body.String() {
		t.Error("turning delegation on must change the rendered form (preset applied)")
	}
}

func TestSchemaPreviewReturnsFragmentAndRejectsMalformedForm(t *testing.T) {
	h := builderH(t)
	rr := postBuilder(t, h.SchemaPreview, twoFieldForm())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "alpha") {
		t.Errorf("the preview must reflect the submitted fields, got: %s", rr.Body.String())
	}

	// A body that cannot be parsed as a form must be a 400, not a 500 or a
	// half-rendered preview.
	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/preview", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad := httptest.NewRecorder()
	h.SchemaPreview(bad, req)
	if bad.Code != http.StatusBadRequest {
		t.Errorf("malformed form: status = %d, want 400", bad.Code)
	}
}

func TestAddSchemaFieldAppendsABlankRow(t *testing.T) {
	h := builderH(t)
	rr := postBuilder(t, h.AddSchemaField, twoFieldForm())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `name="field_name_2"`) {
		t.Error("AddSchemaField must render a third row (field_name_2) after the two submitted")
	}
}

func TestRemoveSchemaFieldDropsOnlyTheRequestedRow(t *testing.T) {
	h := builderH(t)
	form := twoFieldForm()
	form.Set("idx", "0")
	rr := postBuilder(t, h.RemoveSchemaField, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, `value="alpha"`) {
		t.Error("the removed row (alpha) is still rendered")
	}
	if !strings.Contains(body, `value="beta"`) {
		t.Error("the untouched row (beta) must survive the removal")
	}

	// An out-of-range index must be a no-op, never a panic.
	form.Set("idx", "99")
	rr = postBuilder(t, h.RemoveSchemaField, form)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `value="alpha"`) {
		t.Errorf("out-of-range idx must leave the fields untouched (status %d)", rr.Code)
	}
}

func TestAddFieldLanguageAddsABlankRowToOneFieldOnly(t *testing.T) {
	h := builderH(t)
	// Every field already renders one default "en" row (index 0), so the row
	// AddFieldLanguage appends is index 1.
	form := twoFieldForm()
	form.Set("idx", "1")
	rr := postBuilder(t, h.AddFieldLanguage, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="field_lang_1_1"`) {
		t.Error("field 1 must gain a second (blank) language row")
	}
	if strings.Contains(body, `name="field_lang_0_1"`) {
		t.Error("field 0 must NOT gain a language row")
	}

	// A non-numeric or out-of-range idx must be ignored.
	for _, bad := range []string{"abc", "-1", "99"} {
		form.Set("idx", bad)
		rr = postBuilder(t, h.AddFieldLanguage, form)
		if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), `name="field_lang_1_1"`) {
			t.Errorf("idx=%q must be ignored (status %d)", bad, rr.Code)
		}
	}
}
