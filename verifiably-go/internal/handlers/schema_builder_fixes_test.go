package handlers

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// ---------------------------------------------------------------------------
// Bug 1 — the mdoc docType selector did not appear when picking mso_mdoc.
// ---------------------------------------------------------------------------

// TestStdChangeToMdocYieldsDocTypeAndMandatoryFields is the regression guard
// for the reported symptom: "picking ISO mDL from the format list does not
// show the docType selector, so the format's mandatory fields never load".
//
// It asserts on the DATA the format-change handler produces AND on the markup
// a re-render of that data yields, because the bug lived in the seam between
// them — extractBuilderData was always capable of preloading the mandatory
// set, but nothing re-rendered the form, so the docType block (behind
// {{if eq .Std "mso_mdoc"}}) never appeared and the operator had no way to
// pick a docType in the first place.
//
// The post deliberately carries NO doctype value, which is exactly what the
// browser sends the instant the format changes: the docType <select> does not
// exist in the DOM yet, so there is nothing to submit.
func TestStdChangeToMdocYieldsDocTypeAndMandatoryFields(t *testing.T) {
	form := url.Values{}
	form.Set("name", "Licencia")
	form.Set("std", "mso_mdoc")
	// The two default blank rows a fresh builder renders.
	form.Set("field_name_0", "")
	form.Set("field_datatype_0", "string")
	form.Set("field_name_1", "")
	form.Set("field_datatype_1", "string")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/std", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	if data.DocType == "" {
		t.Fatalf("DocType is empty after switching to mso_mdoc — the docType <select> has no empty option, " +
			"so the browser would render its first entry as selected while the server believed nothing was " +
			"picked, and the mandatory fields would never preload")
	}
	// Whatever the default is, it must be a docType the selector actually
	// offers — otherwise the rendered <select> has no matching <option> and
	// silently displays something else.
	offered := false
	for _, dt := range data.KnownDocTypes {
		if dt.DocType == data.DocType {
			offered = true
			break
		}
	}
	if !offered {
		t.Errorf("DocType %q is not among KnownDocTypes %v — the selector would render no matching option",
			data.DocType, data.KnownDocTypes)
	}

	// The standard's mandatory elements must be present, Required, and locked.
	names := map[string]vctypes.FieldSpec{}
	for _, f := range data.Fields {
		names[f.Name] = f
	}
	for _, want := range []string{"family_name", "given_name", "birth_date", "document_number", "un_distinguishing_sign"} {
		f, ok := names[want]
		if !ok {
			t.Errorf("mandatory field %q missing after switching to mso_mdoc; got %v", want, fieldNames(data.Fields))
			continue
		}
		if !f.Required {
			t.Errorf("mandatory field %q is not Required", want)
		}
	}

	// Re-rendering that data must actually SHOW the docType selector. This is
	// the half the bug broke: the data was fine, the form was never redrawn.
	out := renderBuilderForm(t, data)
	if !strings.Contains(out, `name="doctype"`) {
		t.Errorf("re-rendered builder form has no docType selector:\n%s", out)
	}
	if !strings.Contains(out, `value="`+data.DocType+`"`) {
		t.Errorf("re-rendered form has no option for the selected docType %q", data.DocType)
	}
	if !strings.Contains(out, `value="un_distinguishing_sign"`) {
		t.Errorf("re-rendered form does not show the preloaded mandatory fields")
	}
}

// The format <select> must carry the htmx attributes that make the above
// re-render happen at all. Without them only the FORM's own hx-trigger fires,
// which targets #json-preview — the JSON panel, not the form — which is
// precisely why the docType selector stayed invisible.
func TestStdSelectRerendersTheForm(t *testing.T) {
	tmpl := loadSchemaBuilderTemplate(t)
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "fragment_schema_builder_form", builderData{Std: "w3c_vcdm_2"}); err != nil {
		t.Fatalf("render builder form: %v", err)
	}
	out := buf.String()
	sel := out[strings.Index(out, `<select name="std"`):]
	sel = sel[:strings.Index(sel, "</select>")]
	for _, want := range []string{
		`hx-post="/issuer/schema/build/std"`,
		`hx-include="#builder-form-el"`,
		`hx-target="#builder-form"`,
		`hx-swap="innerHTML"`,
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("the std <select> is missing %s — changing the format would only swap the JSON "+
				"preview, leaving the docType selector hidden:\n%s", want, sel)
		}
	}
}

// Switching format must not silently discard fields the operator already
// typed. Toward mso_mdoc the mandatory set is preloaded, but the operator's
// own rows are kept alongside it.
func TestStdChangeToMdocKeepsOperatorFields(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("field_name_0", "student_number")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Student Number")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/std", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	for _, f := range data.Fields {
		if f.Name == "student_number" {
			if f.Labels["en"] != "Student Number" {
				t.Errorf("the operator's label was dropped: Labels=%v", f.Labels)
			}
			return
		}
	}
	t.Errorf("the operator's own field was discarded by the format switch; got %v", fieldNames(data.Fields))
}

// Switching AWAY from mso_mdoc leaves the fields exactly as submitted. The
// previously-preloaded ISO rows become ordinary editable fields rather than
// vanishing — silently deleting eleven rows an operator may have since edited
// would lose work.
func TestStdChangeAwayFromMdocKeepsFields(t *testing.T) {
	form := url.Values{}
	form.Set("std", "w3c_vcdm_2")
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_name_1", "student_number")
	form.Set("field_datatype_1", "string")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/std", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)
	got := fieldNames(data.Fields)
	if len(got) != 2 || got[0] != "family_name" || got[1] != "student_number" {
		t.Errorf("fields = %v, want both kept verbatim when leaving mso_mdoc", got)
	}
	if data.DocType != "" {
		t.Errorf("DocType = %q, want empty for a non-mdoc format", data.DocType)
	}
}

// ---------------------------------------------------------------------------
// Bug 2 — boolean fields never submitted, so issuance failed on a required one.
// ---------------------------------------------------------------------------

// TestBooleanFieldSubmitsRealValueInBothStates is the core guard on the
// reported symptom: issuance failed with "Fill in required fields:
// age_over_18" even when the operator ticked the box.
//
// Both states must produce a real value. Empty is the bug (an unticked
// checkbox submits nothing at all), and "on" is the other half of it (a
// checkbox with no explicit value submits the literal string "on", which is
// neither the CBOR boolean ISO 18013-5 wants nor the "true"/"false" literal
// walt.id's profile mapping keys off).
func TestBooleanFieldSubmitsRealValueInBothStates(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "unticked submits false, not empty",
			// An unticked checkbox sends nothing; only the hidden input arrives.
			form: url.Values{"field_age_over_18": {"false"}},
			want: "false",
		},
		{
			name: "ticked submits true, not on",
			form: url.Values{
				"field_age_over_18":          {"false"},
				"field_age_over_18__checked": {"true"},
			},
			want: "true",
		},
		{
			name: "nothing submitted at all is still a boolean literal",
			form: url.Values{},
			want: "false",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/issuer/issue", strings.NewReader(c.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			got := boolFieldValue(req, "age_over_18")
			if got != c.want {
				t.Errorf("boolFieldValue = %q, want %q", got, c.want)
			}
			if got == "" || got == "on" {
				t.Errorf("boolFieldValue = %q — must never be empty or the raw checkbox %q", got, "on")
			}
		})
	}
}

// A REQUIRED boolean must pass validation in BOTH states. An unticked
// required boolean is a legitimate answer, not a missing field:
// age_over_18=false is meaningful data about the holder. Treating "false" as
// unfilled makes a required boolean unsatisfiable in one of its two valid
// states — which is exactly the live failure the operator hit.
//
// It drives the WHOLE path — the browser's form bytes through the same
// value-gathering and validation SubmitIssue performs — rather than handing
// missingRequiredFields a pre-baked "false". A pre-baked value would pass
// even against the broken code, because "false" is a non-empty string; the
// live bug was that the gathering step produced "" in the first place. Only
// running both steps together catches that.
func TestRequiredBooleanPassesValidationInBothStates(t *testing.T) {
	schema := vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{
		{Name: "age_over_18", Datatype: "boolean", Required: true},
		{Name: "family_name", Datatype: "string", Required: true},
	}}

	for _, tc := range []struct {
		name string
		form url.Values
	}{
		// The wire shape the FIXED form produces, taken from the rendered
		// markup rather than hand-written — see formValuesForRenderedBool. An
		// unticked box contributes only the hidden partner; a ticked one adds
		// the __checked input. Deriving it from the template means this test
		// fails if either half of the fix is missing, instead of quietly
		// asserting against a shape the server never actually receives.
		{"unticked", formValuesForRenderedBool(t, "age_over_18", false)},
		{"ticked", formValuesForRenderedBool(t, "age_over_18", true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/issuer/issue", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			subject := gatherSubjectForTest(req, schema)
			if missing := missingRequiredFields(schema, subject, nil); len(missing) > 0 {
				t.Errorf("required boolean rejected as missing in the %s state: %v (subject=%v)",
					tc.name, missing, subject)
			}
		})
	}

	// The exemption must not disable validation for everything else: a blank
	// required STRING is still a missing field.
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue",
		strings.NewReader(url.Values{"field_age_over_18": {"false"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missing := missingRequiredFields(schema, gatherSubjectForTest(req, schema), nil)
	if len(missing) != 1 || missing[0] != "family_name" {
		t.Errorf("missing = %v, want exactly [family_name] — the boolean exemption must not weaken other fields", missing)
	}
}

// formValuesForRenderedBool renders the real issue form for a single boolean
// field and returns what a BROWSER would submit for it, in the given tick
// state — plus a value for the companion required string so the only variable
// under test is the boolean.
//
// It reads the values out of the rendered markup instead of hard-coding them,
// which is what makes the fail-before-fix check honest: against the broken
// template there is no hidden partner and no __checked input, so an unticked
// box contributes NOTHING and the field reaches the server as "" — the exact
// live failure. A hand-written form carrying "false" would paper over that.
//
// Browser rules applied: every non-checkbox input submits its value; a
// checkbox submits its value only when checked.
func formValuesForRenderedBool(t *testing.T, field string, ticked bool) url.Values {
	t.Helper()
	stored := map[string]string{"family_name": "Pérez"}
	if ticked {
		stored[field] = "true"
	}
	html := renderIssueSingleForm(t, vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{
		{Name: field, Datatype: "boolean", Required: true},
		{Name: "family_name", Datatype: "string", Required: true},
	}}, stored)

	out := url.Values{}
	for _, tag := range strings.Split(html, "<input")[1:] {
		tag = tag[:strings.Index(tag, ">")]
		name := attrValue(tag, "name")
		if name == "" || !strings.HasPrefix(name, "field_") {
			continue
		}
		isCheckbox := strings.Contains(tag, `type="checkbox"`)
		// A checkbox that isn't checked submits nothing at all — the whole
		// root of the bug.
		if isCheckbox && !strings.Contains(tag, "\n                checked\n") {
			continue
		}
		out.Set(name, attrValue(tag, "value"))
	}
	return out
}

// attrValue pulls a double-quoted attribute's value out of a rendered tag.
// Deliberately tiny: the inputs here are this repo's own templates, not
// arbitrary HTML, so a full parser would obscure more than it protects.
func attrValue(tag, attr string) string {
	i := strings.Index(tag, attr+`="`)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(attr)+2:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// gatherSubjectForTest mirrors SubmitIssue's subject-gathering step: booleans
// via boolFieldValue, everything else via the trimmed form value. Kept here
// (rather than calling SubmitIssue) so the test needs no session, adapter or
// backend — but deliberately routed through the same boolFieldValue the
// handler uses, so the boolean half is the real thing rather than a copy.
func gatherSubjectForTest(r *http.Request, schema vctypes.Schema) map[string]string {
	subject := map[string]string{}
	for _, fs := range schema.FieldsSpec {
		if isBooleanField(fs) {
			subject[fs.Name] = boolFieldValue(r, fs.Name)
			continue
		}
		subject[fs.Name] = strings.TrimSpace(r.FormValue("field_" + fs.Name))
	}
	return subject
}

// An existing value must round-trip: re-rendering the issue form with
// FieldValues["age_over_18"] == "true" shows the box ticked, and anything
// else leaves it unticked. This is the requirement easiest to miss, because
// the form renders fine either way — it just quietly loses the operator's
// answer when they come back to it.
func TestBooleanFieldRoundTripsExistingValue(t *testing.T) {
	schema := vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{
		{Name: "age_over_18", Datatype: "boolean", Required: true},
	}}
	for _, tc := range []struct {
		name       string
		vals       map[string]string
		wantTicked bool
	}{
		{"stored true ticks the box", map[string]string{"age_over_18": "true"}, true},
		{"stored false leaves it unticked", map[string]string{"age_over_18": "false"}, false},
		{"fresh form leaves it unticked", map[string]string{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderIssueSingleForm(t, schema, tc.vals)
			// The hidden "false" partner must always be there — it is what
			// makes the unticked state submit anything at all.
			if !strings.Contains(out, `<input type="hidden" name="field_age_over_18" value="false">`) {
				t.Errorf("missing the hidden false input:\n%s", out)
			}
			if !strings.Contains(out, `name="field_age_over_18__checked"`) ||
				!strings.Contains(out, `value="true"`) {
				t.Errorf("missing the checkbox carrying \"true\":\n%s", out)
			}
			// `checked` as its own attribute — not the substring inside the
			// input's own __checked NAME, which is present either way.
			ticked := strings.Contains(out, "\n                checked\n")
			if ticked != tc.wantTicked {
				t.Errorf("ticked = %v, want %v\n%s", ticked, tc.wantTicked, out)
			}
		})
	}
}

// The boolean rendering must not have leaked into every other field: a plain
// string field keeps its single text input and gains no hidden partner.
func TestNonBooleanFieldsUnaffected(t *testing.T) {
	schema := vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{
		{Name: "family_name", Datatype: "string", Required: true},
	}}
	out := renderIssueSingleForm(t, schema, map[string]string{"family_name": "Pérez"})
	if strings.Contains(out, "__checked") {
		t.Errorf("a string field grew a checkbox partner:\n%s", out)
	}
	if !strings.Contains(out, `name="field_family_name"`) || !strings.Contains(out, `value="Pérez"`) {
		t.Errorf("string field lost its plain text input:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Bug 3 — per-field labels with an explicit language.
// ---------------------------------------------------------------------------

// A field with three languages must round-trip through parseFieldSpecsFromForm
// with all three intact — the whole point of the redesign is that N languages
// per field are expressible at all.
func TestThreeLanguagesRoundTrip(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Family Name")
	form.Set("field_lang_0_1", "es-DO")
	form.Set("field_label_0_1", "Apellidos")
	form.Set("field_lang_0_2", "ht")
	form.Set("field_label_0_2", "Siyati")

	fields := parseFieldSpecsFromForm(form)
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(fields))
	}
	want := map[string]string{"en": "Family Name", "es-DO": "Apellidos", "ht": "Siyati"}
	if len(fields[0].Labels) != len(want) {
		t.Fatalf("Labels = %v, want all three languages", fields[0].Labels)
	}
	for loc, label := range want {
		if got := fields[0].Labels[loc]; got != label {
			t.Errorf("Labels[%q] = %q, want %q", loc, got, label)
		}
	}

	// And back out again: re-rendering must reproduce all three rows, so the
	// operator sees what they saved rather than losing a language per trip.
	out := renderFieldRow(t, fields[0], 0, false, nil)
	for _, want := range []string{
		`value="en"`, `value="Family Name"`,
		`value="es-DO"`, `value="Apellidos"`,
		`value="ht"`, `value="Siyati"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("re-rendered row lost %s:\n%s", want, out)
		}
	}
}

// A curated ISO label must survive preload and appear with "en" as its
// language — pre-filled and editable, not derived and not lost.
// The form posts the field row BACK, which is what the template does on every
// re-render — and is the case where the curated label is actually at risk. The
// operator has typed a Spanish label and never touched the English one, so the
// English half arrives blank; the curated value must survive that rather than
// being replaced by the submitted (empty) map. A form carrying no rows at all
// would only exercise the trivial first-paint path.
func TestCuratedISOLabelSurvivesPreloadWithEnglishLanguage(t *testing.T) {
	form := url.Values{}
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	form.Set("field_name_0", "un_distinguishing_sign")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "") // untouched by the operator
	form.Set("field_lang_0_1", "es")
	form.Set("field_label_0_1", "Signo Distintivo de la ONU")

	req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/std", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data := extractBuilderData(req)

	var uds *vctypes.FieldSpec
	for i := range data.Fields {
		if data.Fields[i].Name == "un_distinguishing_sign" {
			uds = &data.Fields[i]
			break
		}
	}
	if uds == nil {
		t.Fatalf("un_distinguishing_sign missing from the preloaded set: %v", fieldNames(data.Fields))
	}
	if uds.Labels["en"] != "UN Distinguishing Sign" {
		t.Errorf("Labels[en] = %q, want the curated %q — DeriveLabel would degrade this to "+
			"%q in the holder's wallet", uds.Labels["en"], "UN Distinguishing Sign", "Un Distinguishing Sign")
	}

	// It must reach the FORM as a pre-filled first language row whose language
	// reads "en" — and the label input must be editable, not readonly. Only
	// the identifier is locked for a mandatory field.
	out := renderFieldRow(t, *uds, 0, true, nil)
	rows := FieldLangRows(*uds)
	if len(rows) == 0 || rows[0].Lang != "en" || rows[0].Label != "UN Distinguishing Sign" {
		t.Fatalf("first language row = %+v, want {en, UN Distinguishing Sign}", rows)
	}
	if !strings.Contains(out, `value="UN Distinguishing Sign"`) {
		t.Errorf("curated label not pre-filled into the form:\n%s", out)
	}
	labelInput := out[strings.Index(out, `name="field_label_0_0"`):]
	labelInput = labelInput[:strings.Index(labelInput, ">")]
	if strings.Contains(labelInput, "readonly") {
		t.Errorf("the curated label must stay EDITABLE; only the identifier is locked:\n%s", labelInput)
	}
}

// The first language row is freely editable, not locked to English: a
// deployment issuing only in Spanish sets it to "es" and carries no English
// at all. Asserted end-to-end — through the parser, the row ordering, and the
// catalog metadata — because "English is not special" has to hold at every
// layer or it silently reappears at one of them.
func TestSpanishOnlyDeploymentCarriesNoEnglish(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "es")
	form.Set("field_label_0_0", "Apellidos")

	fields := parseFieldSpecsFromForm(form)
	if got := fields[0].Labels["es"]; got != "Apellidos" {
		t.Errorf("Labels[es] = %q, want Apellidos", got)
	}
	if _, exists := fields[0].Labels["en"]; exists {
		t.Errorf("an English entry was synthesised for a Spanish-only field: %v", fields[0].Labels)
	}
	rows := FieldLangRows(fields[0])
	if len(rows) != 1 || rows[0].Lang != "es" {
		t.Errorf("language rows = %+v, want exactly one Spanish row", rows)
	}
}

// A blank label leaves NO map entry — absent means "derive from the
// identifier" downstream, and an empty-string entry would be a different,
// worse thing: a present key whose value renders as nothing.
func TestBlankLabelProducesNoMapEntry(t *testing.T) {
	form := url.Values{}
	form.Set("field_name_0", "document_number")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "") // language row present, label left blank

	fields := parseFieldSpecsFromForm(form)
	if len(fields[0].Labels) != 0 {
		t.Errorf("Labels = %v, want no entry at all for a blank label", fields[0].Labels)
	}
	if fields[0].Labels != nil {
		t.Errorf("Labels = %#v, want nil — vctypes.FieldSpec.Label keys off absence", fields[0].Labels)
	}
	// Absence must actually reach the derive path.
	if got := fields[0].Label("en"); got != "Document Number" {
		t.Errorf("Label(en) = %q, want the derived %q", got, "Document Number")
	}
}

// An invalid locale code is still rejected, and still reported. The
// index-based naming scheme means a bad code can no longer corrupt an HTML
// attribute name, but it is still not a usable locale and the operator still
// needs to be told why their label vanished.
func TestInvalidLocaleCodeStillRejectedAndReported(t *testing.T) {
	for _, bad := range []string{"es DO", "es\nDO", "es/DO", "es\"DO", strings.Repeat("x", 36), "es<b>"} {
		t.Run(bad, func(t *testing.T) {
			form := url.Values{}
			form.Set("field_name_0", "family_name")
			form.Set("field_datatype_0", "string")
			form.Set("field_lang_0_0", bad)
			form.Set("field_label_0_0", "Apellidos")

			fields := parseFieldSpecsFromForm(form)
			if len(fields[0].Labels) != 0 {
				t.Errorf("invalid locale %q was accepted: %v", bad, fields[0].Labels)
			}
			if got := firstInvalidLocaleCode(form); got != bad {
				t.Errorf("firstInvalidLocaleCode = %q, want %q — the operator gets no error toast "+
					"explaining why their label disappeared", got, bad)
			}
		})
	}

	// A valid code with hyphens and digits must still be accepted — the
	// vocabulary stays OPEN, and this rejects characters, not languages.
	for _, good := range []string{"en", "es-DO", "ht", "qu", "zh-Hans-CN", "x-custom-1"} {
		form := url.Values{}
		form.Set("field_name_0", "family_name")
		form.Set("field_lang_0_0", good)
		form.Set("field_label_0_0", "Apellidos")
		if fields := parseFieldSpecsFromForm(form); fields[0].Labels[good] != "Apellidos" {
			t.Errorf("valid locale %q was rejected: %v", good, fields[0].Labels)
		}
		if got := firstInvalidLocaleCode(form); got != "" {
			t.Errorf("valid locale %q reported as invalid (%q)", good, got)
		}
	}
}

// "Add language" must survive the re-render. A newly-added row is empty, an
// empty row makes no map entry by design, and the builder re-renders from the
// map on every keystroke — so without BlankLangRows the builder would eat its
// own click and the row would vanish before the operator could type in it.
func TestAddLanguageRowSurvivesRerender(t *testing.T) {
	f := vctypes.FieldSpec{Name: "family_name", Datatype: "string",
		Labels: map[string]string{"en": "Family Name"}}

	out := renderFieldRow(t, f, 0, false, 1)
	// The filled English row is index 0, so the pending blank row must be
	// index 1 — NOT 0, which would collide with and overwrite the English one.
	if !strings.Contains(out, `name="field_lang_0_1"`) || !strings.Contains(out, `name="field_label_0_1"`) {
		t.Errorf("the added language row is missing from the re-render:\n%s", out)
	}
	if !strings.Contains(out, `/issuer/schema/build/add-language`) {
		t.Errorf("the + Add language button is missing:\n%s", out)
	}

	// And the count must be derivable from what the form posts back, or the
	// row disappears on the NEXT keystroke instead of this one.
	form := url.Values{}
	form.Set("field_name_0", "family_name")
	form.Set("field_datatype_0", "string")
	form.Set("field_lang_0_0", "en")
	form.Set("field_label_0_0", "Family Name")
	form.Set("field_lang_0_1", "") // the pending row, still empty
	form.Set("field_label_0_1", "")

	fields := parseFieldSpecsFromForm(form)
	if got := blankLangRowsFromForm(form, fields)[0]; got != 1 {
		t.Errorf("blank language rows = %d, want 1 — the pending row is dropped on the next re-render", got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func fieldNames(fs []vctypes.FieldSpec) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

// renderBuilderForm renders the whole builder form fragment from builderData.
func renderBuilderForm(t *testing.T, d builderData) string {
	t.Helper()
	tmpl := loadSchemaBuilderTemplate(t)
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "fragment_schema_builder_form", d); err != nil {
		t.Fatalf("render builder form: %v", err)
	}
	return buf.String()
}

// renderIssueSingleForm renders the manual single-subject issue form for a
// schema, with the given already-known field values. Parses the real
// templates/pages/issuer_issue.html rather than a fixture, so the assertions
// are against the markup the server actually serves.
func renderIssueSingleForm(t *testing.T, schema vctypes.Schema, vals map[string]string) string {
	t.Helper()
	tmpl := template.New("").Funcs(template.FuncMap{
		"t":                 func(s string, _ ...any) string { return s },
		"replaceUnderscore": func(s string) string { return strings.ReplaceAll(s, "_", " ") },
		"dict":              func(pairs ...any) map[string]any { return nil },
		"jsonRows":          func(v any) template.JS { return template.JS("[]") },
	})
	if _, err := tmpl.ParseFiles("../../templates/pages/issuer_issue.html"); err != nil {
		t.Fatalf("parse issuer_issue.html: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "fragment_issue_single_form", map[string]any{
		"Schema":       schema,
		"SingleSource": "manual",
		"IssuerDpg":    "walt.id",
		"FieldValues":  vals,
	}); err != nil {
		t.Fatalf("render issue form: %v", err)
	}
	return buf.String()
}

// renderFieldRow renders one _field_row. blank is `any` so a test can pass
// nil — the same untyped nil the production template produces via
// `index $blank $i` on a field with no pending language rows.
func renderFieldRow(t *testing.T, f vctypes.FieldSpec, idx int, locked bool, blank any) string {
	t.Helper()
	tmpl := loadSchemaBuilderTemplate(t)
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "_field_row", map[string]any{
		"Idx": idx, "Field": f, "Locked": locked, "Blank": blank,
	}); err != nil {
		t.Fatalf("render _field_row: %v", err)
	}
	return buf.String()
}
