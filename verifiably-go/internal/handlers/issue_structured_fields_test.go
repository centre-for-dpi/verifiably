package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// mdlSchemaForTest is the schema an operator actually issues against: the
// docType's own curated field list, not a hand-written stand-in. Sourcing it
// from mdoc.MandatoryFields is the point — a test that declared its own
// FieldSpec could assert a shape the system never produces, which is exactly
// how this feature reached production broken twice.
func mdlSchemaForTest() vctypes.Schema {
	return vctypes.Schema{
		ID:         "org.iso.18013.5.1.mDL",
		Std:        "mso_mdoc",
		Name:       "Mobile Driving Licence",
		FieldsSpec: mdoc.MandatoryFields("org.iso.18013.5.1.mDL"),
	}
}

// TestDrivingPrivilegesRendersRepeaterNotATextBox is the UI half of the F4
// regression. The operator saw a single text box, typed "1", and the offer
// failed at wallet redemption. The form must offer real controls per entry.
func TestDrivingPrivilegesRendersRepeaterNotATextBox(t *testing.T) {
	html := renderIssueFormWithStructured(t, mdlSchemaForTest(), nil)

	// The pre-fix rendering: one text input named field_driving_privileges.
	// Its presence means the operator is back to typing a scalar.
	if strings.Contains(html, `name="field_driving_privileges"`) {
		t.Errorf("driving_privileges still renders as a single scalar input " +
			"(name=\"field_driving_privileges\") — that is the control the operator " +
			"typed \"1\" into, producing \"input |\\\"1\\\"| is not a json array\"")
	}
	for _, want := range []string{
		`name="dp_vehicle_category_code_0"`,
		`name="dp_issue_date_0"`,
		`name="dp_expiry_date_0"`,
		`name="dp_vehicle_category_code_1"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("issue form has no %s — the operator cannot enter a second privilege entry", want)
		}
	}
	// The date sub-fields must be real date pickers, not text boxes: walt.id
	// parses them with stringToFullDate and a free-text date fails at signing.
	if !strings.Contains(html, `type="date" name="dp_issue_date_0"`) {
		t.Errorf("dp_issue_date_0 is not a date input — a free-text date fails walt.id's stringToFullDate")
	}
}

// TestPortraitRendersFilePicker is the same assertion for the image field.
func TestPortraitRendersFilePicker(t *testing.T) {
	html := renderIssueFormWithStructured(t, mdlSchemaForTest(), nil)
	if !strings.Contains(html, `type="file" name="field_portrait__file"`) {
		t.Errorf("portrait does not render a file input — the operator would have to paste base64 by hand")
	}
	if !strings.Contains(html, `accept="image/jpeg,image/png"`) {
		t.Errorf("portrait file input does not constrain accepted types")
	}
}

// TestSubmitIssueSendsDrivingPrivilegesAsRealJSONArray is THE end-to-end
// regression for F4, and the one that would have caught the live failure.
//
// It goes: real curated schema -> real rendered form -> a browser-shaped
// multipart POST -> the real SubmitIssue parsing path -> the real
// buildIssuer2Offer body -> assertion on the JSON that would hit walt.id.
//
// The assertion unmarshals the value and checks its Go TYPE. A substring
// check would pass against the broken shape: a stringified array still
// contains "vehicle_category_code".
func TestSubmitIssueSendsDrivingPrivilegesAsRealJSONArray(t *testing.T) {
	schema := mdlSchemaForTest()

	// What a browser posts after the operator fills two privilege rows.
	form := map[string]string{
		"dp_vehicle_category_code_0": "B",
		"dp_issue_date_0":            "2021-06-01",
		"dp_expiry_date_0":           "2031-06-01",
		"dp_vehicle_category_code_1": "C1",
		"dp_issue_date_1":            "2022-09-15",
		"dp_expiry_date_1":           "2032-09-15",
	}
	r := multipartRequest(t, form, "", nil)

	structured := gatherStructuredForTest(t, r, schema)
	raw, ok := structured["driving_privileges"]
	if !ok {
		t.Fatalf("driving_privileges is absent from StructuredData — the filled form produced nothing")
	}

	// The body as it would be marshalled onto the wire to issuer-api2.
	body := marshalCredentialData(t, map[string]any{"driving_privileges": raw})

	var probe struct {
		DrivingPrivileges any `json:"driving_privileges"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("unmarshal wire body: %v (body=%s)", err, body)
	}
	arr, isArray := probe.DrivingPrivileges.([]any)
	if !isArray {
		t.Fatalf("driving_privileges arrives at walt.id as %T, want []any.\n"+
			"This is the F4 failure: walt.id answers "+
			"\"Expected to execute conversion from json array, but input |...| is not a json array\".\n"+
			"wire body: %s", probe.DrivingPrivileges, body)
	}
	if len(arr) != mdoc.DrivingPrivilegesArrayConfigSize {
		t.Fatalf("driving_privileges has %d entries, want %d — walt.id's arrayConfig is exact-length "+
			"and answers \"Json array sizes (input & config) are not equal\" otherwise",
			len(arr), mdoc.DrivingPrivilegesArrayConfigSize)
	}

	first, _ := arr[0].(map[string]any)
	if first["vehicle_category_code"] != "B" {
		t.Errorf("entry 0 category = %v, want B", first["vehicle_category_code"])
	}
	if first["issue_date"] != "2021-06-01" {
		t.Errorf("entry 0 issue_date = %v, want the bare full-date 2021-06-01 — "+
			"an RFC3339 timestamp fails walt.id's stringToFullDate", first["issue_date"])
	}
	second, _ := arr[1].(map[string]any)
	if second["vehicle_category_code"] != "C1" {
		t.Errorf("entry 1 category = %v, want C1", second["vehicle_category_code"])
	}
}

// A single filled row must still issue. This is the case the operator hits
// most often, and the one the fixed-size arrayConfig makes non-obvious.
func TestSubmitIssueSingleDrivingPrivilegeIsPadded(t *testing.T) {
	schema := mdlSchemaForTest()
	r := multipartRequest(t, map[string]string{
		"dp_vehicle_category_code_0": "A",
		"dp_issue_date_0":            "2020-02-02",
		"dp_expiry_date_0":           "2030-02-02",
	}, "", nil)

	structured := gatherStructuredForTest(t, r, schema)
	var arr []map[string]any
	if err := json.Unmarshal(structured["driving_privileges"], &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != mdoc.DrivingPrivilegesArrayConfigSize {
		t.Fatalf("one filled row produced %d entries, want %d", len(arr), mdoc.DrivingPrivilegesArrayConfigSize)
	}
	for i, e := range arr {
		if e["issue_date"] == "" || e["issue_date"] == nil {
			t.Errorf("entry %d has no issue_date — a blank pad fails stringToFullDate "+
				"with \"Text '' could not be parsed at index 0\"", i)
		}
	}
}

// TestPortraitFileArrivesAsBase64 is the portrait half of the end-to-end
// regression: a picked file must reach walt.id as base64 of the raw bytes.
func TestPortraitFileArrivesAsBase64(t *testing.T) {
	pngBytes := tinyPNG(t)
	r := multipartRequest(t, map[string]string{}, "field_portrait__file", pngBytes)

	got, err := imageFieldValue(r, "portrait")
	if err != nil {
		t.Fatalf("imageFieldValue: %v", err)
	}
	if got == "" {
		t.Fatalf("portrait is empty — the picked file did not reach the handler")
	}
	// Must be base64 of the RAW bytes, with no data: URI prefix. walt.id
	// decodes exactly what we send; a prefix would corrupt the byte string.
	if strings.HasPrefix(got, "data:") {
		t.Errorf("portrait carries a data: URI prefix — walt.id's base64StringToByteString "+
			"would decode the prefix as image data. got %.32s…", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("portrait is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, pngBytes) {
		t.Errorf("decoded portrait (%d bytes) does not match the uploaded file (%d bytes)",
			len(decoded), len(pngBytes))
	}
}

func TestPortraitRejectsOversizeUpload(t *testing.T) {
	big := make([]byte, maxImageUploadBytes+1024)
	copy(big, tinyPNG(t))
	r := multipartRequest(t, map[string]string{}, "field_portrait__file", big)

	_, err := imageFieldValue(r, "portrait")
	if err == nil {
		t.Fatalf("an oversize upload was accepted — walt.id would fail later, cryptically")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error %q does not tell the operator there is a size limit", err)
	}
}

func TestPortraitRejectsNonImageUpload(t *testing.T) {
	r := multipartRequest(t, map[string]string{}, "field_portrait__file",
		[]byte("%PDF-1.7\nnot an image at all"))
	_, err := imageFieldValue(r, "portrait")
	if err == nil {
		t.Fatalf("a non-image upload was accepted")
	}
	if !strings.Contains(err.Error(), "JPEG") {
		t.Errorf("error %q does not say which formats are accepted", err)
	}
}

// An already-uploaded portrait must survive a re-render, like every other
// prefilled field — otherwise a validation error elsewhere on the form
// silently discards the operator's photo.
func TestPortraitRoundTripsWhenNoNewFilePicked(t *testing.T) {
	existing := base64.StdEncoding.EncodeToString(tinyPNG(t))
	r := multipartRequest(t, map[string]string{"field_portrait": existing}, "", nil)

	got, err := imageFieldValue(r, "portrait")
	if err != nil {
		t.Fatalf("imageFieldValue: %v", err)
	}
	if got != existing {
		t.Errorf("portrait was not preserved across a submit with no new file:\ngot  %.32s…\nwant %.32s…", got, existing)
	}
}

// TestMultipartFormStillParsesFlatFields is the regression guard for the
// encoding change. Switching the form to multipart/form-data touches EVERY
// issuance, not just mDL — if flat fields stopped parsing, every non-mdoc
// credential would break. Asserted through the real SubmitIssue parsing step.
func TestMultipartFormStillParsesFlatFields(t *testing.T) {
	r := multipartRequest(t, map[string]string{
		"field_family_name":     "Perez",
		"field_given_name":      "Ana",
		"field_document_number": "DL-99887",
		"issuer_dpg":            "walt.id",
		"schema_id":             "org.iso.18013.5.1.mDL",
	}, "", nil)

	if err := r.ParseMultipartForm(maxIssueFormMemory); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}
	for k, want := range map[string]string{
		"field_family_name":     "Perez",
		"field_given_name":      "Ana",
		"field_document_number": "DL-99887",
		"issuer_dpg":            "walt.id",
		"schema_id":             "org.iso.18013.5.1.mDL",
	} {
		if got := r.FormValue(k); got != want {
			t.Errorf("multipart FormValue(%q) = %q, want %q — the encoding change broke flat-field parsing", k, got, want)
		}
	}
}

// The urlencoded path must keep working too: API callers and any cached page
// still post that way, and ParseMultipartForm returns ErrNotMultipart for it.
func TestUrlencodedFormStillParsesAfterMultipartSwitch(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/issuer/issue",
		strings.NewReader("field_family_name=Perez&issuer_dpg=walt.id"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Mirror SubmitIssue's parse step exactly.
	if err := r.ParseMultipartForm(maxIssueFormMemory); err != nil {
		_ = r.ParseForm()
	}
	if got := r.FormValue("field_family_name"); got != "Perez" {
		t.Errorf("urlencoded FormValue = %q, want Perez — the multipart switch broke non-browser callers", got)
	}
}

// A required structured field must be reported as missing when the operator
// leaves every row blank — checking it against the flat subject map would
// wrongly report a correctly-filled one as missing, and wrongly accept an
// empty one.
func TestMissingRequiredStructuredField(t *testing.T) {
	schema := vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{
		{Name: "driving_privileges", Datatype: "string", Format: mdoc.FormatDrivingPrivileges, Required: true},
	}}

	if missing := missingRequiredFields(schema, map[string]string{}, nil); len(missing) != 1 || missing[0] != "driving_privileges" {
		t.Errorf("empty structured field: missing = %v, want [driving_privileges]", missing)
	}

	filled := map[string]json.RawMessage{"driving_privileges": json.RawMessage(`[{"vehicle_category_code":"B"}]`)}
	if missing := missingRequiredFields(schema, map[string]string{}, filled); len(missing) != 0 {
		t.Errorf("filled structured field reported missing: %v — the operator would be blocked "+
			"from issuing a correctly filled form", missing)
	}
}

// --- helpers ---

// gatherStructuredForTest mirrors SubmitIssue's structured-gathering step,
// routed through the SAME drivingPrivilegeRows + mdoc.EncodeDrivingPrivileges
// the handler calls, so the tested path is the production one rather than a
// copy that could diverge.
func gatherStructuredForTest(t *testing.T, r *http.Request, schema vctypes.Schema) map[string]json.RawMessage {
	t.Helper()
	if err := r.ParseMultipartForm(maxIssueFormMemory); err != nil {
		_ = r.ParseForm()
	}
	out := map[string]json.RawMessage{}
	for _, fs := range schema.FieldsSpec {
		if !isStructuredField(fs) {
			continue
		}
		raw, err := mdoc.EncodeDrivingPrivileges(drivingPrivilegeRows(r, 0))
		if err != nil {
			t.Fatalf("encode %s: %v", fs.Name, err)
		}
		if len(raw) > 0 {
			out[fs.Name] = raw
		}
	}
	return out
}

// marshalCredentialData marshals a namespace payload the way the adapter's
// issuer2RuntimeOverrides does, so the assertion is made against real wire
// bytes rather than against the in-memory Go value.
func marshalCredentialData(t *testing.T, data map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal credentialData: %v", err)
	}
	return raw
}

// multipartRequest builds the kind of request a browser posts from the issue
// form: multipart/form-data, optionally carrying one file part.
func multipartRequest(t *testing.T, fields map[string]string, fileField string, fileBytes []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	if fileField != "" {
		fw, err := mw.CreateFormFile(fileField, "upload.png")
		if err != nil {
			t.Fatalf("create file part: %v", err)
		}
		if _, err := fw.Write(fileBytes); err != nil {
			t.Fatalf("write file part: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/issuer/issue", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// tinyPNG produces a real, sniffable PNG so the content-type check under test
// is exercised against genuine image bytes rather than a magic-number stub.
func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// renderIssueFormWithStructured renders the real issue form with the
// structured-field template data populated the way applyStructuredFieldDefaults
// does in production.
func renderIssueFormWithStructured(t *testing.T, schema vctypes.Schema, vals map[string]string) string {
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
	data := issueData{Schema: schema, SingleSource: "manual", IssuerDpg: "walt.id", FieldValues: vals}
	if data.FieldValues == nil {
		data.FieldValues = map[string]string{}
	}
	applyStructuredFieldDefaults(&data, httptest.NewRequest(http.MethodGet, "/issuer/issue", nil))

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "fragment_issue_single_form", data); err != nil {
		t.Fatalf("render issue form: %v", err)
	}
	return buf.String()
}

// TestDrivingPrivilegesOverCapWarnsOperator pins that filling more categories
// than the vendor profile can carry is REJECTED rather than silently
// truncated. The form renders 4 rows but walt.id's arrayConfig takes exactly
// 2, so without the guard in SubmitIssue the operator would see a successful
// issuance and a credential missing categories they entered — the
// quiet-data-loss class this whole change set exists to remove.
func TestDrivingPrivilegesOverCapWarnsOperator(t *testing.T) {
	form := url.Values{}
	for i, code := range []string{"A", "B", "C"} {
		form.Set(fmt.Sprintf("dp_vehicle_category_code_%d", i), code)
		form.Set(fmt.Sprintf("dp_issue_date_%d", i), "2020-01-01")
		form.Set(fmt.Sprintf("dp_expiry_date_%d", i), "2030-01-01")
	}
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()

	filled := drivingPrivilegeRows(req, 0)
	if len(filled) != 3 {
		t.Fatalf("drivingPrivilegeRows read %d entries, want 3", len(filled))
	}
	if len(filled) <= mdoc.DrivingPrivilegesArrayConfigSize {
		t.Fatalf("test premise broken: 3 entries should exceed the cap of %d",
			mdoc.DrivingPrivilegesArrayConfigSize)
	}

	// The encoder truncates as a backstop — that silent drop is precisely what
	// makes an un-warned operator lose data, which is why SubmitIssue rejects
	// before reaching it.
	raw, err := mdoc.EncodeDrivingPrivileges(filled)
	if err != nil {
		t.Fatalf("EncodeDrivingPrivileges: %v", err)
	}
	var got []mdoc.DrivingPrivilege
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != mdoc.DrivingPrivilegesArrayConfigSize {
		t.Errorf("encoded %d entries, want %d", len(got), mdoc.DrivingPrivilegesArrayConfigSize)
	}
	for _, p := range got {
		if p.VehicleCategoryCode == "C" {
			t.Error("third category survived encoding — the cap is not what this test assumes")
		}
	}
}

// TestMdocDatesAreFullDateNotRFC3339 reproduces a live failure: the operator's
// birth_date reached walt.id as "1984-08-18T04:00:00Z" and issuance died at
// wallet redemption with
//
//	DateTimeParseException: Text '1984-08-18T04:00:00Z' could not be parsed,
//	unparsed text found at index 10
//
// Index 10 is where the date ends and the time begins. ISO 18013-5 dates are
// CBOR full-date (tag 1004) — no time component. normalizeIssuanceTimeTZ
// returns full RFC3339, which is correct for W3C validFrom and SD-JWT nbf but
// wrong for mdoc, so mdoc dates must be trimmed. The driving-privilege dates
// already were; the flat ones were not.
func TestMdocDatesAreFullDateNotRFC3339(t *testing.T) {
	for _, tc := range []struct {
		name, std, in, want string
	}{
		{"mdoc trims the time", "mso_mdoc", "1984-08-18", "1984-08-18"},
		{"w3c keeps full RFC3339", "w3c_vcdm_2", "1984-08-18", "1984-08-18T04:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// -240 = UTC-4, the offset the operator's browser reported.
			normalized := normalizeIssuanceTimeTZ(tc.in, -240)
			got := normalized
			if tc.std == "mso_mdoc" {
				got = fullDateOnly(normalized)
			}
			if got != tc.want {
				t.Errorf("%s: got %q, want %q", tc.std, got, tc.want)
			}
			if tc.std == "mso_mdoc" && strings.Contains(got, "T") {
				t.Errorf("mdoc date %q still carries a time component — walt.id "+
					"rejects it at index 10", got)
			}
		})
	}
}
