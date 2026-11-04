package handlers

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// saveAdapter captures SaveCustomSchema and lets a test choose what the
// issuer DPG looks like (notably whether it is the Inji auth-code flavour).
type saveAdapter struct {
	testAdapter
	dpgs    map[string]vctypes.DPG
	saved   []vctypes.Schema
	saveErr error
}

func (s *saveAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return s.dpgs, nil
}

func (s *saveAdapter) SaveCustomSchema(_ context.Context, schema vctypes.Schema) error {
	s.saved = append(s.saved, schema)
	return s.saveErr
}

// postWithSession POSTs form to handler under a session that mutate has
// already seeded (DPG, destination, …), mirroring the browser's cookie.
func postWithSession(t *testing.T, h *H, handler http.HandlerFunc, target string, form url.Values, mutate func(*Session)) *httptest.ResponseRecorder {
	t.Helper()
	seed := httptest.NewRecorder()
	sess := h.Sessions.MustGet(seed, httptest.NewRequest(http.MethodGet, "/", nil))
	if mutate != nil {
		mutate(sess)
	}
	cookies := seed.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie issued")
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookies[0])
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func saveForm() url.Values {
	return url.Values{
		"name":             {"Library Card"},
		"std":              {"w3c_vcdm_2"},
		"field_name_0":     {"holder_name"},
		"field_datatype_0": {"string"},
	}
}

func newSaveH(ad backend.Adapter) *H { return &H{Adapter: ad, Sessions: NewStore()} }

func TestSaveSchemaRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{"missing name", func(v url.Values) { v.Set("name", "  ") }, "Schema needs a name"},
		{"no fields", func(v url.Values) { v.Del("field_name_0"); v.Del("field_datatype_0") }, "Add at least one claim field"},
		{"bad field name", func(v url.Values) { v.Set("field_name_0", "ñandú") }, "Nombre de campo inválido"},
		{"bad locale", func(v url.Values) {
			v.Set("field_lang_0_0", "es DO!")
			v.Set("field_label_0_0", "Nombre")
		}, "Código de idioma inválido"},
		{"mdoc with an unknown docType", func(v url.Values) {
			v.Set("std", "mso_mdoc")
			v.Set("doctype", "evil.docType")
		}, "docType de mdoc inválido"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ad := &saveAdapter{dpgs: map[string]vctypes.DPG{"dpg1": {}}}
			form := saveForm()
			tc.mutate(form)
			h := newSaveH(ad)
			rr := postWithSession(t, h, h.SaveSchema, "/issuer/schema/save", form, nil)
			if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), tc.want) {
				t.Fatalf("got %d %q, want 422 containing %q", rr.Code, rr.Body.String(), tc.want)
			}
			if len(ad.saved) != 0 {
				t.Error("an invalid schema must never reach SaveCustomSchema")
			}
		})
	}
}

func TestSaveSchemaRejectsMdocOnTheAuthCodePath(t *testing.T) {
	ad := &saveAdapter{dpgs: map[string]vctypes.DPG{"inji-ac": {SchemaApply: "inji_authcode"}}}
	form := saveForm()
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	h := newSaveH(ad)

	rr := postWithSession(t, h, h.SaveSchema, "/issuer/schema/save", form, func(s *Session) { s.IssuerDpg = "inji-ac" })
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "no está soportado en modo Auth-Code") {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if len(ad.saved) != 0 {
		t.Error("an mdoc schema must not be saved through the auth-code path")
	}
}

func TestSaveSchemaPersistsAndRedirects(t *testing.T) {
	ad := &saveAdapter{dpgs: map[string]vctypes.DPG{"dpg1": {}}}
	h := newSaveH(ad)

	rr := postWithSession(t, h, h.SaveSchema, "/issuer/schema/save?use=1", saveForm(), nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/issuer/schema" {
		t.Fatalf("got %d Location=%q, want 303 → /issuer/schema", rr.Code, rr.Header().Get("Location"))
	}
	if len(ad.saved) != 1 || ad.saved[0].Name != "Library Card" {
		t.Fatalf("SaveCustomSchema got %+v", ad.saved)
	}
}

func TestSaveSchemaSavesAValidMdocSchema(t *testing.T) {
	ad := &saveAdapter{dpgs: map[string]vctypes.DPG{"dpg1": {}}}
	form := saveForm()
	form.Set("std", "mso_mdoc")
	form.Set("doctype", "org.iso.18013.5.1.mDL")
	h := newSaveH(ad)

	rr := postWithSession(t, h, h.SaveSchema, "/issuer/schema/save", form, nil)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if len(ad.saved) != 1 || ad.saved[0].Std != "mso_mdoc" ||
		len(ad.saved[0].AdditionalTypes) == 0 || ad.saved[0].AdditionalTypes[0] != "org.iso.18013.5.1.mDL" {
		t.Fatalf("the docType must travel on the saved schema: %+v", ad.saved)
	}
}

func TestSaveSchemaSurfacesAdapterErrors(t *testing.T) {
	ad := &saveAdapter{dpgs: map[string]vctypes.DPG{"dpg1": {}}, saveErr: errors.New("disk full")}
	h := newSaveH(ad)
	rr := postWithSession(t, h, h.SaveSchema, "/issuer/schema/save", saveForm(), nil)
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "disk full") {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
}

// ─── SubmitIssue: image upload, booleans, plain dates ────────────────────────

func imageSchema() vctypes.Schema {
	return vctypes.Schema{
		ID: "org.iso.18013.5.1.mDL", Name: "Mobile Driving Licence", Std: "mso_mdoc",
		FieldsSpec: []vctypes.FieldSpec{{Name: "portrait", Format: "image"}},
	}
}

// multipartIssue posts the issue form as multipart/form-data with an optional
// file part for portrait, the way the browser does when an image is picked.
func multipartIssue(t *testing.T, ad backend.Adapter, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("issuer_dpg", "dpg1")
	_ = mw.WriteField("schema_id", "org.iso.18013.5.1.mDL")
	if file != nil {
		fw, err := mw.CreateFormFile("field_portrait__file", "me.png")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(file)
	}
	_ = mw.Close()

	h := &H{Adapter: ad, Sessions: NewStore(), Templates: resultFragments(t)}
	seed := httptest.NewRecorder()
	sess := h.Sessions.MustGet(seed, httptest.NewRequest(http.MethodGet, "/", nil))
	sess.Dest = "wallet"
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue/submit", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(seed.Result().Cookies()[0])
	rr := httptest.NewRecorder()
	h.SubmitIssue(rr, req)
	return rr
}

// pngBytes is the 8-byte PNG signature plus padding — enough for
// http.DetectContentType to call it image/png.
var pngBytes = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...)

func TestSubmitIssueAcceptsAnUploadedPortrait(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{
		schemas:     []vctypes.Schema{imageSchema()},
		issueResult: backend.IssueToWalletResult{OfferURI: "offer://portrait"},
	}}
	rr := multipartIssue(t, ad, pngBytes)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if got := ad.walletReq.SubjectData["portrait"]; got == "" {
		t.Error("the uploaded image must reach the adapter as base64 in SubjectData")
	}
}

func TestSubmitIssueRejectsBadPortraitUploads(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{schemas: []vctypes.Schema{imageSchema()}}}

	notAnImage := multipartIssue(t, ad, []byte("this is plain text, not a photo"))
	if notAnImage.Code != http.StatusUnprocessableEntity || !strings.Contains(notAnImage.Body.String(), "must be a JPEG or PNG") {
		t.Errorf("non-image: got %d %q", notAnImage.Code, notAnImage.Body.String())
	}

	tooBig := multipartIssue(t, ad, append(append([]byte{}, pngBytes...), make([]byte, maxImageUploadBytes+1)...))
	if tooBig.Code != http.StatusUnprocessableEntity || !strings.Contains(tooBig.Body.String(), "limit") {
		t.Errorf("oversize: got %d %q", tooBig.Code, tooBig.Body.String())
	}
	if ad.walletN != 0 {
		t.Error("a rejected upload must never reach the adapter")
	}
}

func TestSubmitIssueBooleanPostedDirectlyAndPlainDateNormalised(t *testing.T) {
	schema := vctypes.Schema{
		ID: "Delegation", Name: "Delegation", Std: "w3c_vcdm_2",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "active", Datatype: "boolean"},
			{Name: "renewal_at", Datatype: "string", Format: "datetime"},
		},
	}
	ad := &captureAdapter{testAdapter: testAdapter{
		schemas:     []vctypes.Schema{schema},
		issueResult: backend.IssueToWalletResult{OfferURI: "offer://d"},
	}}
	rr := submitIssue(t, ad, "wallet", url.Values{
		"issuer_dpg": {"dpg1"}, "schema_id": {"Delegation"},
		// An API/bulk caller posts the literal on the base name, no checkbox.
		"field_active":     {"TRUE"},
		"field_renewal_at": {"2030-01-02T03:04"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if ad.walletReq.SubjectData["active"] != "true" {
		t.Errorf("active = %q, want \"true\"", ad.walletReq.SubjectData["active"])
	}
	if got := ad.walletReq.SubjectData["renewal_at"]; !strings.HasPrefix(got, "2030-01-02T03:04") || !strings.HasSuffix(got, "Z") {
		t.Errorf("renewal_at = %q, want an RFC3339 UTC instant", got)
	}
}
