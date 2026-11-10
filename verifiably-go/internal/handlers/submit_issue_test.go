package handlers

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// captureAdapter records the IssueRequest SubmitIssue builds, so tests can
// assert on what actually reaches the adapter instead of on rendered HTML.
type captureAdapter struct {
	testAdapter
	walletReq backend.IssueRequest
	pdfReq    backend.IssueRequest
	pdfErr    error
	walletN   int
	pdfN      int
}

func (c *captureAdapter) IssueToWallet(_ context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	c.walletN++
	c.walletReq = req
	return c.issueResult, c.issueErr
}

func (c *captureAdapter) IssueAsPDF(_ context.Context, req backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	c.pdfN++
	c.pdfReq = req
	return backend.IssueAsPDFResult{IssuerName: "Test Issuer"}, c.pdfErr
}

func resultFragments(t *testing.T) *template.Template {
	t.Helper()
	return template.Must(template.New("").Parse(
		`{{define "fragment_issue_wallet_result"}}WALLET:{{.OfferURI}}{{end}}` +
			`{{define "fragment_issue_pdf_result"}}PDF:{{.PDFResult.IssuerName}}{{end}}`))
}

// submitIssue seeds a session carrying dest, then POSTs the form to
// SubmitIssue with that session's cookie.
func submitIssue(t *testing.T, ad backend.Adapter, dest string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	store := NewStore()
	h := &H{Adapter: ad, Sessions: store, Templates: resultFragments(t)}

	seed := httptest.NewRecorder()
	sess := store.MustGet(seed, httptest.NewRequest(http.MethodGet, "/", nil))
	sess.Dest = dest
	cookies := seed.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie issued")
	}

	req := httptest.NewRequest(http.MethodPost, "/issuer/issue/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookies[0])
	rr := httptest.NewRecorder()
	h.SubmitIssue(rr, req)
	return rr
}

func personSchema() vctypes.Schema {
	return vctypes.Schema{
		ID: "PersonCredential", Name: "Person", Std: "w3c_vcdm_2",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "given_name", Required: true},
			{Name: "nickname"},
		},
	}
}

func TestSubmitIssueWithoutDpgOrSchemaIsASessionExpiredError(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{schemas: []vctypes.Schema{personSchema()}}}
	rr := submitIssue(t, ad, "wallet", url.Values{})
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Session expired") {
		t.Fatalf("got %d %q, want 422 session-expired", rr.Code, rr.Body.String())
	}
	if ad.walletN != 0 {
		t.Error("nothing may be issued without a DPG and a schema")
	}
}

func TestSubmitIssueSurfacesAnUnavailableBackend(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{schemasErr: errors.New("boom")}}
	rr := submitIssue(t, ad, "wallet", url.Values{"issuer_dpg": {"dpg1"}, "schema_id": {"PersonCredential"}})
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "backend unavailable: boom") {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
}

func TestSubmitIssueRejectsMissingRequiredFields(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{schemas: []vctypes.Schema{personSchema()}}}
	rr := submitIssue(t, ad, "wallet", url.Values{
		"issuer_dpg": {"dpg1"}, "schema_id": {"PersonCredential"},
		"field_given_name": {"   "},
	})
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Fill in required fields: given_name") {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if ad.walletN != 0 {
		t.Error("an incomplete form must never reach the adapter")
	}
}

func TestSubmitIssueToWalletPassesTrimmedSubjectData(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{
		schemas:     []vctypes.Schema{personSchema()},
		issueResult: backend.IssueToWalletResult{OfferURI: "openid-credential-offer://x"},
	}}
	rr := submitIssue(t, ad, "wallet", url.Values{
		"issuer_dpg": {"dpg1"}, "schema_id": {"PersonCredential"},
		"field_given_name": {"  Ada  "},
	})
	if rr.Code != http.StatusOK || rr.Body.String() != "WALLET:openid-credential-offer://x" {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if got := ad.walletReq.SubjectData["given_name"]; got != "Ada" {
		t.Errorf("given_name = %q, want trimmed %q", got, "Ada")
	}
	if ad.walletReq.IssuerDpg != "dpg1" || ad.walletReq.Schema.ID != "PersonCredential" {
		t.Errorf("request lost its DPG/schema: %+v", ad.walletReq)
	}
}

func TestSubmitIssueToWalletSurfacesAdapterErrors(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{
		schemas:  []vctypes.Schema{personSchema()},
		issueErr: errors.New("issuer exploded"),
	}}
	rr := submitIssue(t, ad, "wallet", url.Values{
		"issuer_dpg": {"dpg1"}, "schema_id": {"PersonCredential"}, "field_given_name": {"Ada"},
	})
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "issuer exploded") {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
}

func TestSubmitIssueAsPDF(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{schemas: []vctypes.Schema{personSchema()}}}
	form := url.Values{"issuer_dpg": {"dpg1"}, "schema_id": {"PersonCredential"}, "field_given_name": {"Ada"}}

	rr := submitIssue(t, ad, "pdf", form)
	if rr.Code != http.StatusOK || rr.Body.String() != "PDF:Test Issuer" {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if ad.pdfN != 1 || ad.walletN != 0 {
		t.Errorf("dest=pdf must call IssueAsPDF only (pdf=%d wallet=%d)", ad.pdfN, ad.walletN)
	}

	ad.pdfErr = errors.New("renderer down")
	rr = submitIssue(t, ad, "pdf", form)
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "renderer down") {
		t.Fatalf("pdf error: got %d %q", rr.Code, rr.Body.String())
	}
}

func mdocSubmitSchema() vctypes.Schema {
	return vctypes.Schema{
		ID: "org.iso.18013.5.1.mDL", Name: "Mobile Driving Licence", Std: "mso_mdoc",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "family_name", Required: true},
			{Name: "birth_date", Required: true, Datatype: "string", Format: "date"},
			{Name: "age_over_18", Datatype: "boolean"},
			{Name: "driving_privileges", Required: true, Format: "driving_privileges"},
		},
	}
}

func mdocForm() url.Values {
	return url.Values{
		"issuer_dpg": {"dpg1"}, "schema_id": {"org.iso.18013.5.1.mDL"},
		"field_family_name": {"Lovelace"},
		// An operator east of UTC (+05:30). The full-date must come through
		// untouched — routing it through the instant normaliser shifts it back
		// a day for every zone east of UTC.
		"field_birth_date": {"1984-08-18"},
		"tz_offset":        {"330"},
		// The hidden "false" + the ticked checkbox pair the form really posts.
		"field_age_over_18":          {"false"},
		"field_age_over_18__checked": {"true"},
		"dp_vehicle_category_code_0": {"B"},
		"dp_issue_date_0":            {"2021-06-01"},
		"dp_expiry_date_0":           {"2031-06-01"},
	}
}

func TestSubmitIssueMdocKeepsFullDateBooleanAndStructuredClaims(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{
		schemas:     []vctypes.Schema{mdocSubmitSchema()},
		issueResult: backend.IssueToWalletResult{OfferURI: "openid-credential-offer://mdoc"},
	}}
	rr := submitIssue(t, ad, "wallet", mdocForm())
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	got := ad.walletReq
	if got.SubjectData["birth_date"] != "1984-08-18" {
		t.Errorf("birth_date = %q, want 1984-08-18 (no east-of-UTC day shift)", got.SubjectData["birth_date"])
	}
	if got.SubjectData["age_over_18"] != "true" {
		t.Errorf("age_over_18 = %q, want \"true\" from the checkbox", got.SubjectData["age_over_18"])
	}
	dp, ok := got.StructuredData["driving_privileges"]
	if !ok || !strings.Contains(string(dp), `"B"`) {
		t.Errorf("driving_privileges must travel in StructuredData as a JSON array, got %s", dp)
	}
	if _, leaked := got.SubjectData["driving_privileges"]; leaked {
		t.Error("a structured claim must never be stringified into SubjectData")
	}
}

func TestSubmitIssueMdocRequiresADrivingPrivilegeCategory(t *testing.T) {
	ad := &captureAdapter{testAdapter: testAdapter{schemas: []vctypes.Schema{mdocSubmitSchema()}}}
	form := mdocForm()
	form.Del("dp_vehicle_category_code_0")
	form.Del("dp_issue_date_0")
	form.Del("dp_expiry_date_0")

	rr := submitIssue(t, ad, "wallet", form)
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "driving_privileges es obligatorio") {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	if ad.walletN != 0 {
		t.Error("an mDL without a driving privilege must never reach the adapter")
	}
}
