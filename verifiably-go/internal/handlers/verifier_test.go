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

	qrgen "github.com/skip2/go-qrcode"
	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/vctypes"
)

// ─── fixtures ────────────────────────────────────────────────────────────────

const verifierDPG = "Example Verifier"

// verifierAdapter extends delegAPIAdapter (ListAllSchemas / ListVerifierDpgs /
// RequestPresentation / FetchPresentationResult) with VerifyDirect and records
// the requests the verifier handlers send.
type verifierAdapter struct {
	delegAPIAdapter
	presReqs     []backend.PresentationRequest
	directReqs   []backend.DirectVerifyRequest
	directResult backend.VerificationResult
	directErr    error
}

func (a *verifierAdapter) RequestPresentation(ctx context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	a.presReqs = append(a.presReqs, req)
	return a.delegAPIAdapter.RequestPresentation(ctx, req)
}

func (a *verifierAdapter) VerifyDirect(_ context.Context, req backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	a.directReqs = append(a.directReqs, req)
	return a.directResult, a.directErr
}

// verifierTrust is a trust.Registry whose IsTrusted answer is injectable.
type verifierTrust struct {
	trustFakeRegistry
	err error
}

func (f *verifierTrust) IsTrusted(context.Context, string, string) error { return f.err }

// verifierFixtureSchemas covers every branch of the presentable-schema filter
// and of buildTemplateForSchema: custom W3C with variants, custom SD-JWT
// without variants, delegation cards (onBehalfOf) in both formats, a stock
// (non-custom) schema with variants, an Inji-style non-custom SD-JWT schema
// without variants, a schema scoped to another vendor, one whose variants are
// all non-presentable, and one whose primary variant must be rebased.
func verifierFixtureSchemas() []vctypes.Schema {
	own := []string{verifierDPG}
	return []vctypes.Schema{
		{ID: "diploma", Name: "Diploma", Desc: "University degree", Std: "w3c_vcdm_2", Custom: true, DPGs: own, IssuerDisplayName: "Example University",
			FieldsSpec: []vctypes.FieldSpec{{Name: "name"}, {Name: "degree"}},
			Variants: []vctypes.SchemaVariant{
				{ID: "diploma", Std: "w3c_vcdm_2", Format: "ldp_vc", CanPresent: true},
				{ID: "diploma-sdjwt", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", Vct: "https://issuer.example/vct/diploma", CanPresent: true}}},
		{ID: "person", Name: "Person", Std: "sd_jwt_vc (IETF)", Custom: true, DPGs: own,
			FieldsSpec: []vctypes.FieldSpec{{Name: "name"}, {Name: "subjectRef"}}},
		{ID: "access", Name: "Access Grant", Std: "w3c_vcdm_2", Custom: true, DPGs: own,
			FieldsSpec: []vctypes.FieldSpec{{Name: "onBehalfOf"}, {Name: "allowedAction"}}},
		{ID: "access-sdjwt", Name: "Access Grant SD", Std: "sd_jwt_vc (IETF)", Custom: true, DPGs: own,
			FieldsSpec: []vctypes.FieldSpec{{Name: "onBehalfOf"}}},
		{ID: "stock", Name: "Stock Card", Std: "w3c_vcdm_2", DPGs: own,
			FieldsSpec: []vctypes.FieldSpec{{Name: "id"}},
			Variants: []vctypes.SchemaVariant{
				{ID: "stock", Std: "w3c_vcdm_2", Format: "jwt_vc_json", CanPresent: true},
				{ID: "stock-sdjwt", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", CanPresent: true}}},
		{ID: "inji-sd", Name: "Inji SD", Std: "sd_jwt_vc (IETF)", DPGs: own, FieldsSpec: []vctypes.FieldSpec{{Name: "id"}}},
		{ID: "other", Name: "Other Vendor Card", Std: "w3c_vcdm_2", Custom: true, DPGs: []string{"Other Vendor"}},
		{ID: "nopresent", Name: "No Present", Std: "w3c_vcdm_2", Custom: true, DPGs: own,
			Variants: []vctypes.SchemaVariant{{ID: "nopresent", Std: "w3c_vcdm_2", Format: "jwt_vc_json-ld"}}},
		{ID: "rebase", Name: "Rebase Card", Std: "w3c_vcdm_2", Custom: true, DPGs: own,
			Variants: []vctypes.SchemaVariant{
				{ID: "rebase", Std: "w3c_vcdm_2", Format: "jwt_vc_json-ld"},
				{ID: "rebase-sdjwt", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", CanPresent: true}}},
	}
}

func verifierNewAdapter() *verifierAdapter {
	ad := &verifierAdapter{}
	ad.schemas = verifierFixtureSchemas()
	return ad
}

// verifierSetup builds an H over verifier_verify with a seeded verifier session.
func verifierSetup(t *testing.T, ad *verifierAdapter, mutate func(*Session)) (*H, []*http.Cookie) {
	t.Helper()
	tmpl := loadPageTemplates(t, "verifier_verify")
	// fragment_verify_result includes the _delegation_card partial, which the
	// production glob picks up from templates/public/verify.html.
	if _, err := tmpl.ParseFiles("../../templates/public/verify.html"); err != nil {
		t.Fatalf("parse public verify template: %v", err)
	}
	h := &H{Adapter: ad, Sessions: NewStore(), Templates: tmpl}
	cookies := seedSession(t, h, func(s *Session) {
		s.VerifierDpg = verifierDPG
		if mutate != nil {
			mutate(s)
		}
	})
	return h, cookies
}

func verifierPost(h *H, fn func(http.ResponseWriter, *http.Request), v url.Values, cookies []*http.Cookie) (*httptest.ResponseRecorder, *Session) {
	req := formPost("/verifier/verify", v, cookies...)
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr, sessionOf(h, req)
}

func verifierToast(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }

func verifierNames(ss []vctypes.Schema) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return strings.Join(out, ",")
}

// ─── pure helpers ────────────────────────────────────────────────────────────

func TestVerifierPresentableSchemas_Branches(t *testing.T) {
	got := verifierPresentableSchemas(verifierFixtureSchemas(), verifierDPG)
	if names := verifierNames(got); names != "diploma,person,access,access-sdjwt,rebase-sdjwt" {
		t.Fatalf("presentable = %s", names)
	}
	rebased := got[len(got)-1]
	if rebased.ID != "rebase-sdjwt" || rebased.Std != "sd_jwt_vc (IETF)" || len(rebased.Variants) != 1 {
		t.Errorf("rebased card = %+v", rebased)
	}
	// No DPG chosen → no vendor scoping: the other-vendor card is kept.
	if names := verifierNames(verifierPresentableSchemas(verifierFixtureSchemas(), "")); !strings.Contains(names, "other") {
		t.Errorf("unscoped = %s", names)
	}
}

func TestVerifierAuthcodeSchemas_Branches(t *testing.T) {
	h := &H{Adapter: &testAdapter{}}
	h.Subjects = &fakeSubjects{listCredsErr: errors.New("db down")}
	if got := h.verifierAuthcodeSchemas(context.Background()); got != nil {
		t.Errorf("list error: want nil, got %v", got)
	}
	h.Subjects = &fakeSubjects{
		listCreds:   []map[string]string{{"key": ""}, {"key": "person_sd"}, {"key": "person_ldp", "displayName": "Person"}},
		formatByKey: map[string]string{"person_sd": "vc+sd-jwt"},
	}
	got := h.verifierAuthcodeSchemas(context.Background())
	if len(got) != 2 {
		t.Fatalf("schemas = %+v", got)
	}
	if got[0].ID != "person_sd" || got[0].Name != "person_sd" || got[0].Std != "sd_jwt_vc (IETF)" {
		t.Errorf("sd-jwt schema = %+v", got[0])
	}
	if got[1].Name != "Person" || got[1].Std != "w3c_vcdm_2" {
		t.Errorf("ldp schema = %+v", got[1])
	}
}

func TestVerifierSchemas_IncludesAuthcodeForInjiVerify(t *testing.T) {
	h := &H{Adapter: &testAdapter{schemas: []vctypes.Schema{{ID: "a"}}}}
	h.Subjects = &fakeSubjects{listCreds: []map[string]string{{"key": "person_ldp"}}}
	got, err := h.verifierSchemas(context.Background(), "Inji Verify")
	if err != nil || verifierNames(got) != "a,person_ldp" {
		t.Errorf("Inji Verify: %s err=%v", verifierNames(got), err)
	}
	got, err = h.verifierSchemas(context.Background(), verifierDPG)
	if err != nil || verifierNames(got) != "a" {
		t.Errorf("other DPG: %s err=%v", verifierNames(got), err)
	}
	h.Adapter = &testAdapter{schemasErr: errors.New("boom")}
	if _, err := h.verifierSchemas(context.Background(), verifierDPG); err == nil {
		t.Error("adapter error must propagate")
	}
}

func TestVerifierCustomData(t *testing.T) {
	schemas := verifierFixtureSchemas()
	sess := &Session{VerifierDpg: verifierDPG, VerifierSchemaFilter: "all"}
	body := verifierCustomData(sess, schemas, vctypes.DPG{Vendor: verifierDPG})
	if verifierNames(body["Schemas"].([]vctypes.Schema)) != "diploma,person,access,access-sdjwt,rebase-sdjwt" {
		t.Errorf("all: %s", verifierNames(body["Schemas"].([]vctypes.Schema)))
	}
	if stds := body["Stds"].([]string); strings.Join(stds, "|") != "all|w3c_vcdm_2|sd_jwt_vc (IETF)" {
		t.Errorf("stds = %v", stds)
	}
	if body["VerifierDpgObj"].(vctypes.DPG).Vendor != verifierDPG || body["DelegFormat"] != "jwt_vc_json" {
		t.Errorf("dpg/format = %v/%v", body["VerifierDpgObj"], body["DelegFormat"])
	}

	// Std filter promotes the matching variant; query narrows by name/desc/std.
	sess.VerifierSchemaFilter = "sd_jwt_vc (IETF)"
	sess.VerifierSchemaQuery = "DEGREE"
	body = verifierCustomData(sess, schemas, vctypes.DPG{})
	got := body["Schemas"].([]vctypes.Schema)
	if len(got) != 1 || got[0].ID != "diploma-sdjwt" {
		t.Errorf("filtered = %s", verifierNames(got))
	}

	// Delegation step 1: only onBehalfOf cards.
	sess = &Session{VerifierDpg: verifierDPG, VerifierSchemaFilter: "all", VerifierDelegation: true}
	body = verifierCustomData(sess, schemas, vctypes.DPG{})
	if verifierNames(body["Schemas"].([]vctypes.Schema)) != "access,access-sdjwt" {
		t.Errorf("step 1 = %s", verifierNames(body["Schemas"].([]vctypes.Schema)))
	}
	// Step 2 with an SD-JWT delegation: identity cards in the same wire format.
	sess.VerifierDelegSchemaID = "access-sdjwt"
	sess.VerifierSubjectSchemaID = "person"
	body = verifierCustomData(sess, schemas, vctypes.DPG{})
	if verifierNames(body["Schemas"].([]vctypes.Schema)) != "person,rebase-sdjwt" {
		t.Errorf("step 2 = %s", verifierNames(body["Schemas"].([]vctypes.Schema)))
	}
	if body["DelegName"] != "Access Grant SD" || body["SubjectName"] != "Person" || body["DelegFormat"] != "vc+sd-jwt" {
		t.Errorf("names/format = %v/%v/%v", body["DelegName"], body["SubjectName"], body["DelegFormat"])
	}
}

func TestSchemaStdByVariantID(t *testing.T) {
	schemas := verifierFixtureSchemas()
	for id, want := range map[string]string{"": "", "diploma-sdjwt": "sd_jwt_vc (IETF)", "diploma": "w3c_vcdm_2", "nope": ""} {
		if got := schemaStdByVariantID(schemas, id); got != want {
			t.Errorf("%q: got %q want %q", id, got, want)
		}
	}
}

func TestSchemaNameForCredential(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://portal.example/")
	schemas := verifierFixtureSchemas()
	cred := func(types ...string) backend.NormalizedCredential { return backend.NormalizedCredential{Types: types} }
	cases := []struct {
		name string
		c    backend.NormalizedCredential
		want string
	}{
		{"host-derived vct", cred("VerifiableCredential", "https://portal.example/credentials/person"), "Person"},
		{"custom type name", cred("verifiablecredential", "AccessGrant"), "Access Grant"},
		{"variant vct", cred("https://issuer.example/vct/diploma"), "Diploma"},
		{"vct tail is the schema id", cred("https://elsewhere.example/types#rebase-sdjwt"), "Rebase Card"},
		{"bare variant id", cred("stock-sdjwt"), "Stock Card"},
		{"blank and unknown", cred(" ", "Unknown", "https://x.example/"), ""},
	}
	for _, tc := range cases {
		if got := schemaNameForCredential(schemas, tc.c); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
	if got := schemaNameForCredential(nil, cred("Person")); got != "" {
		t.Errorf("no schemas: %q", got)
	}
}

func TestSchemaStdByID(t *testing.T) {
	h := &H{Adapter: verifierNewAdapter()}
	ctx := context.Background()
	if got := h.schemaStdByID(ctx, verifierDPG, ""); got != "" {
		t.Errorf("empty id: %q", got)
	}
	if got := h.schemaStdByID(ctx, verifierDPG, "diploma-sdjwt"); got != "sd_jwt_vc (IETF)" {
		t.Errorf("variant: %q", got)
	}
	if got := h.schemaStdByID(ctx, verifierDPG, "missing"); got != "" {
		t.Errorf("unknown: %q", got)
	}
	h.Adapter = &testAdapter{schemasErr: errors.New("boom")}
	if got := h.schemaStdByID(ctx, verifierDPG, "diploma"); got != "" {
		t.Errorf("adapter error: %q", got)
	}
}

func TestBuildTemplateForSchema_Branches(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://portal.example")
	h := &H{Adapter: verifierNewAdapter()}
	ctx := context.Background()
	if _, err := h.buildTemplateForSchema(ctx, verifierDPG, "", nil, ""); err == nil || !strings.Contains(err.Error(), "pick a schema") {
		t.Errorf("empty id: %v", err)
	}
	if _, err := h.buildTemplateForSchema(ctx, verifierDPG, "missing", nil, ""); err == nil || !strings.Contains(err.Error(), `unknown schema "missing"`) {
		t.Errorf("unknown: %v", err)
	}
	// Custom W3C with variants: bogus fields dropped, full disclosure default.
	tpl, err := h.buildTemplateForSchema(ctx, verifierDPG, "diploma", []string{"degree", "bogus"}, "")
	if err != nil || strings.Join(tpl.Fields, ",") != "degree" || tpl.CredentialType != "Diploma" || tpl.Vct != "" || tpl.WireFormat != "" || tpl.Disclosure != "full credential shared" {
		t.Errorf("custom w3c: %+v err=%v", tpl, err)
	}
	// Custom SD-JWT: host-derived vct, selective disclosure of every field.
	tpl, err = h.buildTemplateForSchema(ctx, verifierDPG, "person", nil, "selective")
	if err != nil || tpl.Vct != "https://portal.example/credentials/person" || tpl.WireFormat != "vc+sd-jwt" || tpl.Disclosure != "selective — only name, subjectRef shared" {
		t.Errorf("custom sd-jwt: %+v err=%v", tpl, err)
	}
	// Stock schema: the picked variant supplies format; SD-JWT vct is derived.
	tpl, err = h.buildTemplateForSchema(ctx, verifierDPG, "stock-sdjwt", nil, "")
	if err != nil || tpl.WireFormat != "vc+sd-jwt" || tpl.Vct != "https://portal.example/credentials/stock-sdjwt" || tpl.CredentialType != "stock-sdjwt" {
		t.Errorf("stock sd-jwt: %+v err=%v", tpl, err)
	}
	// Inji-style: no variants, no Custom → both vct and wire format derived.
	tpl, err = h.buildTemplateForSchema(ctx, verifierDPG, "inji-sd", nil, "")
	if err != nil || tpl.WireFormat != "vc+sd-jwt" || tpl.Vct != "https://portal.example/credentials/inji-sd" {
		t.Errorf("inji sd-jwt: %+v err=%v", tpl, err)
	}
	h.Adapter = &testAdapter{schemasErr: errors.New("boom")}
	if _, err := h.buildTemplateForSchema(ctx, verifierDPG, "diploma", nil, ""); err == nil || !strings.Contains(err.Error(), "could not load schemas") {
		t.Errorf("adapter error: %v", err)
	}
}

func TestValidateWebhookURL_Branches(t *testing.T) {
	if _, err := validateWebhookURL("https://a b/hook"); err == nil || !strings.Contains(err.Error(), "invalid URL") {
		t.Errorf("parse error: %v", err)
	}
	// 203.0.113.0/24 (TEST-NET-3) is a numeric literal outside every blocked
	// range, so LookupHost returns it verbatim with no network access.
	if got, err := validateWebhookURL(" https://203.0.113.9/hook "); err != nil || got != "https://203.0.113.9/hook" {
		t.Errorf("public literal: %q %v", got, err)
	}
	t.Setenv("VERIFIABLY_WEBHOOK_ALLOWED_HOSTS", "hooks.example, 203.0.113.9")
	if got, err := validateWebhookURL("https://203.0.113.9/hook"); err != nil || got == "" {
		t.Errorf("allow-listed: %q %v", got, err)
	}
	if _, err := validateWebhookURL("https://203.0.113.10/hook"); err == nil || !strings.Contains(err.Error(), "not in VERIFIABLY_WEBHOOK_ALLOWED_HOSTS") {
		t.Errorf("not allow-listed: %v", err)
	}
}

func TestAttachTrustStatus(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h := &H{}
	res := backend.VerificationResult{Issuer: "did:example:issuer"}
	h.attachTrustStatus(req, &res)
	if res.TrustStatus != "" {
		t.Errorf("nil registry: %q", res.TrustStatus)
	}
	reg := &verifierTrust{}
	h.TrustRegistry = reg
	empty := backend.VerificationResult{}
	h.attachTrustStatus(req, &empty)
	if empty.TrustStatus != "" {
		t.Errorf("empty issuer: %q", empty.TrustStatus)
	}
	h.attachTrustStatus(req, &res)
	if res.TrustStatus != "trusted" {
		t.Errorf("trusted: %q", res.TrustStatus)
	}
	reg.err = trust.ErrUntrusted
	res = backend.VerificationResult{Issuer: "did:example:issuer"}
	h.attachTrustStatus(req, &res)
	if res.TrustStatus != "untrusted" || res.TrustReason == "" {
		t.Errorf("untrusted: %+v", res)
	}
	reg.err = errors.New("registry timeout")
	res = backend.VerificationResult{Issuer: "did:example:issuer"}
	h.attachTrustStatus(req, &res)
	if res.TrustStatus != "unknown" || res.TrustReason != "" {
		t.Errorf("io error: %+v", res)
	}
}

func TestAttachIssuerDisplay(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h := &H{Adapter: verifierNewAdapter()}
	h.attachIssuerDisplay(req, nil) // nil-safe
	res := backend.VerificationResult{IssuerDisplay: "Already", CredentialTitle: "Diploma"}
	h.attachIssuerDisplay(req, &res)
	if res.IssuerDisplay != "Already" {
		t.Errorf("preset display overwritten: %q", res.IssuerDisplay)
	}
	res = backend.VerificationResult{CredentialTitle: "  "}
	h.attachIssuerDisplay(req, &res)
	if res.IssuerDisplay != "" {
		t.Errorf("blank title: %q", res.IssuerDisplay)
	}
	res = backend.VerificationResult{CredentialTitle: " diploma "}
	h.attachIssuerDisplay(req, &res)
	if res.IssuerDisplay != "Example University" {
		t.Errorf("match: %q", res.IssuerDisplay)
	}
	res = backend.VerificationResult{CredentialTitle: "Person"} // no IssuerDisplayName
	h.attachIssuerDisplay(req, &res)
	if res.IssuerDisplay != "" {
		t.Errorf("match without display name: %q", res.IssuerDisplay)
	}
	res = backend.VerificationResult{CredentialTitle: "Nothing"}
	h.attachIssuerDisplay(req, &res)
	if res.IssuerDisplay != "" {
		t.Errorf("no match: %q", res.IssuerDisplay)
	}
	h.Adapter = &testAdapter{schemasErr: errors.New("boom")}
	res = backend.VerificationResult{CredentialTitle: "Diploma"}
	h.attachIssuerDisplay(req, &res)
	if res.IssuerDisplay != "" {
		t.Errorf("adapter error: %q", res.IssuerDisplay)
	}
}

// ─── handlers ────────────────────────────────────────────────────────────────

func TestShowVerify(t *testing.T) {
	t.Run("no DPG redirects", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), func(s *Session) { s.VerifierDpg = "" })
		rr := httptest.NewRecorder()
		h.ShowVerify(rr, issueGET("/verifier/verify", true, cookies))
		if rr.Header().Get("HX-Redirect") != "/verifier/dpg" {
			t.Errorf("HX-Redirect = %q", rr.Header().Get("HX-Redirect"))
		}
		rr = httptest.NewRecorder()
		h.ShowVerify(rr, issueGET("/verifier/verify", false, cookies))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/verifier/dpg" {
			t.Errorf("plain redirect: %d %q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("schema error toasts", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.schemasErr = errors.New("registry down")
		h, cookies := verifierSetup(t, ad, nil)
		rr := httptest.NewRecorder()
		h.ShowVerify(rr, issueGET("/verifier/verify", true, cookies))
		if !strings.Contains(verifierToast(rr), "backend unavailable: registry down") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("renders the card grid", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		req := issueGET("/verifier/verify", true, cookies)
		rr := httptest.NewRecorder()
		h.ShowVerify(rr, req)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Diploma") || strings.Contains(rr.Body.String(), "Other Vendor Card") {
			t.Errorf("status %d body=%.300s", rr.Code, rr.Body.String())
		}
		if sessionOf(h, req).VerifierSchemaFilter != "all" {
			t.Error("filter should default to all")
		}
		rr = httptest.NewRecorder()
		h.ShowVerify(rr, issueGET("/verifier/verify", false, cookies))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<!DOCTYPE html>") {
			t.Errorf("full page: %d", rr.Code)
		}
	})
}

func verifierBadForm(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/verifier/verify", strings.NewReader("schema_id=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func TestGenerateRequest(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://portal.example")
	t.Run("bad form", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr := httptest.NewRecorder()
		h.GenerateRequest(rr, verifierBadForm(cookies))
		if !strings.Contains(verifierToast(rr), "Bad form") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("no schema picked", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr, _ := verifierPost(h, h.GenerateRequest, url.Values{}, cookies)
		if !strings.Contains(verifierToast(rr), "pick a schema first") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("bad webhook", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr, _ := verifierPost(h, h.GenerateRequest, url.Values{"schema_id": {"diploma"}, "webhook_url": {"http://hooks.example"}}, cookies)
		if !strings.Contains(verifierToast(rr), "must use https") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("adapter error", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.verifyErr = errors.New("verifier offline")
		h, cookies := verifierSetup(t, ad, nil)
		rr, _ := verifierPost(h, h.GenerateRequest, url.Values{"schema_id": {"diploma"}}, cookies)
		if !strings.Contains(verifierToast(rr), "verifier offline") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("single credential request", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.verifyResult = backend.PresentationRequestResult{RequestURI: "openid4vp://req-1", State: "st-1"}
		h, cookies := verifierSetup(t, ad, nil)
		rr, sess := verifierPost(h, h.GenerateRequest, url.Values{
			"schema_id": {"diploma-sdjwt"}, "field_key": {"degree"}, "disclosure": {"selective"},
			"policy": {"signature"}, "webhook_url": {"https://203.0.113.9/hook"},
		}, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "openid4vp://req-1") {
			t.Fatalf("status %d body=%.300s", rr.Code, rr.Body.String())
		}
		if len(ad.presReqs) != 1 {
			t.Fatalf("requests = %d", len(ad.presReqs))
		}
		pr := ad.presReqs[0]
		if pr.WebhookURL != "https://203.0.113.9/hook" || strings.Join(pr.Policies, ",") != "signature" || pr.Template == nil || pr.Template.Vct != "https://issuer.example/vct/diploma" || pr.Template.WireFormat != "vc+sd-jwt" {
			t.Errorf("request = %+v tpl=%+v", pr, pr.Template)
		}
		if sess.CurrentOID4VPLink != "openid4vp://req-1" || sess.CurrentOID4VPState != "st-1" || sess.CurrentOID4VPTemplate != "custom" || sess.CustomOID4VPSchemaID != "diploma-sdjwt" {
			t.Errorf("session = %+v", sess)
		}
	})
	t.Run("default policies", func(t *testing.T) {
		ad := verifierNewAdapter()
		h, cookies := verifierSetup(t, ad, nil)
		verifierPost(h, h.GenerateRequest, url.Values{"schema_id": {"diploma"}}, cookies)
		if len(ad.presReqs) != 1 || strings.Join(ad.presReqs[0].Policies, ",") != "signature,expired,not-before" {
			t.Errorf("policies = %v", ad.presReqs)
		}
	})
	t.Run("delegation pair from picked schemas", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.verifyResult = backend.PresentationRequestResult{RequestURI: "openid4vp://pair", State: "st-2"}
		h, cookies := verifierSetup(t, ad, func(s *Session) {
			s.VerifierDelegSchemaID = "access-sdjwt"
			s.VerifierSubjectSchemaID = "person"
		})
		rr, sess := verifierPost(h, h.GenerateRequest, url.Values{"delegation": {"on"}}, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Presentation request · 2 credentials") {
			t.Fatalf("status %d body=%.400s", rr.Code, rr.Body.String())
		}
		pr := ad.presReqs[0]
		if pr.Template != nil || len(pr.Templates) != 2 || pr.Templates[0].Title != "Person" || pr.Templates[1].Title != "Access Grant SD" || len(pr.Templates[1].Fields) != 1 {
			t.Errorf("pair = %+v", pr.Templates)
		}
		if sess.CustomOID4VPTemplate == nil || sess.CustomOID4VPTemplate.Title != "Access Grant SD" {
			t.Errorf("session template = %+v", sess.CustomOID4VPTemplate)
		}
	})
	t.Run("delegation pair w3c from form + canonical defaults", func(t *testing.T) {
		ad := verifierNewAdapter()
		h, cookies := verifierSetup(t, ad, nil)
		verifierPost(h, h.GenerateRequest, url.Values{"delegation": {"on"}, "schema_id": {"access"}, "subject_schema_id": {"diploma"}}, cookies)
		pr := ad.presReqs[0]
		if len(pr.Templates) != 2 || strings.Join(pr.Templates[1].Fields, ",") != "onBehalfOf" || pr.Templates[0].Title != "Diploma" {
			t.Errorf("w3c pair = %+v", pr.Templates)
		}
		verifierPost(h, h.GenerateRequest, url.Values{"delegation": {"on"}}, cookies)
		pr = ad.presReqs[1]
		if len(pr.Templates) != 2 || pr.Templates[0].CredentialType != "BirthCertificate" || pr.Templates[1].CredentialType != "DelegatedAccessCredential" {
			t.Errorf("defaults = %+v", pr.Templates)
		}
	})
	t.Run("delegation leg errors", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr, _ := verifierPost(h, h.GenerateRequest, url.Values{"delegation": {"on"}, "schema_id": {"missing"}}, cookies)
		if !strings.Contains(verifierToast(rr), "delegation credential: unknown schema") {
			t.Errorf("deleg toast = %q", verifierToast(rr))
		}
		rr, _ = verifierPost(h, h.GenerateRequest, url.Values{"delegation": {"on"}, "schema_id": {"access"}, "subject_schema_id": {"missing"}}, cookies)
		if !strings.Contains(verifierToast(rr), "subject identity credential: unknown schema") {
			t.Errorf("subject toast = %q", verifierToast(rr))
		}
	})
}

func TestBuildVerifierTemplate(t *testing.T) {
	t.Run("no DPG redirects", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), func(s *Session) { s.VerifierDpg = "" })
		rr, _ := verifierPost(h, h.BuildVerifierTemplate, url.Values{}, cookies)
		if rr.Header().Get("HX-Redirect") != "/verifier/dpg" {
			t.Errorf("HX-Redirect = %q", rr.Header().Get("HX-Redirect"))
		}
	})
	t.Run("bad form", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr := httptest.NewRecorder()
		h.BuildVerifierTemplate(rr, verifierBadForm(cookies))
		if !strings.Contains(verifierToast(rr), "Bad form") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("schema error", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.schemasErr = errors.New("down")
		h, cookies := verifierSetup(t, ad, nil)
		rr, _ := verifierPost(h, h.BuildVerifierTemplate, url.Values{}, cookies)
		if !strings.Contains(verifierToast(rr), "Could not load schemas: down") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("filter, search and card pick", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr, sess := verifierPost(h, h.BuildVerifierTemplate, url.Values{"filter": {"sd_jwt_vc (IETF)"}, "q": {"person"}}, cookies)
		if rr.Code != 200 || sess.VerifierSchemaFilter != "sd_jwt_vc (IETF)" || sess.VerifierSchemaQuery != "person" {
			t.Fatalf("status %d sess=%+v", rr.Code, sess)
		}
		if !strings.Contains(rr.Body.String(), "Person") || strings.Contains(rr.Body.String(), "Access Grant SD") {
			t.Errorf("body=%.400s", rr.Body.String())
		}
		// Card pick: every field selected, preview stored.
		rr, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"schema_id": {"diploma"}, "q": {""}, "filter": {"all"}}, cookies)
		if rr.Code != 200 || sess.CustomOID4VPSchemaID != "diploma" || sess.CustomOID4VPTemplate == nil || strings.Join(sess.CustomOID4VPTemplate.Fields, ",") != "name,degree" {
			t.Fatalf("pick: %d %+v", rr.Code, sess.CustomOID4VPTemplate)
		}
		// Re-render keeps the user's valid checks and honours disclosure.
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"field_key": {"degree", "bogus"}, "disclosure": {"selective"}}, cookies)
		if strings.Join(sess.CustomOID4VPTemplate.Fields, ",") != "degree" || sess.CustomOID4VPTemplate.Disclosure != "selective — only degree shared" {
			t.Errorf("re-render: %+v", sess.CustomOID4VPTemplate)
		}
		// Re-render with no checks falls back to every field.
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"q": {"dip"}}, cookies)
		if strings.Join(sess.CustomOID4VPTemplate.Fields, ",") != "name,degree" {
			t.Errorf("fallback fields: %+v", sess.CustomOID4VPTemplate)
		}
	})
	t.Run("no pick keeps the grid", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), func(s *Session) { s.VerifierSchemaFilter = "" })
		rr, sess := verifierPost(h, h.BuildVerifierTemplate, url.Values{}, cookies)
		if rr.Code != 200 || sess.VerifierSchemaFilter != "all" || sess.CustomOID4VPTemplate != nil {
			t.Errorf("status %d sess=%+v", rr.Code, sess)
		}
	})
	t.Run("delegation two-step picker", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), func(s *Session) { s.CustomOID4VPSchemaID = "diploma" })
		rr, sess := verifierPost(h, h.BuildVerifierTemplate, url.Values{"delegation_toggle_fired": {"1"}, "delegation": {"on"}}, cookies)
		if rr.Code != 200 || !sess.VerifierDelegation || sess.CustomOID4VPSchemaID != "" {
			t.Fatalf("toggle: %d %+v", rr.Code, sess)
		}
		if !strings.Contains(rr.Body.String(), "Access Grant") || strings.Contains(rr.Body.String(), "Diploma") {
			t.Errorf("step 1 body=%.400s", rr.Body.String())
		}
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"schema_id": {"access"}}, cookies)
		if sess.VerifierDelegSchemaID != "access" || sess.VerifierSubjectSchemaID != "" {
			t.Errorf("step 1 pick: %+v", sess)
		}
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"schema_id": {"diploma"}}, cookies)
		if sess.VerifierDelegSchemaID != "access" || sess.VerifierSubjectSchemaID != "diploma" {
			t.Errorf("step 2 pick: %+v", sess)
		}
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"reset_subject": {"1"}, "schema_id": {"diploma"}}, cookies)
		if sess.VerifierDelegSchemaID != "access" || sess.VerifierSubjectSchemaID != "" {
			t.Errorf("reset subject: %+v", sess)
		}
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"reset_deleg": {"1"}}, cookies)
		if sess.VerifierDelegSchemaID != "" || sess.VerifierSubjectSchemaID != "" {
			t.Errorf("reset deleg: %+v", sess)
		}
		_, sess = verifierPost(h, h.BuildVerifierTemplate, url.Values{"delegation_toggle_fired": {"1"}}, cookies)
		if sess.VerifierDelegation {
			t.Error("toggle off should clear delegation mode")
		}
	})
}

func TestFetchResponse(t *testing.T) {
	t.Run("no request yet", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		rr, _ := verifierPost(h, h.FetchResponse, url.Values{}, cookies)
		if !strings.Contains(verifierToast(rr), "Generate a request first") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
	})
	t.Run("adapter error", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.fetchErr = errors.New("poll failed")
		h, cookies := verifierSetup(t, ad, func(s *Session) { s.CurrentOID4VPState = "st-1" })
		rr, _ := verifierPost(h, h.FetchResponse, url.Values{}, cookies)
		if !strings.Contains(verifierToast(rr), "poll failed") || ad.fetchState != "st-1" {
			t.Errorf("toast = %q state=%q", verifierToast(rr), ad.fetchState)
		}
	})
	t.Run("pending fills the preview from the custom template", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.fetchResult = backend.VerificationResult{Pending: true, Method: "OID4VP · "}
		h, cookies := verifierSetup(t, ad, func(s *Session) {
			s.CurrentOID4VPState = "st-1"
			s.CustomOID4VPTemplate = &vctypes.OID4VPTemplate{Title: "Diploma", Format: "w3c_vcdm_2", Fields: []string{"degree"}, Disclosure: "full credential shared"}
		})
		rr, _ := verifierPost(h, h.FetchResponse, url.Values{}, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "OID4VP · full credential shared") || !strings.Contains(rr.Body.String(), "w3c_vcdm_2") {
			t.Errorf("status %d body=%.400s", rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "fragment_verify_stop_polling") || strings.Contains(rr.Body.String(), "hx-swap-oob") {
			t.Error("pending must not stop polling")
		}
	})
	t.Run("terminal valid result logs an event", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.fetchResult = backend.VerificationResult{Valid: true, Issuer: "did:example:issuer", CredentialTitle: "Diploma", Method: "OID4VP · x", Format: "w3c_vcdm_2", Requested: []string{"degree"}}
		vlog := &pubVerifyLog{done: make(chan struct{})}
		h, cookies := verifierSetup(t, ad, func(s *Session) {
			s.CurrentOID4VPState = "st-1"
			s.CustomOID4VPSchemaID = "diploma"
			s.CustomOID4VPTemplate = &vctypes.OID4VPTemplate{Title: "Diploma"}
		})
		h.VerificationLog = vlog
		h.TrustRegistry = &verifierTrust{}
		rr, _ := verifierPost(h, h.FetchResponse, url.Values{}, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "hx-swap-oob") || !strings.Contains(rr.Body.String(), "Example University") {
			t.Errorf("status %d body=%.600s", rr.Code, rr.Body.String())
		}
		<-vlog.done
		if len(vlog.events) != 1 || vlog.events[0].Status != "valid" || vlog.events[0].TrustStatus != "trusted" || vlog.events[0].SchemaName != "Diploma" || vlog.events[0].VerifierDPG != verifierDPG {
			t.Errorf("event = %+v", vlog.events)
		}
	})
	t.Run("terminal invalid result without a custom template", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.fetchResult = backend.VerificationResult{Valid: false, Issuer: "did:example:issuer"}
		vlog := &pubVerifyLog{appendErr: errors.New("log down"), done: make(chan struct{})}
		h, cookies := verifierSetup(t, ad, func(s *Session) {
			s.CurrentOID4VPState = "st-1"
			s.CustomOID4VPSchemaID = "diploma"
		})
		h.VerificationLog = vlog
		rr, _ := verifierPost(h, h.FetchResponse, url.Values{}, cookies)
		if rr.Code != 200 {
			t.Errorf("status %d", rr.Code)
		}
		<-vlog.done
		if len(vlog.events) != 0 {
			t.Errorf("failed append must not record: %+v", vlog.events)
		}
	})
	t.Run("terminal result without a log", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.fetchResult = backend.VerificationResult{Valid: true}
		h, cookies := verifierSetup(t, ad, func(s *Session) { s.CurrentOID4VPState = "st-1" })
		rr, _ := verifierPost(h, h.FetchResponse, url.Values{}, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "hx-swap-oob") {
			t.Errorf("status %d body=%.300s", rr.Code, rr.Body.String())
		}
	})
}

// verifierMultipart builds a multipart POST of form fields plus, when image is
// non-empty, a credential_image PNG part.
func verifierMultipart(t *testing.T, fields map[string]string, image []byte, cookies []*http.Cookie) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("multipart field: %v", err)
		}
	}
	if len(image) > 0 {
		fw, err := mw.CreateFormFile("credential_image", "qr.png")
		if err != nil {
			t.Fatalf("multipart file: %v", err)
		}
		if _, err := fw.Write(image); err != nil {
			t.Fatalf("multipart file body: %v", err)
		}
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/verifier/direct", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("HX-Request", "true")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func TestVerifyDirect(t *testing.T) {
	t.Run("input validation", func(t *testing.T) {
		h, cookies := verifierSetup(t, verifierNewAdapter(), nil)
		for method, want := range map[string]string{
			"upload": "Could not read QR from upload",
			"paste":  "Paste a credential first",
			"scan":   "Scanner did not return a credential payload",
		} {
			rr, _ := verifierPost(h, h.VerifyDirect, url.Values{"method": {method}}, cookies)
			if !strings.Contains(verifierToast(rr), want) {
				t.Errorf("%s: toast = %q", method, verifierToast(rr))
			}
		}
	})
	t.Run("adapter error", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.directErr = errors.New("cannot parse")
		h, cookies := verifierSetup(t, ad, nil)
		rr, _ := verifierPost(h, h.VerifyDirect, url.Values{"method": {"paste"}, "credential_data": {" eyJ.abc "}}, cookies)
		if !strings.Contains(verifierToast(rr), "cannot parse") {
			t.Errorf("toast = %q", verifierToast(rr))
		}
		if len(ad.directReqs) != 1 || ad.directReqs[0].CredentialData != "eyJ.abc" || ad.directReqs[0].Method != "paste" || ad.directReqs[0].VerifierDpg != verifierDPG {
			t.Errorf("request = %+v", ad.directReqs)
		}
	})
	t.Run("valid multipart paste", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.directResult = backend.VerificationResult{Valid: true, Issuer: "did:example:issuer", CredentialTitle: "Diploma", Format: "w3c_vcdm_2"}
		h, cookies := verifierSetup(t, ad, nil)
		h.TrustRegistry = &verifierTrust{err: trust.ErrUntrusted}
		rr := httptest.NewRecorder()
		h.VerifyDirect(rr, verifierMultipart(t, map[string]string{"method": "paste", "credential_data": "eyJ.abc"}, nil, cookies))
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Example University") {
			t.Errorf("status %d body=%.600s", rr.Code, rr.Body.String())
		}
	})
	t.Run("upload decodes the QR image", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.directResult = backend.VerificationResult{Valid: true}
		h, cookies := verifierSetup(t, ad, nil)
		pngBytes, err := qrgen.Encode("eyJhbGciOiJFUzI1NiJ9.e30.sig", qrgen.Medium, 256)
		if err != nil {
			t.Fatalf("qr encode: %v", err)
		}
		rr := httptest.NewRecorder()
		h.VerifyDirect(rr, verifierMultipart(t, map[string]string{"method": "upload"}, pngBytes, cookies))
		if rr.Code != 200 || len(ad.directReqs) != 1 || ad.directReqs[0].CredentialData != "eyJhbGciOiJFUzI1NiJ9.e30.sig" || ad.directReqs[0].Method != "upload" {
			t.Errorf("status %d reqs=%+v", rr.Code, ad.directReqs)
		}
	})
	t.Run("invalid scan", func(t *testing.T) {
		ad := verifierNewAdapter()
		ad.directResult = backend.VerificationResult{Valid: false}
		h, cookies := verifierSetup(t, ad, nil)
		rr, _ := verifierPost(h, h.VerifyDirect, url.Values{"method": {"scan"}, "credential_data": {"qr-payload"}}, cookies)
		if rr.Code != 200 || rr.Header().Get("HX-Trigger") != "" {
			t.Errorf("status %d toast=%q", rr.Code, verifierToast(rr))
		}
	})
}
