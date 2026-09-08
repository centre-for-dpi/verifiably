package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/vctypes"
)

// issueAdapter is the fake backend for the single-issue and bulk-issue
// handlers (issuance.go, bulk.go). Unimplemented methods panic (nil embed).
type issueAdapter struct {
	backend.Adapter
	schemas    []vctypes.Schema
	schemasErr error
	dpgs       map[string]vctypes.DPG
	dpgsErr    error
	prefill    map[string]string
	walletRes  backend.IssueToWalletResult
	walletErr  error
	pdfRes     backend.IssueAsPDFResult
	pdfErr     error
	bulkRes    backend.IssueBulkResult
	bulkErr    error
	resolve    func(vctypes.Schema) vctypes.Schema // optional schemaFieldResolver hook

	issueReqs []backend.IssueRequest
	bulkReqs  []backend.IssueBulkRequest
}

func (a *issueAdapter) ListAllSchemas(context.Context) ([]vctypes.Schema, error) {
	return a.schemas, a.schemasErr
}
func (a *issueAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.dpgs, a.dpgsErr
}
func (a *issueAdapter) PrefillSubjectFields(context.Context, vctypes.Schema) (map[string]string, error) {
	if a.prefill == nil {
		return nil, nil
	}
	out := map[string]string{}
	for k, v := range a.prefill {
		out[k] = v
	}
	return out, nil
}
func (a *issueAdapter) IssueToWallet(_ context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	a.issueReqs = append(a.issueReqs, req)
	return a.walletRes, a.walletErr
}
func (a *issueAdapter) IssueAsPDF(_ context.Context, req backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	a.issueReqs = append(a.issueReqs, req)
	return a.pdfRes, a.pdfErr
}
func (a *issueAdapter) IssueBulk(_ context.Context, req backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	a.bulkReqs = append(a.bulkReqs, req)
	return a.bulkRes, a.bulkErr
}
func (a *issueAdapter) ResolveSchemaFields(s vctypes.Schema) vctypes.Schema {
	if a.resolve != nil {
		return a.resolve(s)
	}
	return s
}

// issuePersonSchema is a generic two-field schema with a required name.
func issuePersonSchema() vctypes.Schema {
	return vctypes.Schema{ID: "person", Name: "Person", Std: "w3c_vcdm_2",
		FieldsSpec: []vctypes.FieldSpec{{Name: "name", Required: true}, {Name: "birthDate", Format: "date"}}}
}

// issueH builds an H over issuer_issue + issuer_mode with a seeded issuer session.
func issueH(t *testing.T, ad *issueAdapter, mutate func(*Session)) (*H, []*http.Cookie) {
	t.Helper()
	h := &H{Adapter: ad, Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_issue", "issuer_mode"), StatusLists: NewStatusListSet()}
	cookies := seedSession(t, h, func(s *Session) {
		s.IssuerDpg = "Example DPG"
		s.SchemaID = "person"
		s.Scale = "single"
		s.Dest = "wallet"
		if mutate != nil {
			mutate(s)
		}
	})
	return h, cookies
}

func issueGET(path string, htmx bool, cookies []*http.Cookie) *http.Request {
	var req *http.Request
	if htmx {
		req = htmxMainRequest(http.MethodGet, path)
	} else {
		req = httptest.NewRequest(http.MethodGet, path, nil)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func sessionOf(h *H, req *http.Request) *Session {
	return h.Sessions.MustGet(httptest.NewRecorder(), req)
}

func TestInjiPreAuthUnsupported(t *testing.T) {
	const pre = "Inji Certify · Pre-Auth"
	if !injiPreAuthWalletUnsupported(pre, "w3c_vcdm_2") || injiPreAuthWalletUnsupported(pre, "sd_jwt_vc") || injiPreAuthWalletUnsupported("Example DPG", "w3c_vcdm_2") {
		t.Fatal("wallet-unsupported predicate wrong")
	}
	if !injiPreAuthPdfUnsupported(pre, "sd_jwt_vc (IETF)") || injiPreAuthPdfUnsupported(pre, "w3c_vcdm_2") || injiPreAuthPdfUnsupported("Example DPG", "sd_jwt_vc") {
		t.Fatal("pdf-unsupported predicate wrong")
	}
}

func TestShowIssuanceMode(t *testing.T) {
	const pre = "Inji Certify · Pre-Auth"
	t.Run("no DPG/schema → redirect", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{}, func(s *Session) { s.SchemaID = "" })
		rr := httptest.NewRecorder()
		h.ShowIssuanceMode(rr, issueGET("/issuer/mode", true, cookies))
		if rr.Header().Get("HX-Redirect") != "/issuer/dpg" {
			t.Fatalf("HX-Redirect=%q status=%d", rr.Header().Get("HX-Redirect"), rr.Code)
		}
	})
	t.Run("ListIssuerDpgs error → toast", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{dpgsErr: errors.New("catalog down")}, nil)
		rr := httptest.NewRecorder()
		h.ShowIssuanceMode(rr, issueGET("/issuer/mode", false, cookies))
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "catalog down") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("pdf forced to wallet when DPG lacks DirectPDF; bulk-only forces bulk", func(t *testing.T) {
		ad := &issueAdapter{dpgs: map[string]vctypes.DPG{"Example DPG": {Vendor: "Example", BulkOnly: true}}, schemasErr: errors.New("skip")}
		h, cookies := issueH(t, ad, func(s *Session) { s.Dest = "pdf" })
		req := issueGET("/issuer/mode", true, cookies)
		rr := httptest.NewRecorder()
		h.ShowIssuanceMode(rr, req)
		sess := sessionOf(h, req)
		if rr.Code != 200 || sess.Dest != "wallet" || sess.Scale != "bulk" {
			t.Fatalf("status=%d dest=%q scale=%q", rr.Code, sess.Dest, sess.Scale)
		}
		if body := rr.Body.String(); !strings.Contains(body, `option-card disabled`) || !strings.Contains(body, "not for Example") {
			t.Fatalf("body=%s", body)
		}
	})
	t.Run("pre-auth W3C blocks wallet and forces pdf", func(t *testing.T) {
		ad := &issueAdapter{dpgs: map[string]vctypes.DPG{pre: {Vendor: "Inji", DirectPDF: true}}, schemas: []vctypes.Schema{issuePersonSchema()}}
		h, cookies := issueH(t, ad, func(s *Session) { s.IssuerDpg = pre })
		req := issueGET("/issuer/mode", false, cookies)
		rr := httptest.NewRecorder()
		h.ShowIssuanceMode(rr, req)
		if sess := sessionOf(h, req); sess.Dest != "pdf" {
			t.Fatalf("dest=%q", sess.Dest)
		}
		if body := rr.Body.String(); !strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "mobile wallets cannot accept") {
			t.Fatalf("body=%s", body)
		}
	})
	t.Run("pre-auth SD-JWT blocks pdf and forces wallet", func(t *testing.T) {
		s := issuePersonSchema()
		s.Std = "sd_jwt_vc (IETF)"
		ad := &issueAdapter{dpgs: map[string]vctypes.DPG{pre: {Vendor: "Inji", DirectPDF: true}}, schemas: []vctypes.Schema{s}}
		h, cookies := issueH(t, ad, func(s *Session) { s.IssuerDpg = pre; s.Dest = "pdf" })
		req := issueGET("/issuer/mode", true, cookies)
		rr := httptest.NewRecorder()
		h.ShowIssuanceMode(rr, req)
		if sess := sessionOf(h, req); sess.Dest != "wallet" {
			t.Fatalf("dest=%q", sess.Dest)
		}
		if body := rr.Body.String(); !strings.Contains(body, "QR-on-PDF is not supported for SD-JWT") {
			t.Fatalf("body=%s", body)
		}
	})
}

func TestSetIssuanceMode(t *testing.T) {
	const pre = "Inji Certify · Pre-Auth"
	t.Run("sets scale/dest and redirects", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{dpgsErr: errors.New("x"), schemasErr: errors.New("x")}, nil)
		req := formPost("/issuer/mode", url.Values{"scale": {"bulk"}, "dest": {"pdf"}}, cookies...)
		rr := httptest.NewRecorder()
		h.SetIssuanceMode(rr, req)
		sess := sessionOf(h, req)
		if rr.Header().Get("HX-Redirect") != "/issuer/issue" || sess.Scale != "bulk" || sess.Dest != "pdf" {
			t.Fatalf("redirect=%q scale=%q dest=%q", rr.Header().Get("HX-Redirect"), sess.Scale, sess.Dest)
		}
	})
	t.Run("bulk-only guard + pre-auth W3C guard", func(t *testing.T) {
		ad := &issueAdapter{dpgs: map[string]vctypes.DPG{pre: {BulkOnly: true}}, schemas: []vctypes.Schema{issuePersonSchema()}}
		h, cookies := issueH(t, ad, func(s *Session) { s.IssuerDpg = pre })
		req := formPost("/issuer/mode", url.Values{"scale": {"single"}, "dest": {"wallet"}}, cookies...)
		h.SetIssuanceMode(httptest.NewRecorder(), req)
		sess := sessionOf(h, req)
		if sess.Scale != "bulk" || sess.Dest != "pdf" {
			t.Fatalf("scale=%q dest=%q", sess.Scale, sess.Dest)
		}
	})
	t.Run("pre-auth SD-JWT guard", func(t *testing.T) {
		s := issuePersonSchema()
		s.Std = "sd_jwt_vc"
		ad := &issueAdapter{dpgs: map[string]vctypes.DPG{}, schemas: []vctypes.Schema{s}}
		h, cookies := issueH(t, ad, func(s *Session) { s.IssuerDpg = pre })
		req := formPost("/issuer/mode", url.Values{"dest": {"pdf"}}, cookies...)
		h.SetIssuanceMode(httptest.NewRecorder(), req)
		if sess := sessionOf(h, req); sess.Dest != "wallet" {
			t.Fatalf("dest=%q", sess.Dest)
		}
	})
}

func TestShowIssue(t *testing.T) {
	t.Run("no DPG → redirect", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{}, func(s *Session) { s.IssuerDpg = "" })
		rr := httptest.NewRecorder()
		h.ShowIssue(rr, issueGET("/issuer/issue", false, cookies))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/issuer/dpg" {
			t.Fatalf("status=%d loc=%q", rr.Code, rr.Header().Get("Location"))
		}
	})
	t.Run("backend error / schema missing → toast", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{schemasErr: errors.New("down")}, nil)
		rr := httptest.NewRecorder()
		h.ShowIssue(rr, issueGET("/issuer/issue", true, cookies))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "backend unavailable: down") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
		h, cookies = issueH(t, &issueAdapter{schemas: []vctypes.Schema{{ID: "other"}}}, nil)
		rr = httptest.NewRecorder()
		h.ShowIssue(rr, issueGET("/issuer/issue", true, cookies))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "selected schema missing") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("single scale: identity claims overlay prefill, resolver applied, sources rendered", func(t *testing.T) {
		resolved := false
		ad := &issueAdapter{
			schemas: []vctypes.Schema{issuePersonSchema()},
			dpgs:    map[string]vctypes.DPG{"Example DPG": {Vendor: "Example", Capabilities: []vctypes.Capability{{Kind: "data", Key: "api", Title: "Secured API", Body: "pull"}, {Kind: "other", Key: "x"}}}},
			prefill: map[string]string{"name": "Demo Name", "birthDate": "1990-01-01"},
			resolve: func(s vctypes.Schema) vctypes.Schema { resolved = true; return s },
		}
		h, cookies := issueH(t, ad, func(s *Session) { s.UserClaims = map[string]string{"name": "Ada Lovelace"} })
		rr := httptest.NewRecorder()
		h.ShowIssue(rr, issueGET("/issuer/issue", false, cookies))
		body := rr.Body.String()
		if rr.Code != 200 || !resolved || !strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "<em>Person</em>") ||
			!strings.Contains(body, `value="Ada Lovelace"`) || !strings.Contains(body, `value="1990-01-01"`) || !strings.Contains(body, ">Secured API</button>") {
			t.Fatalf("status=%d resolved=%v body=%s", rr.Code, resolved, body)
		}
	})
	t.Run("bulk scale: stale BulkSource falls back to the first allowed chip; registries from env", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg1","label":"Example Registry","url":"https://registry.example","entity":"Person"}]`)
		ad := &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, dpgs: map[string]vctypes.DPG{"Example DPG": dpgWithBulk("db", "api")}}
		h, cookies := issueH(t, ad, func(s *Session) { s.Scale = "bulk"; s.BulkSource = "csv" })
		req := issueGET("/issuer/issue", true, cookies)
		rr := httptest.NewRecorder()
		h.ShowIssue(rr, req)
		body := rr.Body.String()
		if sess := sessionOf(h, req); sess.BulkSource != "db" {
			t.Fatalf("BulkSource=%q", sess.BulkSource)
		}
		if strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, "bulk issuance") || !strings.Contains(body, `id="bulk-area"`) {
			t.Fatalf("body=%s", body)
		}
	})
	t.Run("bulk scale: empty BulkSource defaults to csv (fallback chips)", func(t *testing.T) {
		ad := &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, dpgs: map[string]vctypes.DPG{}}
		h, cookies := issueH(t, ad, func(s *Session) { s.Scale = "bulk"; s.BulkSource = "" })
		req := issueGET("/issuer/issue", true, cookies)
		rr := httptest.NewRecorder()
		h.ShowIssue(rr, req)
		if sess := sessionOf(h, req); sess.BulkSource != "" {
			t.Fatalf("session BulkSource must stay untouched when csv is allowed, got %q", sess.BulkSource)
		}
		if body := rr.Body.String(); !strings.Contains(body, "CSV upload") || !strings.Contains(body, "Database") {
			t.Fatalf("fallback chips missing: %s", body)
		}
	})
}

func TestPrefillValues(t *testing.T) {
	schema := issuePersonSchema()
	sess := &Session{UserClaims: map[string]string{"name": "Ada"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h := &H{Adapter: &issueAdapter{}}
	if got := h.prefillValues(req, schema, sess); got["name"] != "Ada" || len(got) != 1 {
		t.Fatalf("nil adapter prefill: %v", got)
	}
	h = &H{Adapter: &issueAdapter{prefill: map[string]string{"name": "x", "birthDate": "d"}}}
	if got := h.prefillValues(req, schema, sess); got["name"] != "Ada" || got["birthDate"] != "d" {
		t.Fatalf("overlay: %v", got)
	}
	if got := h.prefillValues(req, schema, &Session{}); got["name"] != "x" {
		t.Fatalf("no claims: %v", got)
	}
}

func TestSourcesFromCapabilities(t *testing.T) {
	out := sourcesFromCapabilities(vctypes.DPG{Capabilities: []vctypes.Capability{{Kind: "bulk_source", Key: "csv"}, {Kind: "data", Key: "api", Title: "API", Body: "hint"}}})
	if len(out) != 2 || out[0].Key != "manual" || out[1].Key != "api" || out[1].Hint != "hint" {
		t.Fatalf("out=%+v", out)
	}
}

func TestSubmitIssue(t *testing.T) {
	post := func(h *H, v url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.SubmitIssue(rr, formPost("/issuer/issue", v, cookies...))
		return rr
	}
	trigger := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }

	t.Run("session expired", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{}, func(s *Session) { s.IssuerDpg = ""; s.SchemaID = "" })
		if rr := post(h, url.Values{}, cookies); !strings.Contains(trigger(rr), "Session expired") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
	})
	t.Run("backend error (form values re-sync the session)", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{schemasErr: errors.New("down")}, func(s *Session) { s.IssuerDpg = ""; s.SchemaID = "" })
		req := formPost("/issuer/issue", url.Values{"issuer_dpg": {"Form DPG"}, "schema_id": {"person"}}, cookies...)
		rr := httptest.NewRecorder()
		h.SubmitIssue(rr, req)
		if sess := sessionOf(h, req); !strings.Contains(trigger(rr), "backend unavailable: down") || sess.IssuerDpg != "Form DPG" || sess.SchemaID != "person" {
			t.Fatalf("trigger=%q sess=%+v", trigger(rr), sess)
		}
	})
	t.Run("missing required field", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}}, nil)
		if rr := post(h, url.Values{"field_name": {"  "}}, cookies); !strings.Contains(trigger(rr), "Fill in required fields: name") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
	})
	t.Run("validity window rejected", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}}, nil)
		if rr := post(h, url.Values{"field_name": {"Ada"}, "valid_until": {"2030-01-01"}}, cookies); !strings.Contains(trigger(rr), "does not declare an expiry") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
	})
	t.Run("wallet: allocation error, adapter error, success", func(t *testing.T) {
		ad := &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, walletErr: errors.New("walt 502")}
		h, cookies := issueH(t, ad, nil)
		store := &slFakeStore{id: "v1", allocErr: errors.New("full")}
		h.StatusLists.Register(&StatusListEntry{Store: store, Kind: "bitstring"})
		if rr := post(h, url.Values{"field_name": {"Ada"}}, cookies); !strings.Contains(trigger(rr), "status list allocate: full") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
		store.allocErr = nil
		store.allocIndex = 42
		if rr := post(h, url.Values{"field_name": {"Ada"}}, cookies); !strings.Contains(trigger(rr), "walt 502") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
		ad.walletErr = nil
		ad.walletRes = backend.IssueToWalletResult{OfferURI: "openid-credential-offer://example?x=1", Flow: "pre_auth", PIN: "1234"}
		log := issuedLog(t)
		h.IssuanceLog = log
		rr := post(h, url.Values{"field_name": {"Ada"}, "field_birthDate": {"1990-05-06"}, "tz_offset": {"330"}}, cookies)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "Credential offer generated") || !strings.Contains(body, "openid-credential-offer://example?x=1") || !strings.Contains(body, ">1234</div>") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		req := ad.issueReqs[len(ad.issueReqs)-1]
		if req.SubjectData["birthDate"] != "1990-05-05T18:30:00Z" || req.StatusList == nil || req.StatusList.Index != 42 || req.IssuerDpg != "Example DPG" {
			t.Fatalf("req=%+v", req)
		}
		items := log.List(issuance.Filter{})
		if len(items) != 1 || items[0].HolderHint != "Ada" || items[0].OfferURI != "openid-credential-offer://example?x=1" || items[0].StatusList.Index != 42 {
			t.Fatalf("log=%+v", items)
		}
	})
	t.Run("pdf: allocation error, adapter error, success", func(t *testing.T) {
		ad := &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, pdfErr: errors.New("pdf failed")}
		h, cookies := issueH(t, ad, func(s *Session) { s.Dest = "pdf" })
		store := &slFakeStore{id: "v1", allocErr: errors.New("full")}
		h.StatusLists.Register(&StatusListEntry{Store: store, Kind: "bitstring"})
		if rr := post(h, url.Values{"field_name": {"Ada"}}, cookies); !strings.Contains(trigger(rr), "status list allocate: full") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
		store.allocErr = nil
		if rr := post(h, url.Values{"field_name": {"Ada"}}, cookies); !strings.Contains(trigger(rr), "pdf failed") {
			t.Fatalf("trigger=%q", trigger(rr))
		}
		ad.pdfErr = nil
		ad.pdfRes = backend.IssueAsPDFResult{IssuerName: "Example Issuer", IssuerDID: "did:web:issuer.example", PayloadSizeKB: 3, DownloadID: "dl-1"}
		log := issuedLog(t)
		h.IssuanceLog = log
		rr := post(h, url.Values{"field_name": {"Ada"}}, cookies)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "PDF credential generated") || !strings.Contains(body, "Person — ready to print") || !strings.Contains(body, "did:web:issuer.example") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		if items := log.List(issuance.Filter{}); len(items) != 1 || items[0].OfferURI != "" || items[0].StatusList == nil {
			t.Fatalf("log=%+v", items)
		}
	})
}

func TestSetSingleSource(t *testing.T) {
	t.Run("backend error", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{schemasErr: errors.New("down")}, nil)
		rr := httptest.NewRecorder()
		h.SetSingleSource(rr, formPost("/issuer/issue/source", url.Values{}, cookies...))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "backend unavailable: down") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("empty source → manual form; explicit source echoed", func(t *testing.T) {
		ad := &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, dpgs: map[string]vctypes.DPG{"Example DPG": {Capabilities: []vctypes.Capability{{Kind: "data", Key: "api", Title: "API"}}}}, prefill: map[string]string{"name": "Demo"}}
		h, cookies := issueH(t, ad, nil)
		rr := httptest.NewRecorder()
		h.SetSingleSource(rr, formPost("/issuer/issue/source", url.Values{}, cookies...))
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, `id="single-form-wrap"`) || !strings.Contains(body, `name="field_name"`) || !strings.Contains(body, `value="Demo"`) {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		rr = httptest.NewRecorder()
		h.SetSingleSource(rr, formPost("/issuer/issue/source", url.Values{"source": {"api"}}, cookies...))
		if body := rr.Body.String(); strings.Contains(body, `name="field_name"`) {
			t.Fatalf("api source must not render the manual field inputs: %s", body)
		}
	})
}

func TestPreviewPDF(t *testing.T) {
	t.Run("backend error / adapter error", func(t *testing.T) {
		h, cookies := issueH(t, &issueAdapter{schemasErr: errors.New("down")}, nil)
		rr := httptest.NewRecorder()
		h.PreviewPDF(rr, formPost("/issuer/issue/preview", url.Values{}, cookies...))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "backend unavailable: down") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
		h, cookies = issueH(t, &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, pdfErr: errors.New("render failed")}, nil)
		rr = httptest.NewRecorder()
		h.PreviewPDF(rr, formPost("/issuer/issue/preview", url.Values{}, cookies...))
		if !strings.Contains(rr.Header().Get("HX-Trigger"), "render failed") {
			t.Fatalf("trigger=%q", rr.Header().Get("HX-Trigger"))
		}
	})
	t.Run("renders the modal", func(t *testing.T) {
		ad := &issueAdapter{schemas: []vctypes.Schema{issuePersonSchema()}, prefill: map[string]string{"name": "Demo"},
			pdfRes: backend.IssueAsPDFResult{IssuerName: "Example Issuer", IssuerDID: "did:web:issuer.example", Fields: map[string]string{"name": "Demo"}, PayloadSizeKB: 2}}
		h, cookies := issueH(t, ad, nil)
		rr := httptest.NewRecorder()
		h.PreviewPDF(rr, formPost("/issuer/issue/preview", url.Values{}, cookies...))
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "PDF preview — Person") || !strings.Contains(body, "<dd>Demo</dd>") || ad.issueReqs[0].SubjectData["name"] != "Demo" {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
	})
}

func TestBulkSourcesForAndAllowed(t *testing.T) {
	declared := bulkSourcesFor(vctypes.DPG{Capabilities: []vctypes.Capability{
		{Kind: "bulk_source", Key: "registry", Title: "Registry", Body: "r"},
		{Kind: "bulk_source", Key: "ftp", Title: "nope"},
		{Kind: "data", Key: "csv"},
		{Kind: "bulk_source", Key: "csv", Title: "CSV", Body: "c"},
	}})
	if len(declared) != 2 || declared[0].Key != "registry" || declared[1].Label != "CSV" {
		t.Fatalf("declared=%+v", declared)
	}
	fallback := bulkSourcesFor(vctypes.DPG{})
	if len(fallback) != 3 || fallback[0].Key != "csv" || fallback[1].Key != "api" || fallback[2].Key != "db" {
		t.Fatalf("fallback=%+v", fallback)
	}
	if !bulkSourceAllowed("api", fallback) || bulkSourceAllowed("registry", fallback) {
		t.Fatal("bulkSourceAllowed wrong")
	}
}
