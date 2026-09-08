package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/schemacache"
	"github.com/verifiably/verifiably-go/internal/statuslistcache"
	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/internal/verification"
	"github.com/verifiably/verifiably-go/vctypes"
)

// pubVerifySchemas: one custom W3C schema with an SD-JWT variant plus one
// non-custom catalog schema (hidden on the public portal).
func pubVerifySchemas() []vctypes.Schema {
	return []vctypes.Schema{
		{ID: "diploma", Name: "Diploma", Desc: "University degree", Std: "w3c_vcdm_2", Custom: true, SourceDeployment: "ver1",
			FieldsSpec: []vctypes.FieldSpec{{Name: "name"}, {Name: "degree"}},
			Variants:   []vctypes.SchemaVariant{{ID: "diploma", Std: "w3c_vcdm_2", Format: "ldp_vc", CanPresent: true}, {ID: "diploma-sdjwt", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", CanPresent: true}}},
		{ID: "catalog-id", Name: "Catalog ID", Std: "w3c_vcdm_2", FieldsSpec: []vctypes.FieldSpec{{Name: "id"}}},
	}
}

func pubVerifyH(t *testing.T, ad backend.Adapter) *H {
	t.Helper()
	return &H{Adapter: ad, Sessions: NewStore(), Templates: loadPublicTemplates(t)}
}

// pubVerifyLog closes done on the first Append so tests can wait on the
// fire-and-forget goroutine without sleeping.
type pubVerifyLog struct {
	mockVerificationLog
	appendErr error
	done      chan struct{}
	once      sync.Once
}

func (l *pubVerifyLog) Append(ctx context.Context, e verification.Event) error {
	defer l.once.Do(func() { close(l.done) })
	if l.appendErr != nil {
		return l.appendErr
	}
	return l.mockVerificationLog.Append(ctx, e)
}

type pubVerifySLCache struct {
	res  statuslistcache.Result
	err  error
	urls []string
}

func (c *pubVerifySLCache) Fetch(_ context.Context, _ string, listURL string) (statuslistcache.Result, error) {
	c.urls = append(c.urls, listURL)
	return c.res, c.err
}

func TestRenderPublicPage(t *testing.T) {
	h := pubVerifyH(t, &delegAPIAdapter{})
	body := publicVerifyData(&Session{PublicVerifyFilter: "all"}, nil)

	t.Run("full page vs HTMX fragment", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.renderPublicPage(rr, httptest.NewRequest(http.MethodGet, "/verify", nil), "verify", body)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<!DOCTYPE") || !strings.Contains(rr.Body.String(), "<title>Verify credential") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		rr = httptest.NewRecorder()
		h.renderPublicPage(rr, htmxMainRequest(http.MethodGet, "/verify"), "verify", body)
		if rr.Code != 200 || strings.Contains(rr.Body.String(), "<!DOCTYPE") || !strings.Contains(rr.Body.String(), `name="schema_id"`) {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("unknown page → 500 (plain and translating)", func(t *testing.T) {
		// An undefined fragment fails before any byte is written, so the
		// 500 is observable (a layout failure mid-stream would already be 200).
		rr := httptest.NewRecorder()
		h.renderPublicPage(rr, htmxMainRequest(http.MethodGet, "/verify"), "nope", body)
		if rr.Code != 500 {
			t.Fatalf("status=%d", rr.Code)
		}
		th := pubVerifyH(t, &delegAPIAdapter{})
		th.Translator = &i18nUpperTranslator{}
		rr = httptest.NewRecorder()
		req := htmxMainRequest(http.MethodGet, "/verify")
		req.AddCookie(&http.Cookie{Name: "verifiably_lang", Value: "es"})
		th.renderPublicPage(rr, req, "nope", body)
		if rr.Code != 500 {
			t.Fatalf("translating status=%d", rr.Code)
		}
	})
	t.Run("non-English is translated", func(t *testing.T) {
		th := pubVerifyH(t, &delegAPIAdapter{})
		th.Translator = &i18nUpperTranslator{}
		rr := httptest.NewRecorder()
		req := htmxMainRequest(http.MethodGet, "/verify")
		req.AddCookie(&http.Cookie{Name: "verifiably_lang", Value: "es"})
		th.renderPublicPage(rr, req, "verify", body)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "YOUR DOCUMENT") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestPublicPageTitle(t *testing.T) {
	if publicPageTitle("verify") != "Verify credential" || publicPageTitle("x") != "Verification" {
		t.Fatal("publicPageTitle wrong")
	}
}

func TestPublicSchemas(t *testing.T) {
	h := pubVerifyH(t, &delegAPIAdapter{testAdapter: testAdapter{schemas: pubVerifySchemas()}})
	got := h.publicSchemas(context.Background())
	if len(got) != 1 || got[0].ID != "diploma" {
		t.Fatalf("adapter path: %+v", got)
	}
	h.SchemaCache = schemacache.NewAggregator(time.Minute, nil)
	if got := h.publicSchemas(context.Background()); len(got) != 0 {
		t.Fatalf("hub path must read the (empty) cache: %+v", got)
	}
}

func TestPublicVerifyData(t *testing.T) {
	schemas := pubVerifySchemas()
	d := publicVerifyData(&Session{PublicVerifyFilter: "all"}, schemas)
	stds := d["Stds"].([]string)
	if len(d["Schemas"].([]vctypes.Schema)) != 1 || len(d["AllSchemas"].([]vctypes.Schema)) != 1 || len(stds) != 3 || stds[1] != "w3c_vcdm_2" || stds[2] != "sd_jwt_vc (IETF)" {
		t.Fatalf("all: %+v", d)
	}
	d = publicVerifyData(&Session{PublicVerifyFilter: "sd_jwt_vc (IETF)", PublicVerifyQuery: "DEGREE"}, schemas)
	got := d["Schemas"].([]vctypes.Schema)
	if len(got) != 1 || got[0].Std != "sd_jwt_vc (IETF)" {
		t.Fatalf("filter+query: %+v", got)
	}
	d = publicVerifyData(&Session{PublicVerifyFilter: "all", PublicVerifyQuery: "nothing-matches"}, schemas)
	if len(d["Schemas"].([]vctypes.Schema)) != 0 {
		t.Fatalf("query miss: %+v", d["Schemas"])
	}
	d = publicVerifyData(&Session{PublicVerifyFilter: "mso_mdoc"}, schemas)
	if len(d["Schemas"].([]vctypes.Schema)) != 0 {
		t.Fatalf("std miss: %+v", d["Schemas"])
	}
}

func TestShowPublicVerify(t *testing.T) {
	h := pubVerifyH(t, &delegAPIAdapter{testAdapter: testAdapter{schemas: pubVerifySchemas()}})
	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	rr := httptest.NewRecorder()
	h.ShowPublicVerify(rr, req)
	sess := h.Sessions.MustGet(httptest.NewRecorder(), req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Diploma") || strings.Contains(rr.Body.String(), "Catalog ID") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if cookies := rr.Result().Cookies(); len(cookies) == 0 {
		t.Fatal("session cookie expected")
	} else {
		req2 := httptest.NewRequest(http.MethodGet, "/verify", nil)
		req2.AddCookie(cookies[0])
		sess = h.Sessions.MustGet(httptest.NewRecorder(), req2)
	}
	if sess.PublicVerifyFilter != "all" {
		t.Fatalf("filter=%q", sess.PublicVerifyFilter)
	}
}

func TestBuildPublicVerifyTemplate(t *testing.T) {
	h := pubVerifyH(t, &delegAPIAdapter{testAdapter: testAdapter{schemas: pubVerifySchemas()}})
	cookies := seedSession(t, h, nil)
	post := func(v url.Values) (*httptest.ResponseRecorder, *Session) {
		req := formPost("/verify/build", v, cookies...)
		rr := httptest.NewRecorder()
		h.BuildPublicVerifyTemplate(rr, req)
		return rr, h.Sessions.MustGet(httptest.NewRecorder(), req)
	}

	t.Run("bad form", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/verify/build", strings.NewReader("a=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.BuildPublicVerifyTemplate(rr, req)
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "Bad form") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("fresh session defaults the filter to all", func(t *testing.T) {
		rr, sess := post(url.Values{"q": {""}})
		if rr.Code != 200 || sess.PublicVerifyFilter != "all" || sess.PublicVerifyQuery != "" {
			t.Fatalf("status=%d sess=%+v", rr.Code, sess)
		}
	})
	t.Run("filter + query without a pick", func(t *testing.T) {
		rr, sess := post(url.Values{"filter": {"w3c_vcdm_2"}, "q": {"dipl"}})
		if rr.Code != 200 || sess.PublicVerifyFilter != "w3c_vcdm_2" || sess.PublicVerifyQuery != "dipl" || sess.PublicVerifyTemplate != nil {
			t.Fatalf("status=%d sess=%+v", rr.Code, sess)
		}
		if !strings.Contains(rr.Body.String(), `chip small active"`) {
			t.Fatalf("body=%s", rr.Body.String())
		}
	})
	t.Run("unknown schema id leaves the template unset", func(t *testing.T) {
		_, sess := post(url.Values{"schema_id": {"ghost"}})
		if sess.PublicVerifyTemplate != nil || sess.PublicVerifySchemaID != "ghost" {
			t.Fatalf("sess=%+v", sess)
		}
	})
	t.Run("pick a variant → all fields; re-render keeps valid checked fields", func(t *testing.T) {
		rr, sess := post(url.Values{"schema_id": {"diploma-sdjwt"}, "disclosure": {"selective"}})
		tpl := sess.PublicVerifyTemplate
		if tpl == nil || tpl.Format != "sd_jwt_vc (IETF)" || len(tpl.Fields) != 2 || !strings.HasPrefix(tpl.Disclosure, "selective") {
			t.Fatalf("tpl=%+v", tpl)
		}
		if !strings.Contains(rr.Body.String(), "<strong>Diploma</strong>") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		_, sess = post(url.Values{"field_key": {"degree", "bogus"}})
		if tpl := sess.PublicVerifyTemplate; len(tpl.Fields) != 1 || tpl.Fields[0] != "degree" {
			t.Fatalf("tpl=%+v", tpl)
		}
		_, sess = post(url.Values{"field_key": {"bogus"}})
		if tpl := sess.PublicVerifyTemplate; len(tpl.Fields) != 2 {
			t.Fatalf("all-invalid keys must fall back to every field: %+v", tpl)
		}
	})
}

func TestPublicVerifyRequest(t *testing.T) {
	newH := func(t *testing.T, ad *delegAPIAdapter) *H { return pubVerifyH(t, ad) }
	post := func(h *H, v url.Values) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.PublicVerifyRequest(rr, formPost("/verify/request", v))
		return rr
	}
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	okAdapter := func() *delegAPIAdapter {
		return &delegAPIAdapter{testAdapter: testAdapter{schemas: pubVerifySchemas(), verifyResult: backend.PresentationRequestResult{RequestURI: "openid4vp://req", State: "st-1"}}}
	}

	t.Run("rate limited", func(t *testing.T) {
		h := newH(t, okAdapter())
		h.RateLimiter = &RateLimiter{keyLimit: 1, ipLimit: 1, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
		post(h, url.Values{"schema_id": {"diploma"}})
		if rr := post(h, url.Values{"schema_id": {"diploma"}}); !strings.Contains(trig(rr), "Too many requests") {
			t.Fatalf("trigger=%q", trig(rr))
		}
	})
	t.Run("bad form / no schema / unknown schema / no verifiers / adapter error", func(t *testing.T) {
		h := newH(t, okAdapter())
		req := httptest.NewRequest(http.MethodPost, "/verify/request", strings.NewReader("a=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.PublicVerifyRequest(rr, req)
		if !strings.Contains(rr.Body.String(), "Invalid request") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		if rr := post(h, url.Values{}); !strings.Contains(trig(rr), "Select a document type first") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		if rr := post(h, url.Values{"schema_id": {"ghost"}}); !strings.Contains(trig(rr), "Document type not recognized") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		ad := okAdapter()
		ad.noVerifier = true
		if rr := post(newH(t, ad), url.Values{"schema_id": {"diploma"}}); !strings.Contains(trig(rr), "No verifiers available") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		ad = okAdapter()
		ad.verifyErr = errors.New("walt down")
		if rr := post(newH(t, ad), url.Values{"schema_id": {"diploma"}}); !strings.Contains(trig(rr), "no está disponible") {
			t.Fatalf("trigger=%q", trig(rr))
		}
	})
	t.Run("success: SD-JWT custom variant sets vct, fields are validated, disclosure defaults", func(t *testing.T) {
		ad := okAdapter()
		h := newH(t, ad)
		rr := post(h, url.Values{"schema_id": {"diploma-sdjwt"}, "field_key": {"degree", "bogus"}})
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "openid4vp://req") || !strings.Contains(body, "/verify/result/st-1") || !strings.Contains(body, "<strong>Diploma</strong>") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
	})
	t.Run("success: unknown SourceDeployment falls back to the first verifier; default fields", func(t *testing.T) {
		ad := okAdapter()
		ad.schemas[0].SourceDeployment = "elsewhere"
		h := newH(t, ad)
		if rr := post(h, url.Values{"schema_id": {"diploma"}}); rr.Code != 200 || !strings.Contains(rr.Body.String(), "openid4vp://req") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestPublicVerifyResult(t *testing.T) {
	get := func(h *H, state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/verify/result/"+state, nil)
		req.SetPathValue("state", state)
		rr := httptest.NewRecorder()
		h.PublicVerifyResult(rr, req)
		return rr
	}
	t.Run("missing state → 400", func(t *testing.T) {
		if rr := get(pubVerifyH(t, &delegAPIAdapter{}), ""); rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("fetch error and pending fragments", func(t *testing.T) {
		ad := &delegAPIAdapter{fetchErr: errors.New("boom")}
		h := pubVerifyH(t, ad)
		if rr := get(h, "st-1"); !strings.Contains(rr.Body.String(), "Error retrieving result") || ad.fetchState != "st-1" {
			t.Fatalf("body=%s", rr.Body.String())
		}
		ad = &delegAPIAdapter{fetchResult: backend.VerificationResult{Pending: true}}
		if rr := get(pubVerifyH(t, ad), "st-2"); !strings.Contains(rr.Body.String(), "/verify/result/st-2") || strings.Contains(rr.Body.String(), "Error retrieving") {
			t.Fatalf("body=%s", rr.Body.String())
		}
	})
	t.Run("valid result: trust, live status list via CheckedRevocation, event logged", func(t *testing.T) {
		ad := &delegAPIAdapter{fetchResult: backend.VerificationResult{Valid: true, Issuer: "did:web:issuer.example", CredentialTitle: "Diploma", Format: "w3c_vcdm_2", CheckedRevocation: true, Method: "OID4VP · full credential shared"}}
		h := pubVerifyH(t, ad)
		h.TrustRegistry = &trustFakeRegistry{issuers: []trust.TrustedIssuer{{DID: "did:web:issuer.example", DisplayName: "Example University"}}}
		vlog := &pubVerifyLog{done: make(chan struct{})}
		h.VerificationLog = vlog
		t.Setenv("VERIFIABLY_PUBLIC_URL", "https://hub.example")
		rr := get(h, "st-3")
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "<strong>Type:</strong> Diploma") || !strings.Contains(body, "verified live") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		select {
		case <-vlog.done:
		case <-time.After(5 * time.Second):
			t.Fatal("verification event was not appended")
		}
		e := vlog.events[0]
		if e.Status != "valid" || e.IssuerDID != "did:web:issuer.example" || e.SchemaName != "Diploma" || e.DeploymentID != "https://hub.example" || e.StatusListSrc != "live" {
			t.Fatalf("event=%+v", e)
		}
	})
	t.Run("invalid result surfaces the denial reason; log append failure is only warned", func(t *testing.T) {
		ad := &delegAPIAdapter{fetchResult: backend.VerificationResult{Valid: false, Issuer: "did:web:x", Method: "OID4VP ·  · a presented credential has been revoked"}}
		h := pubVerifyH(t, ad)
		vlog := &pubVerifyLog{appendErr: errors.New("db down"), done: make(chan struct{})}
		h.VerificationLog = vlog
		rr := get(h, "st-4")
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "a presented credential has been revoked") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		select {
		case <-vlog.done:
		case <-time.After(5 * time.Second):
			t.Fatal("append not attempted")
		}
		if len(vlog.events) != 0 {
			t.Fatalf("failed append must not record: %+v", vlog.events)
		}
	})
}

func TestCheckStatusListAvailability(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	cache := &pubVerifySLCache{res: statuslistcache.Result{Source: "cached"}}
	reg := &trustFakeRegistry{issuers: []trust.TrustedIssuer{
		{DID: "did:web:none"},
		{DID: "did:web:lists", StatusListEndpoints: []string{"https://issuer.example/status/1", "https://issuer.example/status/2"}},
	}}
	h := &H{}
	if h.checkStatusListAvailability(req, "did:web:lists") != "" {
		t.Fatal("no cache/registry must return empty")
	}
	h = &H{StatusListCache: cache, TrustRegistry: reg}
	cases := map[string]string{"": "", "did:web:unknown": "", "did:web:none": "", "did:web:lists": "cached"}
	for did, want := range cases {
		if got := h.checkStatusListAvailability(req, did); got != want {
			t.Errorf("%q: got %q want %q", did, got, want)
		}
	}
	if len(cache.urls) != 1 || cache.urls[0] != "https://issuer.example/status/1" {
		t.Fatalf("fetched urls=%v", cache.urls)
	}
	cache.err = errors.New("dead")
	if got := h.checkStatusListAvailability(req, "did:web:lists"); got != "unknown" {
		t.Fatalf("fetch error: %q", got)
	}
	reg.listErr = errors.New("registry down")
	if got := h.checkStatusListAvailability(req, "did:web:lists"); got != "" {
		t.Fatalf("registry error: %q", got)
	}
}
