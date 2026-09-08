package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/vctypes"
)

// bulkH builds an issuer session on Example DPG (declared bulk sources csv/api/db)
// with the Person schema selected and Scale=bulk.
func bulkH(t *testing.T, ad *issueAdapter, keys ...string) (*H, []*http.Cookie) {
	t.Helper()
	if ad.schemas == nil {
		ad.schemas = []vctypes.Schema{issuePersonSchema()}
	}
	if ad.dpgs == nil {
		if len(keys) == 0 {
			keys = []string{"csv", "api", "db"}
		}
		ad.dpgs = map[string]vctypes.DPG{"Example DPG": dpgWithBulk(keys...)}
	}
	return issueH(t, ad, func(s *Session) { s.Scale = "bulk" })
}

func bulkPost(h *H, fn func(http.ResponseWriter, *http.Request), v url.Values, cookies []*http.Cookie) (*httptest.ResponseRecorder, *Session) {
	req := formPost("/issuer/issue/bulk", v, cookies...)
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr, sessionOf(h, req)
}

func TestBulkSource(t *testing.T) {
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	h, cookies := bulkH(t, &issueAdapter{}, "csv", "db")
	if rr, _ := bulkPost(h, h.BulkSource, url.Values{"source": {"ftp"}}, cookies); !strings.Contains(trig(rr), "unknown source: ftp") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	if rr, _ := bulkPost(h, h.BulkSource, url.Values{"source": {"api"}}, cookies); !strings.Contains(trig(rr), "source 'api' is not supported") {
		t.Fatalf("trigger=%q", trig(rr))
	}
	sess := sessionOf(h, formPost("/", nil, cookies...))
	sess.BulkRows, sess.BulkLabel = []map[string]string{{"a": "b"}}, "csv"
	rr, sess := bulkPost(h, h.BulkSource, url.Values{"source": {" db "}}, cookies)
	body := rr.Body.String()
	if rr.Code != 200 || sess.BulkSource != "db" || sess.BulkRows != nil || sess.BulkLabel != "" {
		t.Fatalf("status=%d sess=%q rows=%v", rr.Code, sess.BulkSource, sess.BulkRows)
	}
	for _, want := range []string{`class="chip active"`, `name="db_conn"`, "only supports 2 of the 3 bulk sources", `id="csv-preview"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	ad := h.Adapter.(*issueAdapter)
	ad.schemasErr = errors.New("down")
	if rr, _ := bulkPost(h, h.BulkSource, url.Values{"source": {"csv"}}, cookies); !strings.Contains(trig(rr), "backend unavailable: down") {
		t.Fatalf("trigger=%q", trig(rr))
	}
}

func TestBulkInlineError(t *testing.T) {
	h, _ := bulkH(t, &issueAdapter{})
	rr := httptest.NewRecorder()
	h.bulkInlineError(rr, httptest.NewRequest(http.MethodPost, "/", nil), "boom <x>")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Couldn't load the data source.") || !strings.Contains(rr.Body.String(), "boom &lt;x&gt;") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBulkPreview(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{}, "csv", "api", "db", "registry")
	expectErr := func(t *testing.T, v url.Values, want string) {
		t.Helper()
		rr, _ := bulkPost(h, h.BulkPreview, v, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("want %q; status=%d body=%s", want, rr.Code, rr.Body.String())
		}
	}
	rawPost := func(body, ct string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/issuer/issue/bulk/preview", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		req.Header.Set("HX-Request", "true")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.BulkPreview(rr, req)
		return rr
	}

	t.Run("form errors and whitelist", func(t *testing.T) {
		if rr := rawPost("a=%zz", "application/x-www-form-urlencoded"); !strings.Contains(rr.Body.String(), "Bad form:") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		if rr := rawPost("garbage", "multipart/form-data; boundary=zzz"); !strings.Contains(rr.Body.String(), "Upload a CSV first.") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		expectErr(t, url.Values{"source": {"ftp"}}, "is not supported by the selected issuer DPG.")
	})
	t.Run("csv: missing file, header-only, mapped preview", func(t *testing.T) {
		send := func(field, body string) (*httptest.ResponseRecorder, *Session) {
			req, _ := multipartCSV(t, field, "people.csv", body)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rr := httptest.NewRecorder()
			h.BulkPreview(rr, req)
			return rr, sessionOf(h, req)
		}
		if rr, _ := send("other", "a\n1\n"); !strings.Contains(rr.Body.String(), "Choose a CSV file to upload.") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		if rr, _ := send("csv_file", "name,birthDate\n"); !strings.Contains(rr.Body.String(), "No rows returned from the data source") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		rr, sess := send("csv_file", "name,birthDate,extra\nAda,1990-01-01,x\nBob,1991-02-02,y\n")
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "csv — 2 rows · map columns → fields") || !strings.Contains(body, "Issue 2 credentials →") ||
			!strings.Contains(body, `<option value="name" selected>`) || !strings.Contains(body, `<option value="birthDate" selected>`) {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		if len(sess.BulkRows) != 2 || sess.BulkLabel != "csv" || len(sess.BulkColumns) != 3 || sess.BulkColumns[0] != "name" {
			t.Fatalf("stash rows=%d label=%q cols=%v", len(sess.BulkRows), sess.BulkLabel, sess.BulkColumns)
		}
		if strings.Contains(body, `name="mfield" value="individualId"`) {
			t.Fatal("non-provision DPG must not render the holder-identity mapping row")
		}
	})
	t.Run("api: url required, unreachable, truncation, backend error after fetch", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"api"}}, "API URL is required.")
		expectErr(t, url.Values{"source": {"api"}, "api_url": {"http://127.0.0.1:1/rows"}}, "Fetch failed:")
		var sb strings.Builder
		sb.WriteString(`{"data":[`)
		for i := 0; i < maxBulkPreviewRows+1; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"name":"P","birthDate":"1990-01-01"}`)
		}
		sb.WriteString("]}")
		big := registryBodyServer(t, sb.String())
		rr, sess := bulkPost(h, h.BulkPreview, url.Values{"source": {"api"}, "api_url": {big.URL + "/rows?x=1"}}, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Source returned 10001 rows; previewing/applying the first 10000.") || len(sess.BulkRows) != maxBulkPreviewRows || sess.BulkLabel != "api:"+strings.TrimPrefix(big.URL, "http://") {
			t.Fatalf("status=%d rows=%d label=%q", rr.Code, len(sess.BulkRows), sess.BulkLabel)
		}
		ad := h.Adapter.(*issueAdapter)
		ad.schemasErr = errors.New("down")
		expectErr(t, url.Values{"source": {"api"}, "api_url": {big.URL}}, "Backend unavailable: down")
		ad.schemasErr = nil
	})
	t.Run("db: both fields required; unreachable DSN fails fast", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"db"}, "db_query": {"SELECT 1"}}, "Connection string and SELECT query are both required.")
		start := time.Now()
		expectErr(t, url.Values{"source": {"db"}, "db_conn": {"postgres://u:p@127.0.0.1:1/db?connect_timeout=1"}, "db_query": {"SELECT 1"}}, "Fetch failed:")
		if time.Since(start) > 5*time.Second {
			t.Fatal("unreachable DSN must fail fast")
		}
	})
	t.Run("registry: url + entity required, empty (3 messages), ok with provision mapping row", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"registry"}}, "Registry base URL is required")
		sess := sessionOf(h, formPost("/", nil, cookies...))
		sess.SchemaID = ""
		expectErr(t, url.Values{"source": {"registry"}, "reg_url": {"http://127.0.0.1:1"}}, "Registry entity is required.")
		sess.SchemaID = "person"
		expectErr(t, url.Values{"source": {"registry"}, "reg_url": {"http://127.0.0.1:1"}}, "reach the registry at http://127.0.0.1:1, or it has no registered entities")
		wrong := identityRegistryServer(t, `{"data":[]}`, `{"data":[{"name":"Vehicle"}]}`)
		expectErr(t, url.Values{"source": {"registry"}, "reg_url": {wrong.URL}, "reg_entity": {"Person"}}, "Available: Vehicle.")
		empty := identityRegistryServer(t, `{"data":[]}`, `{"data":[{"name":"person"}]}`)
		expectErr(t, url.Values{"source": {"registry"}, "reg_url": {empty.URL}}, "exists in the registry but has no records yet.")

		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg1","label":"Example Registry","url":"http://127.0.0.1:1","entity":"Person"}]`)
		srv := identityRegistryServer(t, `{"data":[{"individualId":"1001","name":"Ada"}]}`, `{}`)
		ad := h.Adapter.(*issueAdapter)
		ad.dpgs["Example DPG"] = vctypes.DPG{SchemaApply: "inji_authcode", Capabilities: dpgWithBulk("registry").Capabilities}
		rr, sess := bulkPost(h, h.BulkPreview, url.Values{"source": {"registry"}, "reg_pick": {"reg1"}, "reg_url": {srv.URL}}, cookies)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "registry:Person — 1 row") || !strings.Contains(body, "Provision 1 subject →") ||
			!strings.Contains(body, `name="mfield" value="individualId"`) || !strings.Contains(body, `<option value="individualId" selected>`) || sess.BulkLabel != "registry:Person" {
			t.Fatalf("status=%d label=%q body=%s", rr.Code, sess.BulkLabel, body)
		}
	})
}

func TestBulkApplyAndRunBulkIssue(t *testing.T) {
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	stash := []map[string]string{{"n": "Ada", "d": "1990-01-01"}, {"n": "Bob", "d": ""}}
	seed := func(h *H, cookies []*http.Cookie) {
		sess := sessionOf(h, formPost("/", nil, cookies...))
		sess.BulkRows, sess.BulkColumns, sess.BulkLabel = stash, []string{"n", "d"}, "csv"
	}
	mapping := url.Values{"mfield": {"name", "birthDate", ""}, "mcol": {"n", "d"}}

	t.Run("bad form / expired preview", func(t *testing.T) {
		h, cookies := bulkH(t, &issueAdapter{})
		req := httptest.NewRequest(http.MethodPost, "/issuer/issue/bulk/apply", strings.NewReader("a=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.BulkApply(rr, req)
		if !strings.Contains(rr.Body.String(), "Bad form:") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		if rr, _ := bulkPost(h, h.BulkApply, mapping, cookies); !strings.Contains(rr.Body.String(), "Preview expired") {
			t.Fatalf("body=%s", rr.Body.String())
		}
	})
	t.Run("backend error / IssueBulk error consume the stash", func(t *testing.T) {
		ad := &issueAdapter{schemasErr: errors.New("down")}
		h, cookies := bulkH(t, ad)
		seed(h, cookies)
		rr, sess := bulkPost(h, h.BulkApply, mapping, cookies)
		if !strings.Contains(trig(rr), "backend unavailable: down") || sess.BulkRows != nil {
			t.Fatalf("trigger=%q rows=%v", trig(rr), sess.BulkRows)
		}
		ad.schemasErr = nil
		ad.bulkErr = errors.New("walt 500")
		seed(h, cookies)
		if rr, _ := bulkPost(h, h.BulkApply, mapping, cookies); !strings.Contains(trig(rr), "walt 500") {
			t.Fatalf("trigger=%q", trig(rr))
		}
	})
	t.Run("success: mapping, per-row bindings, log records, preview fragment", func(t *testing.T) {
		ad := &issueAdapter{prefill: map[string]string{"name": "Demo"}, bulkRes: backend.IssueBulkResult{Accepted: 1, Rejected: 1,
			Errors: []backend.BulkError{{Row: 2, Reason: "missing birthDate"}},
			Rows: []backend.BulkRowResult{
				{Row: 1, Status: "issued", Label: "Ada", Subject: map[string]string{"name": "Ada"}, OfferURI: "openid-credential-offer://one"},
				{Row: 2, Status: "failed", Label: "Bob", Error: "missing birthDate"},
				{Row: 9, Status: "issued", Label: "out of range"},
			}}}
		h, cookies := bulkH(t, ad)
		store := &slFakeStore{id: "v1", allocIndex: 7}
		h.StatusLists.Register(&StatusListEntry{Store: store, Kind: "bitstring"})
		log := issuedLog(t)
		h.IssuanceLog = log
		seed(h, cookies)
		rr, sess := bulkPost(h, h.BulkApply, mapping, cookies)
		body := rr.Body.String()
		if rr.Code != 200 || sess.BulkRows != nil || sess.BulkLabel != "" {
			t.Fatalf("status=%d stash not consumed", rr.Code)
		}
		for _, want := range []string{"csv — 2 rows", `<span class="mono" style="color:var(--ok)">1</span> issued`, "1</span> failed", "openid-credential-offer://one", "missing birthDate"} {
			if !strings.Contains(body, want) {
				t.Errorf("body lacks %q", want)
			}
		}
		req := ad.bulkReqs[0]
		if req.RowCount != 2 || req.Rows[0]["name"] != "Ada" || req.Rows[0]["birthDate"] != "1990-01-01" || len(req.Rows[1]) != 2 || req.Rows[1]["birthDate"] != "" ||
			len(req.StatusLists) != 2 || req.StatusLists[0] == nil || req.StatusLists[0].Index != 7 || req.IssuerDpg != "Example DPG" {
			t.Fatalf("bulk req=%+v", req)
		}
		items := log.List(issuance.Filter{})
		if len(items) != 1 || items[0].OfferURI != "openid-credential-offer://one" || items[0].StatusList == nil || items[0].StatusList.Index != 7 {
			t.Fatalf("log=%+v", items)
		}
	})
}

func TestRunBulkProvision_Branches(t *testing.T) {
	sdjwt := vctypes.Schema{ID: "person", Name: "Person", Std: "sd_jwt_vc (IETF)", FieldsSpec: []vctypes.FieldSpec{{Name: "name"}}}
	newH := func(t *testing.T, ad *issueAdapter, subj SubjectProvisioner) (*H, *Session, *http.Request) {
		t.Helper()
		if ad.dpgs == nil {
			ad.dpgs = map[string]vctypes.DPG{"Inji DPG": {SchemaApply: "inji_authcode"}}
		}
		h := &H{Adapter: ad, Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_issue"), Subjects: subj, StatusLists: NewStatusListSet()}
		req := formPost("/issuer/issue/bulk/apply", nil)
		sess := h.Sessions.MustGet(httptest.NewRecorder(), req)
		sess.IssuerDpg, sess.SchemaID, sess.UserEmail = "Inji DPG", "person", "issuer@example.org"
		return h, sess, req
	}
	trig := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }

	t.Run("no subject store / backend error", func(t *testing.T) {
		h, sess, req := newH(t, &issueAdapter{schemas: []vctypes.Schema{sdjwt}}, nil)
		rr := httptest.NewRecorder()
		h.runBulkIssue(rr, req, sess, nil, "csv")
		if !strings.Contains(trig(rr), "subject provisioning not enabled") {
			t.Fatalf("trigger=%q", trig(rr))
		}
		h, sess, req = newH(t, &issueAdapter{schemasErr: errors.New("down")}, &fakeSubjects{})
		rr = httptest.NewRecorder()
		h.runBulkIssue(rr, req, sess, nil, "csv")
		if !strings.Contains(trig(rr), "backend unavailable: down") {
			t.Fatalf("trigger=%q", trig(rr))
		}
	})
	t.Run("unknown schema falls back to every non-empty column; provision error", func(t *testing.T) {
		f := &fakeSubjects{provErr: errors.New("db write failed")}
		h, sess, req := newH(t, &issueAdapter{schemas: []vctypes.Schema{}}, f)
		rr := httptest.NewRecorder()
		h.runBulkIssue(rr, req, sess, []map[string]string{{"individualId": "1001", "name": " Ada ", "empty": " "}}, "api:x")
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "1</span> failed") || !strings.Contains(body, "db write failed") || len(f.provCalls) != 1 {
			t.Fatalf("status=%d calls=%d body=%s", rr.Code, len(f.provCalls), body)
		}
		claims := f.provCalls[0].claims
		_, slug := injiConfigKeySlug(vctypes.Schema{}) // unknown schema → default slug
		if len(claims) != 2 || claims[subjectClaimKey(slug, "name")] != "Ada" || claims[subjectClaimKey(slug, "individualId")] != "1001" {
			t.Fatalf("claims=%v", claims)
		}
	})
	t.Run("SD-JWT: status index allocated, issuance recorded; no-id and no-claims rows fail", func(t *testing.T) {
		f := &fakeSubjects{}
		h, sess, req := newH(t, &issueAdapter{schemas: []vctypes.Schema{sdjwt}}, f)
		store := &slFakeStore{id: "t1", allocIndex: 5}
		h.StatusLists.Register(&StatusListEntry{Store: store, Kind: "token"})
		log := issuedLog(t)
		h.IssuanceLog = log
		rows := []map[string]string{
			{"individualId": "1001", "name": "Ada"},
			{"name": "NoId"},
			{"uin": "1003", "other": "x"},
		}
		rr := httptest.NewRecorder()
		h.runBulkIssue(rr, req, sess, rows, "csv")
		body := rr.Body.String()
		for _, want := range []string{"csv — 3 rows", `<span class="mono" style="color:var(--ok)">1</span> provisioned`, "2</span> failed", "no identity column", "row has none of the credential"} {
			if !strings.Contains(body, want) {
				t.Errorf("body lacks %q", want)
			}
		}
		if len(f.provCalls) != 1 || f.provCalls[0].subjectID != esignetSubjectID("1001", defaultAuthCodeClientID()) || f.provCalls[0].claims[injiStatusIdxKey("person")] != "5" {
			t.Fatalf("calls=%+v", f.provCalls)
		}
		items := log.List(issuance.Filter{})
		if len(items) != 1 || items[0].StatusList == nil || items[0].StatusList.Type != "token" || items[0].StatusList.Index != 5 {
			t.Fatalf("log=%+v", items)
		}
	})
}

func TestBulkRegistryEntities(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{})
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue/bulk/registry/entities", strings.NewReader("a=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.BulkRegistryEntities(rr, req)
	needURL := rr.Body.String()
	if rr.Code != 200 || strings.Contains(needURL, "No entities found") {
		t.Fatalf("status=%d body=%s", rr.Code, needURL)
	}
	if rr, _ := bulkPost(h, h.BulkRegistryEntities, url.Values{}, cookies); rr.Body.String() != needURL {
		t.Fatalf("missing URL must render the same NeedURL fragment: %s", rr.Body.String())
	}
	if rr, _ := bulkPost(h, h.BulkRegistryEntities, url.Values{"reg_url": {"http://127.0.0.1:1"}}, cookies); !strings.Contains(rr.Body.String(), "No entities found at http://127.0.0.1:1") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	srv := identityRegistryServer(t, `{}`, `{"data":[{"name":"Person"},{"name":"ZzProbe"}]}`)
	rr, _ = bulkPost(h, h.BulkRegistryEntities, url.Values{"reg_url": {srv.URL}}, cookies)
	if !strings.Contains(rr.Body.String(), ">Person</button>") || strings.Contains(rr.Body.String(), "ZzProbe") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestSampleRowsContainsStr(t *testing.T) {
	rows := []map[string]string{{"a": "1"}, {"a": "2"}}
	if got := sampleRows(rows, 5); len(got) != 2 {
		t.Fatalf("short: %v", got)
	}
	if got := sampleRows(rows, 1); len(got) != 1 || got[0]["a"] != "1" {
		t.Fatalf("cut: %v", got)
	}
	if !containsStr([]string{"a", "b"}, "b") || containsStr([]string{"a"}, "z") {
		t.Fatal("containsStr wrong")
	}
}

func TestFetchJSONRows(t *testing.T) {
	ctx := context.Background()
	serve := func(status int, body string, capture *http.Header) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if capture != nil {
				*capture = r.Header.Clone()
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	if _, err := fetchJSONRows(ctx, "http://bad host", "", ""); err == nil {
		t.Fatal("bad URL must error")
	}
	if _, err := fetchJSONRows(ctx, "http://127.0.0.1:1/x", "", ""); err == nil {
		t.Fatal("unreachable must error")
	}
	if _, err := fetchJSONRows(ctx, serve(500, strings.Repeat("e", 300), nil).URL, "", ""); err == nil || !strings.Contains(err.Error(), "HTTP 500: "+strings.Repeat("e", 200)+"…") {
		t.Fatalf("err=%v", err)
	}
	if _, err := fetchJSONRows(ctx, serve(200, "{nope", nil).URL, "", ""); err == nil || !strings.Contains(err.Error(), "decode JSON") {
		t.Fatalf("err=%v", err)
	}
	if _, err := fetchJSONRows(ctx, serve(200, `{"other":1}`, nil).URL, "", ""); err == nil || !strings.Contains(err.Error(), "not a JSON array") {
		t.Fatalf("err=%v", err)
	}
	if _, err := fetchJSONRows(ctx, serve(200, `[1,"x"]`, nil).URL, "", ""); err == nil || !strings.Contains(err.Error(), "array had 2 items, none were objects") {
		t.Fatalf("err=%v", err)
	}
	var hdr http.Header
	srv := serve(200, `{"rows":"no","items":[{"id":1,"name":"Ada","tags":["a"],"n":null},"skip",{"id":2},{"id":3}]}`, &hdr)
	// api_limit counts array ITEMS (the non-object one included), so "3" yields two rows.
	rows, err := fetchJSONRows(ctx, srv.URL, "Bearer tok", "3")
	if err != nil || len(rows) != 2 || rows[0]["id"] != "1" || rows[0]["tags"] != `["a"]` || rows[0]["n"] != "" || rows[1]["id"] != "2" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if hdr.Get("Authorization") != "Bearer tok" || hdr.Get("Accept") != "application/json" {
		t.Fatalf("headers=%v", hdr)
	}
	rows, err = fetchJSONRows(ctx, srv.URL, "", "0")
	if err != nil || len(rows) != 3 {
		t.Fatalf("limit 0 rows=%d err=%v", len(rows), err)
	}
}

func TestQueryDBRows_FailsBeforeConnecting(t *testing.T) {
	ctx := context.Background()
	if _, err := queryDBRows(ctx, "postgres://u:p@127.0.0.1:1/db?connect_timeout=1", " delete from x"); err == nil || !strings.Contains(err.Error(), "only SELECT queries allowed") {
		t.Fatalf("err=%v", err)
	}
	start := time.Now()
	if _, err := queryDBRows(ctx, "postgres://u:p@127.0.0.1:1/db?connect_timeout=1", "SELECT 1"); err == nil {
		t.Fatal("unreachable DSN must error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("connect failure must be fast")
	}
}

func TestStringifyAnyAndTruncate(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"s", "s"},
		{[]byte("b"), "b"},
		{time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC), "2026-03-04"},
		{42.5, "42.5"},
		{true, "true"},
		{map[string]any{"k": "v"}, `{"k":"v"}`},
		{[]any{"a", 1}, `["a",1]`},
		{json.RawMessage(`"quoted"`), "quoted"},
		{make(chan int), ""},
	}
	for i, tc := range cases {
		got := stringifyAny(tc.in)
		if i == len(cases)-1 {
			if !strings.HasPrefix(got, "0x") {
				t.Errorf("unmarshalable value must fall back to fmt.Sprint, got %q", got)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("%v: got %q want %q", tc.in, got, tc.want)
		}
	}
	if truncateForLogBulk("abc", 3) != "abc" || truncateForLogBulk("abcd", 3) != "abc…" {
		t.Fatal("truncateForLogBulk wrong")
	}
	for in, want := range map[string]string{"https://api.example:8443/v1/rows?x=1": "api.example:8443", "api.example/path": "api.example", "plain": "plain", "http://h?q": "h"} {
		if got := truncateHost(in); got != want {
			t.Errorf("truncateHost(%q)=%q want %q", in, got, want)
		}
	}
}

// TestBulkPreview_DB_WaltID (plan §5 item 1): a DPG that declares the db bulk
// source (walt.id does) reaches queryDBRows through BulkPreview with an
// operator-typed DSN. Only the sanctioned unreachable DSN is ever used, so pgx
// fails before any network round-trip.
func TestBulkPreview_DB_WaltID(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{}, "csv", "api", "db")
	expectErr := func(t *testing.T, v url.Values, want string) {
		t.Helper()
		rr, _ := bulkPost(h, h.BulkPreview, v, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("want %q; status=%d body=%s", want, rr.Code, rr.Body.String())
		}
	}
	dsn := "postgres://u:p@127.0.0.1:1/db?connect_timeout=1"
	expectErr(t, url.Values{"source": {"db"}}, "Connection string and SELECT query are both required.")
	expectErr(t, url.Values{"source": {"db"}, "db_conn": {dsn}}, "Connection string and SELECT query are both required.")
	expectErr(t, url.Values{"source": {"db"}, "db_query": {"SELECT 1"}}, "Connection string and SELECT query are both required.")
	expectErr(t, url.Values{"source": {"db"}, "db_conn": {dsn}, "db_query": {"DELETE FROM citizens"}}, "Fetch failed: only SELECT queries allowed")
	start := time.Now()
	expectErr(t, url.Values{"source": {"db"}, "db_conn": {dsn}, "db_query": {"SELECT id, first_name FROM citizens"}}, "Fetch failed:")
	if time.Since(start) > 5*time.Second {
		t.Fatal("unreachable DSN must fail fast")
	}
}

// TestBulkPreview_APILegacyContract pins the pre-M3 "Bulk from API" contract at
// the handler level (reviewer requirement before fetchJSONRows is refactored):
// a form carrying ONLY source/api_url/api_auth/api_limit — no api_mode — must
// produce exactly one GET with Accept: application/json, forward api_auth
// verbatim as Authorization, honour api_limit (counted over array items) and
// label the stash "api:<host>".
func TestBulkPreview_APILegacyContract(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{}, "csv", "api", "db")
	var gotMethod, gotPath string
	var gotHdr http.Header
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotMethod, gotPath, gotHdr = r.Method, r.URL.Path, r.Header.Clone()
		_, _ = w.Write([]byte(`[{"name":"Ada","birthDate":"1990-01-01"},{"name":"Bob","birthDate":"1991-02-02"},{"name":"Cy","birthDate":"1992-03-03"}]`))
	}))
	t.Cleanup(srv.Close)
	rr, sess := bulkPost(h, h.BulkPreview, url.Values{
		"source": {"api"}, "api_url": {srv.URL + "/v1/people"}, "api_auth": {"Bearer legacy-token"}, "api_limit": {"2"},
	}, cookies)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "— 2 rows · map columns → fields") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if calls != 1 || gotMethod != http.MethodGet || gotPath != "/v1/people" {
		t.Fatalf("calls=%d method=%s path=%s", calls, gotMethod, gotPath)
	}
	if gotHdr.Get("Accept") != "application/json" || gotHdr.Get("Authorization") != "Bearer legacy-token" {
		t.Fatalf("headers=%v", gotHdr)
	}
	if len(sess.BulkRows) != 2 || sess.BulkRows[0]["name"] != "Ada" || sess.BulkLabel != "api:"+strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("rows=%v label=%q", sess.BulkRows, sess.BulkLabel)
	}
	// No api_auth → no Authorization header at all.
	bulkPost(h, h.BulkPreview, url.Values{"source": {"api"}, "api_url": {srv.URL}}, cookies)
	if _, has := gotHdr["Authorization"]; has {
		t.Fatalf("Authorization must be absent when api_auth is empty: %v", gotHdr)
	}
	// Error strings are unchanged.
	bad := registryBodyServer(t, `[]`)
	if rr, _ := bulkPost(h, h.BulkPreview, url.Values{"source": {"api"}, "api_url": {bad.URL}}, cookies); !strings.Contains(rr.Body.String(), "Fetch failed: no rows in response (array had 0 items, none were objects)") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}
