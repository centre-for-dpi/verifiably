package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// identityH builds a registrar H (admin session) over registrar_identities.html.
func identityH(t *testing.T, subj SubjectProvisioner, admin bool) (*H, []*http.Cookie) {
	t.Helper()
	h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "registrar_identities"), Subjects: subj}
	cookies := seedSession(t, h, func(s *Session) { s.IsAdmin = admin })
	return h, cookies
}

func identityFake() *fakeSubjects {
	return &fakeSubjects{identities: map[string]map[string]string{
		"1001": {"fullName": "Ada Example", "email": "ada@example.org"},
	}}
}

// identityRegistryServer fakes a Sunbird RC registry: entity searches return
// rows, Schema searches return schemas.
func identityRegistryServer(t *testing.T, rows, schemas string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/Schema/search") {
			_, _ = io.WriteString(w, schemas)
			return
		}
		_, _ = io.WriteString(w, rows)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIdentityBulkSourcesAndAllowed(t *testing.T) {
	src := identityBulkSources()
	if len(src) != 4 || src[0].Key != "csv" || src[3].Key != "registry" {
		t.Fatalf("sources=%+v", src)
	}
	for _, k := range []string{"csv", "api", "db", "registry"} {
		if !identitySourceAllowed(k) {
			t.Errorf("%s must be allowed", k)
		}
	}
	if identitySourceAllowed("ftp") || identitySourceAllowed("") {
		t.Fatal("unknown sources must be rejected")
	}
}

func TestRegistrarOK(t *testing.T) {
	h, _ := identityH(t, nil, false)
	t.Run("not admin: fragment error / page redirect", func(t *testing.T) {
		rr := httptest.NewRecorder()
		if h.registrarOK(rr, httptest.NewRequest(http.MethodGet, "/registrar/identities", nil), &Session{}, true) || !strings.Contains(rr.Body.String(), "sign in as the registrar") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		rr = httptest.NewRecorder()
		if h.registrarOK(rr, httptest.NewRequest(http.MethodGet, "/registrar/identities", nil), &Session{}, false) || rr.Header().Get("Location") != "/admin/login" {
			t.Fatalf("location=%q", rr.Header().Get("Location"))
		}
	})
	t.Run("no identity store: fragment error / page banner", func(t *testing.T) {
		rr := httptest.NewRecorder()
		if h.registrarOK(rr, httptest.NewRequest(http.MethodGet, "/registrar/identities", nil), &Session{IsAdmin: true}, true) || !strings.Contains(rr.Body.String(), "Identity registry not enabled") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		rr = httptest.NewRecorder()
		if h.registrarOK(rr, htmxMainRequest(http.MethodGet, "/registrar/identities"), &Session{IsAdmin: true}, false) || !strings.Contains(rr.Body.String(), "INJI_CERTIFY_DATABASE_URL unset") {
			t.Fatalf("body=%s", rr.Body.String())
		}
	})
	t.Run("ok", func(t *testing.T) {
		h.Subjects = identityFake()
		if !h.registrarOK(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), &Session{IsAdmin: true}, true) {
			t.Fatal("expected ok")
		}
	})
}

func TestShowRegistrarIdentities(t *testing.T) {
	t.Run("not admin → redirect", func(t *testing.T) {
		h, cookies := identityH(t, identityFake(), false)
		rr := httptest.NewRecorder()
		h.ShowRegistrarIdentities(rr, issueGET("/registrar/identities", false, cookies))
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/admin/login" {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("store disabled", func(t *testing.T) {
		h, cookies := identityH(t, nil, true)
		rr := httptest.NewRecorder()
		h.ShowRegistrarIdentities(rr, issueGET("/registrar/identities", true, cookies))
		if rr.Code != 200 || strings.Contains(rr.Body.String(), `id="identity-records"`) {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("renders chips and records; default source csv", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg1","label":"Example Registry","url":"https://registry.example"}]`)
		h, cookies := identityH(t, identityFake(), true)
		req := issueGET("/registrar/identities", false, cookies)
		rr := httptest.NewRecorder()
		h.ShowRegistrarIdentities(rr, req)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "<!DOCTYPE") || !strings.Contains(body, ">1001</td>") || !strings.Contains(body, "Ada Example") || !strings.Contains(body, "Sunbird RC registry") {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		if sess := sessionOf(h, req); sess.IdentityBulkSource != "csv" {
			t.Fatalf("source=%q", sess.IdentityBulkSource)
		}
	})
}

func TestIdentityRecords(t *testing.T) {
	h := &H{}
	if h.identityRecords(httptest.NewRequest(http.MethodGet, "/", nil).Context()) != nil {
		t.Fatal("nil store → nil")
	}
	f := identityFake()
	f.idListErr = errors.New("db down")
	h.Subjects = f
	if h.identityRecords(httptest.NewRequest(http.MethodGet, "/", nil).Context()) != nil {
		t.Fatal("list error → nil")
	}
	f.idListErr = nil
	if recs := h.identityRecords(httptest.NewRequest(http.MethodGet, "/", nil).Context()); len(recs) != 1 || recs[0]["individualId"] != "1001" {
		t.Fatalf("recs=%v", recs)
	}
}

func TestEditSaveDeleteIdentity(t *testing.T) {
	f := identityFake()
	h, cookies := identityH(t, f, true)
	do := func(fn func(http.ResponseWriter, *http.Request), id string, v url.Values) *httptest.ResponseRecorder {
		req := formPost("/registrar/identities/edit", v, cookies...)
		req.SetPathValue("id", id)
		rr := httptest.NewRecorder()
		fn(rr, req)
		return rr
	}

	t.Run("edit: unknown, store error, ok", func(t *testing.T) {
		if rr := do(h.EditIdentity, "nope", nil); !strings.Contains(rr.Body.String(), "No enrolled identity for nope") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		f.idGetErr = errors.New("db down")
		if rr := do(h.EditIdentity, "1001", nil); !strings.Contains(rr.Body.String(), "No enrolled identity for 1001") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		f.idGetErr = nil
		rr := do(h.EditIdentity, " 1001 ", nil)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "EDIT IDENTITY · <span class=\"mono\">1001</span>") || !strings.Contains(rr.Body.String(), `name="email" value="ada@example.org"`) {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("save: missing id, store error, ok", func(t *testing.T) {
		if rr := do(h.SaveIdentity, "", nil); !strings.Contains(rr.Body.String(), "missing individualId") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		f.idUpsertErr = errors.New("constraint")
		if rr := do(h.SaveIdentity, "1001", url.Values{"fullName": {"X"}}); !strings.Contains(rr.Body.String(), "Save failed: constraint") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		f.idUpsertErr = nil
		rr := do(h.SaveIdentity, "1001", url.Values{"fullName": {" Ada Updated "}, "phone": {"555"}})
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Ada Updated") || !strings.Contains(rr.Body.String(), ">555</td>") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if saved := f.identities["1001"]; saved["fullName"] != "Ada Updated" || saved["email"] != "" || len(saved) != len(identityFields)-1 {
			t.Fatalf("saved=%v", saved)
		}
	})
	t.Run("delete: store error, ok", func(t *testing.T) {
		f.idDeleteErr = errors.New("locked")
		if rr := do(h.DeleteIdentityRecord, "1001", nil); !strings.Contains(rr.Body.String(), "Delete failed: locked") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		f.idDeleteErr = nil
		rr := do(h.DeleteIdentityRecord, "1001", nil)
		if rr.Code != 200 || strings.Contains(rr.Body.String(), ">1001</td>") || len(f.identities) != 0 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("non-admin session is refused on every fragment endpoint", func(t *testing.T) {
		h2, c2 := identityH(t, f, false)
		req := formPost("/registrar/identities/1001/edit", nil, c2...)
		req.SetPathValue("id", "1001")
		for _, fn := range []func(http.ResponseWriter, *http.Request){h2.EditIdentity, h2.SaveIdentity, h2.DeleteIdentityRecord, h2.IdentityBulkSource, h2.IdentityBulkPreview, h2.IdentityBulkApply, h2.IdentityRegistryEntities} {
			rr := httptest.NewRecorder()
			fn(rr, req)
			if !strings.Contains(rr.Body.String(), "sign in as the registrar") {
				t.Fatalf("body=%s", rr.Body.String())
			}
		}
	})
}

func TestIdentityBulkSource(t *testing.T) {
	h, cookies := identityH(t, identityFake(), true)
	req := formPost("/registrar/identities/source", url.Values{"source": {"ftp"}}, cookies...)
	rr := httptest.NewRecorder()
	h.IdentityBulkSource(rr, req)
	if !strings.Contains(rr.Body.String(), "unknown source: ftp") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	sess := sessionOf(h, req)
	sess.BulkRows = []map[string]string{{"a": "b"}}
	sess.BulkLabel = "csv"
	req = formPost("/registrar/identities/source", url.Values{"source": {" api "}}, cookies...)
	rr = httptest.NewRecorder()
	h.IdentityBulkSource(rr, req)
	sess = sessionOf(h, req)
	if rr.Code != 200 || sess.IdentityBulkSource != "api" || sess.BulkRows != nil || sess.BulkLabel != "" || !strings.Contains(rr.Body.String(), `name="api_url"`) {
		t.Fatalf("status=%d sess=%+v body=%s", rr.Code, sess.IdentityBulkSource, rr.Body.String())
	}
}

func TestIdentityBulkPreview(t *testing.T) {
	h, cookies := identityH(t, identityFake(), true)
	post := func(v url.Values) (*httptest.ResponseRecorder, *Session) {
		req := formPost("/registrar/identities/preview", v, cookies...)
		rr := httptest.NewRecorder()
		h.IdentityBulkPreview(rr, req)
		return rr, sessionOf(h, req)
	}
	expectErr := func(t *testing.T, v url.Values, want string) {
		t.Helper()
		rr, _ := post(v)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("want %q; status=%d body=%s", want, rr.Code, rr.Body.String())
		}
	}

	t.Run("form errors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/registrar/identities/preview", strings.NewReader("a=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.IdentityBulkPreview(rr, req)
		if !strings.Contains(rr.Body.String(), "Bad form:") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		req = httptest.NewRequest(http.MethodPost, "/registrar/identities/preview", strings.NewReader("garbage"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=zzz")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr = httptest.NewRecorder()
		h.IdentityBulkPreview(rr, req)
		if !strings.Contains(rr.Body.String(), "Upload a CSV first.") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		expectErr(t, url.Values{"source": {"ftp"}}, "Unknown source: ftp")
	})
	t.Run("header-only csv → no rows", func(t *testing.T) {
		req, _ := multipartCSV(t, "csv_file", "empty.csv", "fullName,email\n")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.IdentityBulkPreview(rr, req)
		if !strings.Contains(rr.Body.String(), "No rows returned from the data source") {
			t.Fatalf("body=%s", rr.Body.String())
		}
	})
	t.Run("csv: missing file, then mapped preview", func(t *testing.T) {
		req, _ := multipartCSV(t, "other_field", "x.csv", "a,b\n1,2\n")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.IdentityBulkPreview(rr, req)
		if !strings.Contains(rr.Body.String(), "Choose a CSV file to upload.") {
			t.Fatalf("body=%s", rr.Body.String())
		}
		req, _ = multipartCSV(t, "csv_file", "people.csv", "fullName,"+injiIdentityFields[1]+",email\nAda,1001,ada@example.org\nBob,1002,bob@example.org\n")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr = httptest.NewRecorder()
		h.IdentityBulkPreview(rr, req)
		body := rr.Body.String()
		sess := sessionOf(h, req)
		if rr.Code != 200 || !strings.Contains(body, "csv — 2 rows") || !strings.Contains(body, "Enroll 2 identities") || len(sess.BulkRows) != 2 || sess.BulkLabel != "csv" {
			t.Fatalf("status=%d rows=%d body=%s", rr.Code, len(sess.BulkRows), body)
		}
		// individualId has no exact column → falls back to the recognised alias.
		if !strings.Contains(body, `<option value="`+injiIdentityFields[1]+`" selected>`) {
			t.Fatalf("individualId default not selected: %s", body)
		}
	})
	t.Run("api: url required, fetch failure, empty, truncation", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"api"}}, "API URL is required.")
		expectErr(t, url.Values{"source": {"api"}, "api_url": {"http://127.0.0.1:1/rows"}}, "Fetch failed:")
		empty := registryBodyServer(t, `[]`)
		expectErr(t, url.Values{"source": {"api"}, "api_url": {empty.URL}}, "Fetch failed: no rows in response")
		var sb strings.Builder
		sb.WriteString("[")
		for i := 0; i < maxBulkPreviewRows+1; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"individualId":"%d","fullName":"P%d"}`, i, i)
		}
		sb.WriteString("]")
		big := registryBodyServer(t, sb.String())
		rr, sess := post(url.Values{"source": {"api"}, "api_url": {big.URL}})
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), fmt.Sprintf("Source returned %d rows; enrolling the first %d.", maxBulkPreviewRows+1, maxBulkPreviewRows)) || len(sess.BulkRows) != maxBulkPreviewRows || !strings.HasPrefix(sess.BulkLabel, "api:") {
			t.Fatalf("status=%d rows=%d label=%q", rr.Code, len(sess.BulkRows), sess.BulkLabel)
		}
	})
	t.Run("db: both fields required; unreachable DSN fails fast", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"db"}, "db_conn": {"x"}}, "Connection string and SELECT query are both required.")
		expectErr(t, url.Values{"source": {"db"}, "db_conn": {"postgres://u:p@127.0.0.1:1/db?connect_timeout=1"}, "db_query": {"SELECT 1"}}, "Fetch failed:")
	})
	t.Run("registry: url + entity required, empty, ok", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"registry"}}, "Registry base URL is required")
		expectErr(t, url.Values{"source": {"registry"}, "reg_url": {"http://127.0.0.1:1"}}, "Registry entity is required.")
		empty := identityRegistryServer(t, `{"data":[]}`, `{"data":[{"name":"Person"}]}`)
		expectErr(t, url.Values{"source": {"registry"}, "reg_url": {empty.URL}, "reg_entity": {"Person"}}, "exists in the registry but has no records yet")
		srv := identityRegistryServer(t, `{"data":[{"individualId":"2001","fullName":"Cy"}]}`, `{"data":[]}`)
		rr, sess := post(url.Values{"source": {"registry"}, "reg_url": {srv.URL}, "reg_entity": {"Person"}})
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "registry:Person — 1 row") || len(sess.BulkRows) != 1 || len(sess.BulkColumns) != 2 || !containsStr(sess.BulkColumns, "individualId") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestIdentityBulkApply(t *testing.T) {
	f := identityFake()
	f.identities = map[string]map[string]string{}
	h, cookies := identityH(t, f, true)
	post := func(v url.Values, stash []map[string]string) (*httptest.ResponseRecorder, *Session) {
		req := formPost("/registrar/identities/apply", v, cookies...)
		sess := sessionOf(h, req)
		sess.BulkRows, sess.BulkLabel = stash, "csv"
		rr := httptest.NewRecorder()
		h.IdentityBulkApply(rr, req)
		return rr, sessionOf(h, req)
	}

	req := httptest.NewRequest(http.MethodPost, "/registrar/identities/apply", strings.NewReader("a=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.IdentityBulkApply(rr, req)
	if !strings.Contains(rr.Body.String(), "Bad form:") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	if rr, _ := post(nil, nil); !strings.Contains(rr.Body.String(), "Preview expired") {
		t.Fatalf("body=%s", rr.Body.String())
	}

	f.idUpsertErr = errors.New("write denied")
	stash := []map[string]string{
		{"nid": "1001", "name": "Ada"},
		{"nid": "", "name": "NoId"},
		{"nid": "1003", "name": ""},
	}
	rr, sess := post(url.Values{"mfield": {"individualId", "fullName", ""}, "mcol": {"nid", "name"}}, stash)
	body := rr.Body.String()
	if rr.Code != 200 || sess.BulkRows != nil || sess.BulkLabel != "" {
		t.Fatalf("status=%d stash not cleared", rr.Code)
	}
	for _, want := range []string{"csv — 3 rows", `<span class="mono" style="color:var(--ok)">0</span> enrolled`, "3</span> failed", "no individualId mapped", "row has no identity attributes", "write denied"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	f.idUpsertErr = nil
	rr, _ = post(url.Values{"mfield": {"individualId", "fullName"}, "mcol": {"nid", "name"}}, stash[:1])
	if !strings.Contains(rr.Body.String(), `>1</span> enrolled`) || f.identities["1001"]["fullName"] != "Ada" || len(f.idUpserts) != 1 {
		t.Fatalf("body=%s upserts=%+v", rr.Body.String(), f.idUpserts)
	}
}

func TestRunBulkIdentity_NoStore(t *testing.T) {
	h, _ := identityH(t, nil, true)
	rr := httptest.NewRecorder()
	h.runBulkIdentity(rr, httptest.NewRequest(http.MethodPost, "/", nil), &Session{}, nil, "csv")
	if !strings.Contains(rr.Body.String(), "identity registry not enabled") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestIdentityRegistryEntities(t *testing.T) {
	h, cookies := identityH(t, identityFake(), true)
	req := httptest.NewRequest(http.MethodPost, "/registrar/identities/entities", strings.NewReader("a=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.IdentityRegistryEntities(rr, req)
	if !strings.Contains(rr.Body.String(), "Enter the registry base URL") && !strings.Contains(rr.Body.String(), "URL") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	needURL := rr.Body.String()
	rr = httptest.NewRecorder()
	h.IdentityRegistryEntities(rr, formPost("/registrar/identities/entities", url.Values{}, cookies...))
	if rr.Body.String() != needURL {
		t.Fatalf("missing URL must render the same NeedURL fragment: %s", rr.Body.String())
	}
	srv := identityRegistryServer(t, `{}`, `{"data":[{"name":"Person"},{"name":"Schema"},{"name":"Vehicle"}]}`)
	rr = httptest.NewRecorder()
	h.IdentityRegistryEntities(rr, formPost("/registrar/identities/entities", url.Values{"reg_url": {srv.URL}}, cookies...))
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, ">Person</button>") || !strings.Contains(body, ">Vehicle</button>") || strings.Contains(body, ">Schema</button>") {
		t.Fatalf("status=%d body=%s", rr.Code, body)
	}
}

// TestIdentityBulkPreview_APILegacyContract pins the registrar's api source
// (unchanged by M3): the same legacy form (no api_mode) must yield one GET with
// Accept: application/json, the static Authorization header, the api_limit cap
// and an "api:<host>" label.
func TestIdentityBulkPreview_APILegacyContract(t *testing.T) {
	h, cookies := identityH(t, identityFake(), true)
	var gotMethod string
	var gotHdr http.Header
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotMethod, gotHdr = r.Method, r.Header.Clone()
		_, _ = w.Write([]byte(`[{"individualId":"1","fullName":"A"},{"individualId":"2","fullName":"B"},{"individualId":"3","fullName":"C"}]`))
	}))
	t.Cleanup(srv.Close)
	req := formPost("/registrar/identities/preview", url.Values{
		"source": {"api"}, "api_url": {srv.URL + "/citizens"}, "api_auth": {"X-Road-User EE/123"}, "api_limit": {"2"},
	}, cookies...)
	rr := httptest.NewRecorder()
	h.IdentityBulkPreview(rr, req)
	sess := sessionOf(h, req)
	if rr.Code != 200 || calls != 1 || gotMethod != http.MethodGet {
		t.Fatalf("status=%d calls=%d method=%s body=%s", rr.Code, calls, gotMethod, rr.Body.String())
	}
	if gotHdr.Get("Accept") != "application/json" || gotHdr.Get("Authorization") != "X-Road-User EE/123" {
		t.Fatalf("headers=%v", gotHdr)
	}
	if len(sess.BulkRows) != 2 || sess.BulkRows[1]["individualId"] != "2" || sess.BulkLabel != "api:"+strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("rows=%v label=%q", sess.BulkRows, sess.BulkLabel)
	}
}
