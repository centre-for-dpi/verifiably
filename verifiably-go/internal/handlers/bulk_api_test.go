package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// apiReq builds a urlencoded POST + a session whose SchemaID is "person"
// (the api_entity prefill) for buildAPISource.
func apiReq(t *testing.T, v url.Values) (apiSource, error) {
	t.Helper()
	h := &H{Sessions: NewStore()}
	req := formPost("/issuer/issue/bulk/preview", v)
	sess := sessionOf(h, req)
	sess.SchemaID = "person"
	return buildAPISource(req, sess)
}

func TestBuildAPISource(t *testing.T) {
	const cfg = `[{"id":"reg1","label":"Example Registry","url":"https://registry.example","entity":"Person","searchField":"personId",
		"tokenUrl":"https://idp.example/token","clientId":"cid","clientSecret":"sec","scope":"reg.read","insecureSkipVerify":true},
		{"id":"bare","label":"Bare","url":"https://bare.example"}]`
	t.Setenv("VERIFIABLY_REGISTRIES", cfg)

	t.Run("no fields -> get, defaults, entity from the schema", func(t *testing.T) {
		s, err := apiReq(t, url.Values{})
		if err != nil || s.Mode != "get" || s.URL != "" || s.SearchField != "individualId" || s.Entity != "person" || s.Limit != 0 || s.AuthHeader != "" || s.InsecureSkipVerify {
			t.Fatalf("s=%+v err=%v", s, err)
		}
	})
	t.Run("unknown request style", func(t *testing.T) {
		if _, err := apiReq(t, url.Values{"api_mode": {"soap"}}); err == nil || !strings.Contains(err.Error(), "unknown request style") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("pick supplies every field; configured entity beats the schema prefill", func(t *testing.T) {
		s, err := apiReq(t, url.Values{"api_mode": {"sunbird"}, "api_pick": {"reg1"}, "api_entity": {"person"}})
		if err != nil {
			t.Fatal(err)
		}
		if s.Mode != "sunbird" || s.ID != "reg1" || s.URL != "https://registry.example" || s.Entity != "Person" || s.SearchField != "personId" ||
			s.TokenURL != "https://idp.example/token" || s.ClientID != "cid" || s.ClientSecret != "sec" || s.Scope != "reg.read" || !s.InsecureSkipVerify {
			t.Fatalf("s=%+v", s)
		}
		// Empty form entity -> configured entity too.
		if s, _ := apiReq(t, url.Values{"api_pick": {"reg1"}}); s.Entity != "Person" {
			t.Fatalf("empty form entity: %+v", s)
		}
	})
	t.Run("a deliberately typed entity wins over the pick", func(t *testing.T) {
		if s, _ := apiReq(t, url.Values{"api_pick": {"reg1"}, "api_entity": {" Vehicle "}}); s.Entity != "Vehicle" {
			t.Fatalf("s=%+v", s)
		}
	})
	t.Run("pick without a configured entity: form entity, else schema", func(t *testing.T) {
		if s, _ := apiReq(t, url.Values{"api_pick": {"bare"}}); s.Entity != "person" || s.URL != "https://bare.example" {
			t.Fatalf("s=%+v", s)
		}
		if s, _ := apiReq(t, url.Values{"api_pick": {"bare"}, "api_entity": {"Vehicle"}}); s.Entity != "Vehicle" {
			t.Fatalf("s=%+v", s)
		}
		if s, _ := apiReq(t, url.Values{"api_pick": {"nope"}}); s.URL != "" || s.Entity != "person" {
			t.Fatalf("unknown pick must be a zero base: %+v", s)
		}
	})
	t.Run("manual fields override the pick", func(t *testing.T) {
		s, _ := apiReq(t, url.Values{
			"api_pick": {"reg1"}, "api_url": {" https://other.example/ "}, "api_search": {"uid"}, "api_auth": {"Bearer static"},
			"api_token_url": {"https://idp2.example/token"}, "api_client_id": {"c2"}, "api_client_secret": {"s2"}, "api_scope": {"x"}, "api_insecure": {"0"},
		})
		if s.URL != "https://other.example/" || s.SearchField != "uid" || s.AuthHeader != "Bearer static" || s.TokenURL != "https://idp2.example/token" ||
			s.ClientID != "c2" || s.ClientSecret != "s2" || s.Scope != "x" || s.InsecureSkipVerify {
			t.Fatalf("s=%+v", s)
		}
	})
	t.Run("api_insecure parsing", func(t *testing.T) {
		for _, v := range []string{"1", "on", "true", "TRUE"} {
			if s, _ := apiReq(t, url.Values{"api_insecure": {v}}); !s.InsecureSkipVerify {
				t.Fatalf("%q must enable", v)
			}
		}
		for _, v := range []string{"0", "false", "no"} {
			if s, _ := apiReq(t, url.Values{"api_pick": {"reg1"}, "api_insecure": {v}}); s.InsecureSkipVerify {
				t.Fatalf("%q must disable even with an insecure pick", v)
			}
		}
		if s, _ := apiReq(t, url.Values{"api_pick": {"reg1"}}); !s.InsecureSkipVerify {
			t.Fatal("absent checkbox keeps the pick's flag")
		}
	})
	t.Run("limit parsing", func(t *testing.T) {
		for in, want := range map[string]int{"": 0, "abc": 0, "3": 3, " 7 ": 7, "-2": 0, "3abc": 3} {
			if s, _ := apiReq(t, url.Values{"api_limit": {in}}); s.Limit != want {
				t.Fatalf("limit %q = %d, want %d", in, s.Limit, want)
			}
		}
	})
	t.Run("mode is trimmed and lower-cased", func(t *testing.T) {
		if s, err := apiReq(t, url.Values{"api_mode": {" Sunbird "}}); err != nil || s.Mode != "sunbird" {
			t.Fatalf("s=%+v err=%v", s, err)
		}
	})
}

func TestAPIAuthorization(t *testing.T) {
	ctx := context.Background()
	resetRegistryTokens(t)
	if got := apiAuthorization(ctx, apiSource{AuthHeader: "Bearer static"}); got != "Bearer static" {
		t.Fatalf("static got %q", got)
	}
	tok, _ := registryTokenServer(t, 200, `{"access_token":"grant","expires_in":3600}`)
	s := apiSource{AuthHeader: "Bearer static", registryProvider: registryProvider{TokenURL: tok.URL, ClientID: "c"}}
	if got := apiAuthorization(ctx, s); got != "Bearer grant" {
		t.Fatalf("token must override the static header, got %q", got)
	}
	bad, _ := registryTokenServer(t, 401, `{}`)
	s.TokenURL = bad.URL
	if got := apiAuthorization(ctx, s); got != "Bearer static" {
		t.Fatalf("failed grant must fall back to the static header, got %q", got)
	}
}

// apiSrcGET is the api-source shorthand for a GET fetch.
func apiSrcGET(u, auth string, limit int) apiSource {
	return apiSource{Mode: "get", AuthHeader: auth, Limit: limit, registryProvider: registryProvider{URL: u}}
}

func TestFetchGETRows(t *testing.T) {
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
	if _, err := fetchGETRows(ctx, apiSrcGET("http://bad host", "", 0)); err == nil {
		t.Fatal("bad URL must error")
	}
	if _, err := fetchGETRows(ctx, apiSrcGET("http://127.0.0.1:1/x", "", 0)); err == nil {
		t.Fatal("unreachable must error")
	}
	if _, err := fetchGETRows(ctx, apiSrcGET(serve(500, strings.Repeat("e", 300), nil).URL, "", 0)); err == nil || !strings.Contains(err.Error(), "HTTP 500: "+strings.Repeat("e", 200)+"…") {
		t.Fatalf("err=%v", err)
	}
	if _, err := fetchGETRows(ctx, apiSrcGET(serve(200, "{nope", nil).URL, "", 0)); err == nil || !strings.Contains(err.Error(), "decode JSON") {
		t.Fatalf("err=%v", err)
	}
	if _, err := fetchGETRows(ctx, apiSrcGET(serve(200, `{"other":1}`, nil).URL, "", 0)); err == nil || !strings.Contains(err.Error(), "not a JSON array") {
		t.Fatalf("err=%v", err)
	}
	if _, err := fetchGETRows(ctx, apiSrcGET(serve(200, `[1,"x"]`, nil).URL, "", 0)); err == nil || !strings.Contains(err.Error(), "array had 2 items, none were objects") {
		t.Fatalf("err=%v", err)
	}
	var hdr http.Header
	srv := serve(200, `{"rows":"no","items":[{"id":1,"name":"Ada","tags":["a"],"n":null},"skip",{"id":2},{"id":3}]}`, &hdr)
	rows, err := fetchGETRows(ctx, apiSrcGET(srv.URL, "Bearer tok", 3))
	if err != nil || len(rows) != 2 || rows[0]["id"] != "1" || rows[0]["tags"] != `["a"]` || rows[0]["n"] != "" || rows[1]["id"] != "2" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if hdr.Get("Authorization") != "Bearer tok" || hdr.Get("Accept") != "application/json" {
		t.Fatalf("headers=%v", hdr)
	}
	if rows, err = fetchGETRows(ctx, apiSrcGET(srv.URL, "", 0)); err != nil || len(rows) != 3 {
		t.Fatalf("limit 0 rows=%d err=%v", len(rows), err)
	}
	if _, has := hdr["Authorization"]; has {
		t.Fatalf("no auth expected: %v", hdr)
	}
	for _, key := range []string{"data", "results"} {
		if rows, err := fetchGETRows(ctx, apiSrcGET(serve(200, `{"`+key+`":[{"a":"b"}]}`, nil).URL, "", 0)); err != nil || len(rows) != 1 {
			t.Fatalf("%s envelope rows=%v err=%v", key, rows, err)
		}
	}

	t.Run("client_credentials token and insecure TLS", func(t *testing.T) {
		t.Setenv("VERIFIABLY_ENV", "")
		resetRegistryTokens(t)
		tok, _ := registryTokenServer(t, 200, `{"access_token":"G","expires_in":3600}`)
		var got http.Header
		tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Clone()
			_, _ = io.WriteString(w, `[{"id":"1"}]`)
		}))
		t.Cleanup(tls.Close)
		s := apiSrcGET(tls.URL, "Bearer static", 0)
		s.TokenURL, s.ClientID = tok.URL, "c"
		if _, err := fetchGETRows(ctx, s); err == nil {
			t.Fatal("verifying client must reject the self-signed API")
		}
		s.InsecureSkipVerify = true
		rows, err := fetchGETRows(ctx, s)
		if err != nil || len(rows) != 1 || got.Get("Authorization") != "Bearer G" {
			t.Fatalf("rows=%v err=%v auth=%q", rows, err, got.Get("Authorization"))
		}
	})
}

// fetchJSONRows (kept for the registrar) must be a pure wrapper: same rows and
// same error strings as fetchGETRows for the same inputs.
func TestFetchJSONRows_WrapsFetchGETRows(t *testing.T) {
	ctx := context.Background()
	ok := registryBodyServer(t, `[{"id":"1"},{"id":"2"},"x",{"id":"3"}]`)
	bad := registryBodyServer(t, `[]`)
	cases := []struct{ url, auth, limit string }{
		{ok.URL, "Bearer x", "2"}, {ok.URL, "", "0"}, {ok.URL, "", "abc"}, {bad.URL, "", ""}, {"http://127.0.0.1:1/x", "", ""},
	}
	for _, c := range cases {
		r1, e1 := fetchJSONRows(ctx, c.url, c.auth, c.limit)
		r2, e2 := fetchGETRows(ctx, apiSrcGET(c.url, c.auth, parseLimit(c.limit)))
		if !reflect.DeepEqual(r1, r2) || (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
			t.Fatalf("%+v: wrapper (%v,%v) != direct (%v,%v)", c, r1, e1, r2, e2)
		}
	}
}

// apiSrcSunbird is the api-source shorthand for a Sunbird RC search.
func apiSrcSunbird(u, entity, search string, limit int) apiSource {
	return apiSource{Mode: "sunbird", Limit: limit, registryProvider: registryProvider{URL: u, Entity: entity, SearchField: search}}
}

// sunbirdRowsServer records method/path/body/Authorization of every request
// and answers with status/body.
func sunbirdRowsServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type")+" "+r.Header.Get("Authorization")+" "+string(b))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestFetchSunbirdRows(t *testing.T) {
	ctx := context.Background()
	wantErr := func(t *testing.T, s apiSource, want string) {
		t.Helper()
		rows, err := fetchSunbirdRows(ctx, s)
		if err == nil || !strings.Contains(err.Error(), want) || rows != nil {
			t.Fatalf("want error %q, got rows=%v err=%v", want, rows, err)
		}
	}
	t.Run("validation", func(t *testing.T) {
		wantErr(t, apiSrcSunbird("", "Person", "", 0), "API URL is required.")
		wantErr(t, apiSrcSunbird("http://registry.example", "", "", 0), "Entity is required for Sunbird RC search.")
	})
	t.Run("POST search, data[] envelope, metadata stripped, individualId back-filled, limit", func(t *testing.T) {
		srv, seen := sunbirdRowsServer(t, 200, `{"totalCount":3,"data":[
			{"osid":"1","osOwner":["x"],"_osState":"live","personId":"P1","name":"Ada"},
			{"osid":"2","personId":"P2","name":"Bob","individualId":"keep"},
			"junk",
			{"osid":"3","personId":"P3","name":"Cy"}]}`)
		rows, err := fetchSunbirdRows(ctx, apiSrcSunbird(srv.URL+"/", "Person", "personId", 2))
		if err != nil || len(rows) != 2 {
			t.Fatalf("rows=%v err=%v", rows, err)
		}
		if rows[0]["individualId"] != "P1" || rows[0]["name"] != "Ada" || rows[1]["individualId"] != "keep" {
			t.Fatalf("rows=%v", rows)
		}
		for _, k := range []string{"osid", "osOwner", "_osState"} {
			if _, has := rows[0][k]; has {
				t.Fatalf("metadata %s must be stripped: %v", k, rows[0])
			}
		}
		if len(*seen) != 1 || (*seen)[0] != `POST /api/v1/Person/search application/json  {"filters":{}}` {
			t.Fatalf("seen=%v", *seen)
		}
		if rows, _ := fetchSunbirdRows(ctx, apiSrcSunbird(srv.URL, "Person", "personId", 0)); len(rows) != 3 {
			t.Fatalf("limit 0 rows=%d", len(rows))
		}
	})
	t.Run("{<entity>:[...]} envelope; default search field", func(t *testing.T) {
		srv, _ := sunbirdRowsServer(t, 200, `{"Person":[{"individualId":"9","name":"Zed"}]}`)
		rows, err := fetchSunbirdRows(ctx, apiSrcSunbird(srv.URL, "Person", "", 0))
		if err != nil || len(rows) != 1 || rows[0]["individualId"] != "9" {
			t.Fatalf("rows=%v err=%v", rows, err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		wantErr(t, apiSrcSunbird("http://bad host", "Person", "", 0), "invalid")
		wantErr(t, apiSrcSunbird("http://127.0.0.1:1", "Person", "", 0), "connection refused")
		nf, _ := sunbirdRowsServer(t, 404, `{"id":"sunbird-rc.registry.search","params":{"status":"UNSUCCESSFUL","errmsg":"Schema 'Vehicle' not found"},"responseCode":"OK"}`)
		wantErr(t, apiSrcSunbird(nf.URL, "Vehicle", "", 0), "HTTP 404: Schema 'Vehicle' not found")
		long, _ := sunbirdRowsServer(t, 400, `{"params":{"errmsg":"`+strings.Repeat("m", 300)+`"}}`)
		wantErr(t, apiSrcSunbird(long.URL, "Person", "", 0), "HTTP 400: "+strings.Repeat("m", 200)+"…")
		if _, err := fetchSunbirdRows(ctx, apiSrcSunbird(long.URL, "Person", "", 0)); strings.Contains(err.Error(), strings.Repeat("m", 201)) {
			t.Fatalf("errmsg must be capped at 200 chars: %v", err)
		}
		plain, _ := sunbirdRowsServer(t, 500, strings.Repeat("e", 300))
		wantErr(t, apiSrcSunbird(plain.URL, "Person", "", 0), "HTTP 500: "+strings.Repeat("e", 200)+"…")
		junk, _ := sunbirdRowsServer(t, 200, `{nope`)
		wantErr(t, apiSrcSunbird(junk.URL, "Person", "", 0), "decode JSON")
		empty, _ := sunbirdRowsServer(t, 200, `{"data":[]}`)
		wantErr(t, apiSrcSunbird(empty.URL, "Person", "", 0), "entity 'Person' has no records")
		nulls, _ := sunbirdRowsServer(t, 200, `{"data":[{"osid":"1","x":null}]}`)
		wantErr(t, apiSrcSunbird(nulls.URL, "Person", "", 0), "entity 'Person' has no records")
	})
	t.Run("client_credentials token and insecure TLS", func(t *testing.T) {
		t.Setenv("VERIFIABLY_ENV", "")
		resetRegistryTokens(t)
		tok, _ := registryTokenServer(t, 200, `{"access_token":"R","expires_in":3600}`)
		var auth string
		tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, `{"data":[{"individualId":"1"}]}`)
		}))
		t.Cleanup(tls.Close)
		s := apiSrcSunbird(tls.URL, "Person", "", 0)
		s.TokenURL, s.ClientID = tok.URL, "c"
		if _, err := fetchSunbirdRows(ctx, s); err == nil {
			t.Fatal("verifying client must reject the self-signed registry")
		}
		s.InsecureSkipVerify = true
		if rows, err := fetchSunbirdRows(ctx, s); err != nil || len(rows) != 1 || auth != "Bearer R" {
			t.Fatalf("rows=%v err=%v auth=%q", rows, err, auth)
		}
	})
}

func TestFetchAPIRows_Dispatch(t *testing.T) {
	ctx := context.Background()
	get := registryBodyServer(t, `[{"id":"g"}]`)
	sb, _ := sunbirdRowsServer(t, 200, `{"data":[{"individualId":"s"}]}`)
	if rows, err := fetchAPIRows(ctx, apiSrcGET(get.URL, "", 0)); err != nil || rows[0]["id"] != "g" {
		t.Fatalf("get rows=%v err=%v", rows, err)
	}
	if rows, err := fetchAPIRows(ctx, apiSrcSunbird(sb.URL, "Person", "", 0)); err != nil || rows[0]["individualId"] != "s" {
		t.Fatalf("sunbird rows=%v err=%v", rows, err)
	}
}

// ── handlers (§6.5-7) ───────────────────────────────────────────────────────

func TestBulkPreview_APISunbird(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{}, "csv", "api", "db")
	expectErr := func(t *testing.T, v url.Values, want string) {
		t.Helper()
		rr, _ := bulkPost(h, h.BulkPreview, v, cookies)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("want %q; status=%d body=%s", want, rr.Code, rr.Body.String())
		}
	}
	t.Run("form validation", func(t *testing.T) {
		expectErr(t, url.Values{"source": {"api"}, "api_mode": {"soap"}, "api_url": {"http://x"}}, "unknown request style")
		expectErr(t, url.Values{"source": {"api"}, "api_mode": {"sunbird"}}, "API URL is required.")
	})
	t.Run("pick with the untouched schema prefill -> configured entity, rows, label api:<entity>", func(t *testing.T) {
		srv, seen := sunbirdRowsServer(t, 200, `{"data":[{"osid":"1","personId":"P1","name":"Ada","birthDate":"1990-01-01"},{"osid":"2","personId":"P2","name":"Bob","birthDate":"1991-02-02"}]}`)
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg1","label":"Example Registry","url":"`+srv.URL+`","entity":"Person","searchField":"personId"}]`)
		rr, sess := bulkPost(h, h.BulkPreview, url.Values{"source": {"api"}, "api_mode": {"sunbird"}, "api_pick": {"reg1"}, "api_url": {srv.URL}, "api_entity": {"person"}}, cookies)
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "api:Person — 2 rows · map columns → fields") || !strings.Contains(body, `<option value="name" selected>`) {
			t.Fatalf("status=%d body=%s", rr.Code, body)
		}
		if sess.BulkLabel != "api:Person" || len(sess.BulkRows) != 2 || sess.BulkRows[0]["individualId"] != "P1" || !containsStr(sess.BulkColumns, "individualId") {
			t.Fatalf("label=%q rows=%v cols=%v", sess.BulkLabel, sess.BulkRows, sess.BulkColumns)
		}
		if len(*seen) != 1 || !strings.HasPrefix((*seen)[0], "POST /api/v1/Person/search") {
			t.Fatalf("seen=%v", *seen)
		}
	})
	t.Run("sunbird HTTP error surfaces the registry's message", func(t *testing.T) {
		nf, _ := sunbirdRowsServer(t, 404, `{"params":{"errmsg":"Schema 'x' not found"}}`)
		expectErr(t, url.Values{"source": {"api"}, "api_mode": {"sunbird"}, "api_url": {nf.URL}, "api_entity": {"x"}}, "Fetch failed: HTTP 404: Schema &#39;x&#39; not found")
		empty, _ := sunbirdRowsServer(t, 200, `{"data":[]}`)
		expectErr(t, url.Values{"source": {"api"}, "api_mode": {"sunbird"}, "api_url": {empty.URL}, "api_entity": {"Person"}}, "Fetch failed: entity &#39;Person&#39; has no records")
	})
	t.Run("get mode keeps the host label", func(t *testing.T) {
		get := registryBodyServer(t, `[{"name":"Ada","birthDate":"1990-01-01"}]`)
		rr, sess := bulkPost(h, h.BulkPreview, url.Values{"source": {"api"}, "api_mode": {"get"}, "api_url": {get.URL + "/rows"}}, cookies)
		if rr.Code != 200 || sess.BulkLabel != "api:"+strings.TrimPrefix(get.URL, "http://") {
			t.Fatalf("status=%d label=%q", rr.Code, sess.BulkLabel)
		}
	})
}

func TestBulkAPIEntities(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{})
	req := httptest.NewRequest(http.MethodPost, "/issuer/issue/bulk/api-entities", strings.NewReader("a=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.BulkAPIEntities(rr, req)
	needURL := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(needURL, "Enter a registry base URL") {
		t.Fatalf("status=%d body=%s", rr.Code, needURL)
	}
	if rr, _ := bulkPost(h, h.BulkAPIEntities, url.Values{"api_mode": {"sunbird"}}, cookies); rr.Body.String() != needURL {
		t.Fatalf("missing URL must render the same NeedURL fragment: %s", rr.Body.String())
	}
	if rr, _ := bulkPost(h, h.BulkAPIEntities, url.Values{"api_mode": {"bogus"}, "api_url": {"http://x"}}, cookies); rr.Body.String() != needURL {
		t.Fatalf("bad mode must render the NeedURL fragment: %s", rr.Body.String())
	}
	none, _ := swaggerServer(t, "", "", "")
	rr, _ = bulkPost(h, h.BulkAPIEntities, url.Values{"api_url": {none.URL}}, cookies)
	if b := rr.Body.String(); !strings.Contains(b, "No entities found at "+none.URL) || !strings.Contains(b, "/api/v1/Schema/search") || !strings.Contains(b, "/api/docs/swagger.json") {
		t.Fatalf("body=%s", b)
	}
	viaSchema, _ := swaggerServer(t, swagger2Doc, "", `{"data":[{"name":"Person"},{"name":"ZzProbe"}]}`)
	rr, _ = bulkPost(h, h.BulkAPIEntities, url.Values{"api_url": {viaSchema.URL}}, cookies)
	if b := rr.Body.String(); !strings.Contains(b, `onclick="this.closest('form').elements['api_entity'].value='Person'"`) || strings.Contains(b, "ZzProbe") || strings.Contains(b, "listed from Swagger") {
		t.Fatalf("body=%s", b)
	}
	viaSwagger, _ := swaggerServer(t, swagger2Doc, "", "")
	rr, _ = bulkPost(h, h.BulkAPIEntities, url.Values{"api_url": {viaSwagger.URL}}, cookies)
	if b := rr.Body.String(); !strings.Contains(b, ">Vehicle</button>") || !strings.Contains(b, ">Person</button>") || !strings.Contains(b, "listed from Swagger") || !strings.Contains(b, "elements['api_entity']") {
		t.Fatalf("body=%s", b)
	}
	// A configured pick supplies the URL.
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg1","label":"Example Registry","url":"`+viaSchema.URL+`"}]`)
	rr, _ = bulkPost(h, h.BulkAPIEntities, url.Values{"api_pick": {"reg1"}}, cookies)
	if !strings.Contains(rr.Body.String(), ">Person</button>") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

// The registry chip's discover keeps its contract and now targets reg_entity
// explicitly (and falls back to Swagger).
func TestBulkRegistryEntities_TargetAndVia(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{})
	viaSchema, _ := swaggerServer(t, "", "", `{"data":[{"name":"Person"}]}`)
	rr, _ := bulkPost(h, h.BulkRegistryEntities, url.Values{"reg_url": {viaSchema.URL}}, cookies)
	if b := rr.Body.String(); !strings.Contains(b, `onclick="this.closest('form').elements['reg_entity'].value='Person'"`) || strings.Contains(b, "listed from Swagger") {
		t.Fatalf("body=%s", b)
	}
	viaSwagger, _ := swaggerServer(t, openapi3Doc, "", "")
	rr, _ = bulkPost(h, h.BulkRegistryEntities, url.Values{"reg_url": {viaSwagger.URL}}, cookies)
	if b := rr.Body.String(); !strings.Contains(b, "elements['reg_entity'].value='Person'") || !strings.Contains(b, "listed from Swagger") {
		t.Fatalf("body=%s", b)
	}
}

func TestRegistryEmptyMessage_Provider(t *testing.T) {
	ctx := context.Background()
	none, _ := swaggerServer(t, "", "", "")
	if got := registryEmptyMessage(ctx, registryProvider{URL: none.URL}, "Person"); !strings.Contains(got, "Couldn't reach the registry at "+none.URL+", or it has no registered entities") || !strings.Contains(got, "Swagger") {
		t.Fatalf("got %q", got)
	}
	viaSwagger, _ := swaggerServer(t, openapi3Doc, "", "")
	if got := registryEmptyMessage(ctx, registryProvider{URL: viaSwagger.URL}, "Vehicle"); !strings.Contains(got, "no entity named 'Vehicle'. Available: Person.") {
		t.Fatalf("got %q", got)
	}
	if got := registryEmptyMessage(ctx, registryProvider{URL: viaSwagger.URL}, "Person"); !strings.Contains(got, "exists in the registry but has no records yet") {
		t.Fatalf("got %q", got)
	}
	// Token + insecure flags travel with the provider (a 401-only registry).
	t.Setenv("VERIFIABLY_ENV", "")
	resetRegistryTokens(t)
	tok, _ := registryTokenServer(t, 200, `{"access_token":"E","expires_in":3600}`)
	gated := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer E" {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"name":"Person"}]}`)
	}))
	t.Cleanup(gated.Close)
	p := registryProvider{URL: gated.URL, TokenURL: tok.URL, ClientID: "c", InsecureSkipVerify: true}
	if got := registryEmptyMessage(ctx, p, "Person"); !strings.Contains(got, "has no records yet") {
		t.Fatalf("got %q", got)
	}
}

// ── template (§6.5-8) ───────────────────────────────────────────────────────

func TestBulkSource_APIFormTemplate(t *testing.T) {
	h, cookies := bulkH(t, &issueAdapter{}, "csv", "api", "db")
	render := func(t *testing.T) string {
		t.Helper()
		rr, _ := bulkPost(h, h.BulkSource, url.Values{"source": {"api"}}, cookies)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	t.Run("no registries configured", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", "")
		b := render(t)
		for _, want := range []string{
			`name="source" value="api"`, `name="api_mode" value="get" checked`, `name="api_mode" value="sunbird"`,
			`name="api_url"`, `name="api_entity" value="person"`, `name="api_search" value="individualId"`, `name="api_auth"`,
			`name="api_token_url"`, `name="api_client_id"`, `name="api_client_secret"`, `type="password"`, `name="api_scope"`,
			`name="api_insecure" value="1"`, `name="api_limit"`, `id="api-entities"`, `hx-post="/issuer/issue/bulk/api-entities"`,
			`data-mode="sunbird"`, `<script>`, `Sunbird RC`,
		} {
			if !strings.Contains(b, want) {
				t.Errorf("api form lacks %q", want)
			}
		}
		if strings.Contains(b, `name="api_pick"`) {
			t.Error("api_pick must not render without configured registries")
		}
	})
	t.Run("configured registries: picker carries url/entity/search only, never secrets", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"reg1","label":"Example Registry","url":"https://registry.example","entity":"Person","searchField":"personId",
			"tokenUrl":"https://token-host.test/oauth2/token","clientId":"cid-visible?","clientSecret":"S3CRET-VALUE","scope":"reg.read.hidden","insecureSkipVerify":true}]`)
		b := render(t)
		if !strings.Contains(b, `name="api_pick"`) || !strings.Contains(b, `<option value="reg1" data-url="https://registry.example" data-entity="Person" data-search="personId">Example Registry`) {
			t.Fatalf("picker missing/incomplete: %s", b)
		}
		for _, leak := range []string{"S3CRET-VALUE", "cid-visible?", "token-host.test", "reg.read.hidden"} {
			if strings.Contains(b, leak) {
				t.Errorf("secret/config %q leaked into HTML", leak)
			}
		}
	})
}

// The registrar page keeps its legacy api form untouched.
func TestIdentityBulkSource_APIFormUnchanged(t *testing.T) {
	h, cookies := identityH(t, identityFake(), true)
	req := formPost("/registrar/identities/source", url.Values{"source": {"api"}}, cookies...)
	rr := httptest.NewRecorder()
	h.IdentityBulkSource(rr, req)
	b := rr.Body.String()
	for _, want := range []string{`name="api_url"`, `name="api_auth"`, `name="api_limit"`} {
		if !strings.Contains(b, want) {
			t.Errorf("registrar api form lacks %q", want)
		}
	}
	for _, no := range []string{`name="api_mode"`, `name="api_pick"`, `name="api_entity"`, `api-entities`} {
		if strings.Contains(b, no) {
			t.Errorf("registrar api form must not contain %q", no)
		}
	}
}
