package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// resetRegistryTokens empties the client_credentials token cache so each test
// observes its own fetches.
func resetRegistryTokens(t *testing.T) {
	t.Helper()
	reset := func() {
		registryTokens.Lock()
		registryTokens.m = map[string]registryToken{}
		registryTokens.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// registryTokenServer is a minimal OAuth2 client_credentials token endpoint.
// It records every request body and answers with the given status/body.
func registryTokenServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.Method+" "+r.Header.Get("Content-Type")+" "+string(b))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func TestRegistryProviders_AuthAndTLSFields(t *testing.T) {
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"r","label":"Registry","url":"https://registry.example","entity":"Person","searchField":"individualId",
		"tokenUrl":"https://idp.example/oauth2/token","clientId":"cid","clientSecret":"sec","scope":"registry.read","insecureSkipVerify":true}]`)
	ps := registryProviders()
	if len(ps) != 1 {
		t.Fatalf("len=%d", len(ps))
	}
	p := ps[0]
	if p.TokenURL != "https://idp.example/oauth2/token" || p.ClientID != "cid" || p.ClientSecret != "sec" || p.Scope != "registry.read" || !p.InsecureSkipVerify {
		t.Fatalf("fields: %+v", p)
	}
	// Omitted fields stay zero.
	t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"r","url":"https://registry.example"}]`)
	if p := registryProviders()[0]; p.TokenURL != "" || p.InsecureSkipVerify {
		t.Fatalf("zero fields: %+v", p)
	}
}

func TestRegistryClient(t *testing.T) {
	tlsOf := func(c *http.Client) bool {
		tr, ok := c.Transport.(*http.Transport)
		return ok && tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify
	}
	t.Run("default: shared timeout client, verifying TLS", func(t *testing.T) {
		t.Setenv("VERIFIABLY_ENV", "")
		c := registryClient(registryProvider{URL: "https://registry.example"})
		if c != registryHTTPClient || tlsOf(c) || c.Timeout != 30*time.Second {
			t.Fatalf("client=%+v", c)
		}
	})
	t.Run("insecureSkipVerify: dedicated client skips verification", func(t *testing.T) {
		t.Setenv("VERIFIABLY_ENV", "development")
		c := registryClient(registryProvider{URL: "https://registry.example", InsecureSkipVerify: true})
		if c == registryHTTPClient || !tlsOf(c) || c.Timeout != 30*time.Second {
			t.Fatalf("client=%+v", c)
		}
		// Proves it actually talks to a self-signed server.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
		t.Cleanup(srv.Close)
		resp, err := c.Get(srv.URL)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("insecure GET: %v", err)
		}
		resp.Body.Close()
	})
	t.Run("production refuses insecureSkipVerify", func(t *testing.T) {
		t.Setenv("VERIFIABLY_ENV", "production")
		if c := registryClient(registryProvider{URL: "https://registry.example", InsecureSkipVerify: true}); c != registryHTTPClient || tlsOf(c) {
			t.Fatalf("client=%+v", c)
		}
	})
}

func TestRegistryAuthHeader(t *testing.T) {
	ctx := context.Background()
	t.Run("no tokenUrl -> empty", func(t *testing.T) {
		resetRegistryTokens(t)
		if got := registryAuthHeader(ctx, registryProvider{URL: "https://registry.example"}); got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("token fetched once, form-encoded client_credentials, cached", func(t *testing.T) {
		resetRegistryTokens(t)
		srv, bodies := registryTokenServer(t, 200, `{"access_token":"tok1","token_type":"Bearer","expires_in":3600}`)
		p := registryProvider{URL: "https://registry.example", TokenURL: srv.URL, ClientID: "cid", ClientSecret: "s3cret", Scope: "registry.read"}
		if got := registryAuthHeader(ctx, p); got != "Bearer tok1" {
			t.Fatalf("got %q", got)
		}
		if got := registryAuthHeader(ctx, p); got != "Bearer tok1" {
			t.Fatalf("cached got %q", got)
		}
		if len(*bodies) != 1 {
			t.Fatalf("token endpoint called %d times, want 1: %v", len(*bodies), *bodies)
		}
		b := (*bodies)[0]
		if !strings.HasPrefix(b, "POST application/x-www-form-urlencoded ") || !strings.Contains(b, "grant_type=client_credentials") ||
			!strings.Contains(b, "client_id=cid") || !strings.Contains(b, "client_secret=s3cret") || !strings.Contains(b, "scope=registry.read") {
			t.Fatalf("body=%q", b)
		}
	})
	t.Run("scope omitted when empty; short expiry is refreshed", func(t *testing.T) {
		resetRegistryTokens(t)
		srv, bodies := registryTokenServer(t, 200, `{"access_token":"tok","expires_in":30}`)
		p := registryProvider{TokenURL: srv.URL, ClientID: "cid", ClientSecret: "s"}
		registryAuthHeader(ctx, p)
		registryAuthHeader(ctx, p)
		if len(*bodies) != 2 || strings.Contains((*bodies)[0], "scope=") {
			t.Fatalf("bodies=%v", *bodies)
		}
	})
	t.Run("expires_in 0 -> 5-minute default", func(t *testing.T) {
		resetRegistryTokens(t)
		srv, _ := registryTokenServer(t, 200, `{"access_token":"tok"}`)
		p := registryProvider{TokenURL: srv.URL, ClientID: "cid"}
		before := time.Now()
		if got := registryAuthHeader(ctx, p); got != "Bearer tok" {
			t.Fatalf("got %q", got)
		}
		registryTokens.Lock()
		defer registryTokens.Unlock()
		if len(registryTokens.m) != 1 {
			t.Fatalf("cache=%v", registryTokens.m)
		}
		for _, e := range registryTokens.m {
			if d := e.expiry.Sub(before); d < 4*time.Minute || d > 6*time.Minute {
				t.Fatalf("expiry %v from now, want ~5m", d)
			}
		}
	})
	t.Run("failures degrade to empty", func(t *testing.T) {
		resetRegistryTokens(t)
		bad, _ := registryTokenServer(t, 401, `{"error":"invalid_client"}`)
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: bad.URL, ClientID: "c"}); got != "" {
			t.Fatalf("401 got %q", got)
		}
		junk, _ := registryTokenServer(t, 200, `{nope`)
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: junk.URL, ClientID: "c"}); got != "" {
			t.Fatalf("junk got %q", got)
		}
		empty, _ := registryTokenServer(t, 200, `{"access_token":""}`)
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: empty.URL, ClientID: "c"}); got != "" {
			t.Fatalf("empty token got %q", got)
		}
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: "http://127.0.0.1:1/token", ClientID: "c"}); got != "" {
			t.Fatalf("unreachable got %q", got)
		}
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: "http://bad host/token", ClientID: "c"}); got != "" {
			t.Fatalf("bad url got %q", got)
		}
	})
	t.Run("insecure token endpoint honours InsecureSkipVerify", func(t *testing.T) {
		resetRegistryTokens(t)
		t.Setenv("VERIFIABLY_ENV", "")
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"access_token":"tls","expires_in":60}`)
		}))
		t.Cleanup(srv.Close)
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: srv.URL, ClientID: "c"}); got != "" {
			t.Fatalf("verifying client must reject the self-signed cert, got %q", got)
		}
		if got := registryAuthHeader(ctx, registryProvider{TokenURL: srv.URL, ClientID: "c", InsecureSkipVerify: true}); got != "Bearer tls" {
			t.Fatalf("insecure got %q", got)
		}
	})
}

// registryCapture is a Sunbird-shaped fake that records the Authorization
// header of every request and answers /Schema/search with `schemas`, anything
// else with `rows`.
func registryCapture(t *testing.T, tlsMode bool, rows, schemas string) (*httptest.Server, *[]string) {
	t.Helper()
	var auths []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		if strings.HasSuffix(r.URL.Path, "/Schema/search") {
			_, _ = io.WriteString(w, schemas)
			return
		}
		_, _ = io.WriteString(w, rows)
	})
	var srv *httptest.Server
	if tlsMode {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, &auths
}

// Every registry call (Schema/search, entity search, bulk search, legacy GET)
// goes through registryClient(p) and carries the client_credentials token.
func TestRegistryCalls_AuthAndTLS(t *testing.T) {
	ctx := context.Background()
	t.Setenv("VERIFIABLY_ENV", "")
	resetRegistryTokens(t)
	tok, _ := registryTokenServer(t, 200, `{"access_token":"T","expires_in":3600}`)
	rec := `{"data":[{"osid":"1","individualId":"1001","name":"Ada"}]}`
	schemas := `{"data":[{"name":"Person"}]}`

	t.Run("plain: Bearer token on all four calls", func(t *testing.T) {
		srv, auths := registryCapture(t, false, rec, schemas)
		p := registryProvider{URL: srv.URL, Entity: "Person", Path: "/r/", TokenURL: tok.URL, ClientID: "c", ClientSecret: "s"}
		if got := sunbirdSchemas(ctx, p); len(got) != 1 || got[0] != "Person" {
			t.Fatalf("schemas=%v", got)
		}
		if got := fetchRegistrySunbird(ctx, p, "1001"); got["name"] != "Ada" {
			t.Fatalf("sunbird=%v", got)
		}
		if got := searchRegistryAll(ctx, p, "Person"); len(got) != 1 || got[0]["individualId"] != "1001" {
			t.Fatalf("all=%v", got)
		}
		legacy := p
		legacy.Entity = ""
		if got := fetchRegistryByEntity(ctx, legacy, "1001"); len(got[""]) == 0 {
			t.Fatalf("legacy=%v", got)
		}
		if len(*auths) != 4 {
			t.Fatalf("calls=%d", len(*auths))
		}
		for i, a := range *auths {
			if a != "Bearer T" {
				t.Fatalf("call %d Authorization=%q", i, a)
			}
		}
	})
	t.Run("no tokenUrl: no Authorization header", func(t *testing.T) {
		srv, auths := registryCapture(t, false, rec, schemas)
		sunbirdSchemas(ctx, registryProvider{URL: srv.URL})
		if len(*auths) != 1 || (*auths)[0] != "" {
			t.Fatalf("auths=%v", *auths)
		}
	})
	t.Run("self-signed registry: rejected unless insecureSkipVerify", func(t *testing.T) {
		srv, _ := registryCapture(t, true, rec, schemas)
		p := registryProvider{URL: srv.URL, Entity: "Person"}
		if got := sunbirdSchemas(ctx, p); got != nil {
			t.Fatalf("verifying client must fail: %v", got)
		}
		p.InsecureSkipVerify = true
		if got := sunbirdSchemas(ctx, p); len(got) != 1 {
			t.Fatalf("insecure schemas=%v", got)
		}
		if got := searchRegistryAll(ctx, p, "Person"); len(got) != 1 {
			t.Fatalf("insecure all=%v", got)
		}
		if got := fetchRegistrySunbird(ctx, p, "1001"); got["name"] != "Ada" {
			t.Fatalf("insecure sunbird=%v", got)
		}
	})
	t.Run("unbuildable URL degrades to empty on all four", func(t *testing.T) {
		p := registryProvider{URL: "http://bad host", Entity: "Person", Path: "/r/"}
		if sunbirdSchemas(ctx, p) != nil || fetchRegistrySunbird(ctx, p, "1") != nil || searchRegistryAll(ctx, p, "Person") != nil {
			t.Fatal("bad URL must yield nil")
		}
		p.Entity = ""
		if got := fetchRegistryByEntity(ctx, p, "1"); len(got) != 0 {
			t.Fatalf("legacy bad URL=%v", got)
		}
	})
}

// swaggerServer serves `docs` at /api/docs/swagger.json and `root` at
// /swagger.json (404 when empty), records paths + Authorization, and answers
// /Schema/search with `schemas`.
func swaggerServer(t *testing.T, docs, root, schemas string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		body := ""
		switch r.URL.Path {
		case "/api/docs/swagger.json":
			body = docs
		case "/swagger.json":
			body = root
		case "/api/v1/Schema/search":
			body = schemas
		}
		if body == "" {
			w.WriteHeader(404)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

const swagger2Doc = `{"swagger":"2.0","paths":{
  "/api/v1/Vehicle":{"post":{}}, "/api/v1/Vehicle/search":{"post":{}}, "/api/v1/Vehicle/{id}":{"get":{}},
  "/api/v1/Person":{"post":{}}, "/api/v1/Person/search":{"post":{}},
  "/api/v1/Schema":{"post":{}}, "/api/v1/ZzProbe":{"post":{}}, "/api/v1/{entityName}":{"post":{}},
  "/api/v1/9Bad":{"post":{}}, "/health":{"get":{}}}}`

const openapi3Doc = `{"openapi":"3.0.1","info":{"title":"registry"},"paths":{"/api/v1/Person":{"post":{}},"/api/v1/Person/search":{"post":{}}}}`

func TestSwaggerEntities(t *testing.T) {
	ctx := context.Background()
	t.Run("Swagger 2 paths -> unique sorted entities minus Schema/ZzProbe", func(t *testing.T) {
		srv, seen := swaggerServer(t, swagger2Doc, "", "")
		got := swaggerEntities(ctx, registryProvider{URL: srv.URL + "/"})
		if len(got) != 2 || got[0] != "Person" || got[1] != "Vehicle" {
			t.Fatalf("got %v", got)
		}
		if len(*seen) != 1 || (*seen)[0] != "GET /api/docs/swagger.json " {
			t.Fatalf("seen=%v", *seen)
		}
	})
	t.Run("OpenAPI 3 paths parse the same way", func(t *testing.T) {
		srv, _ := swaggerServer(t, openapi3Doc, "", "")
		if got := swaggerEntities(ctx, registryProvider{URL: srv.URL}); len(got) != 1 || got[0] != "Person" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("falls back to /swagger.json", func(t *testing.T) {
		srv, seen := swaggerServer(t, "", openapi3Doc, "")
		if got := swaggerEntities(ctx, registryProvider{URL: srv.URL}); len(got) != 1 || got[0] != "Person" {
			t.Fatalf("got %v", got)
		}
		if len(*seen) != 2 || !strings.HasPrefix((*seen)[1], "GET /swagger.json") {
			t.Fatalf("seen=%v", *seen)
		}
	})
	t.Run("both missing / invalid JSON / no paths / unreachable / bad URL -> nil", func(t *testing.T) {
		srv, _ := swaggerServer(t, "", "", "")
		if got := swaggerEntities(ctx, registryProvider{URL: srv.URL}); got != nil {
			t.Fatalf("404s got %v", got)
		}
		junk, _ := swaggerServer(t, "{nope", "", "")
		if got := swaggerEntities(ctx, registryProvider{URL: junk.URL}); got != nil {
			t.Fatalf("junk got %v", got)
		}
		none, _ := swaggerServer(t, `{"paths":{"/health":{}}}`, "", "")
		if got := swaggerEntities(ctx, registryProvider{URL: none.URL}); got != nil {
			t.Fatalf("no entities got %v", got)
		}
		if got := swaggerEntities(ctx, registryProvider{URL: "http://127.0.0.1:1"}); got != nil {
			t.Fatalf("unreachable got %v", got)
		}
		if got := swaggerEntities(ctx, registryProvider{URL: "http://bad host"}); got != nil {
			t.Fatalf("bad URL got %v", got)
		}
	})
	t.Run("token + insecure TLS", func(t *testing.T) {
		t.Setenv("VERIFIABLY_ENV", "")
		resetRegistryTokens(t)
		tok, _ := registryTokenServer(t, 200, `{"access_token":"S","expires_in":3600}`)
		srv, seen := swaggerServer(t, swagger2Doc, "", "")
		swaggerEntities(ctx, registryProvider{URL: srv.URL, TokenURL: tok.URL, ClientID: "c"})
		if len(*seen) != 1 || !strings.HasSuffix((*seen)[0], " Bearer S") {
			t.Fatalf("seen=%v", *seen)
		}
		tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, openapi3Doc) }))
		t.Cleanup(tls.Close)
		if got := swaggerEntities(ctx, registryProvider{URL: tls.URL}); got != nil {
			t.Fatalf("verifying client must fail: %v", got)
		}
		if got := swaggerEntities(ctx, registryProvider{URL: tls.URL, InsecureSkipVerify: true}); len(got) != 1 {
			t.Fatalf("insecure got %v", got)
		}
	})
}

func TestDiscoverEntities(t *testing.T) {
	ctx := context.Background()
	t.Run("Schema/search wins", func(t *testing.T) {
		srv, seen := swaggerServer(t, swagger2Doc, "", `{"data":[{"name":"Person"}]}`)
		names, via := discoverEntities(ctx, registryProvider{URL: srv.URL})
		if via != "schema" || len(names) != 1 || names[0] != "Person" || len(*seen) != 1 {
			t.Fatalf("names=%v via=%q seen=%v", names, via, *seen)
		}
	})
	t.Run("swagger fallback", func(t *testing.T) {
		srv, _ := swaggerServer(t, swagger2Doc, "", "")
		names, via := discoverEntities(ctx, registryProvider{URL: srv.URL})
		if via != "swagger" || len(names) != 2 {
			t.Fatalf("names=%v via=%q", names, via)
		}
	})
	t.Run("nothing", func(t *testing.T) {
		srv, _ := swaggerServer(t, "", "", "")
		if names, via := discoverEntities(ctx, registryProvider{URL: srv.URL}); via != "" || names != nil {
			t.Fatalf("names=%v via=%q", names, via)
		}
	})
}

// Reviewer finding (step 5): a transport-level failure on the first Swagger
// candidate must fall through to <url>/swagger.json, not give up.
func TestSwaggerEntities_TransportErrorFallsBack(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.URL.Path == "/api/docs/swagger.json" {
			// Hijack and close: the client sees an EOF/transport error, not a status.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			conn.Close()
			return
		}
		_, _ = io.WriteString(w, openapi3Doc)
	}))
	t.Cleanup(srv.Close)
	got := swaggerEntities(context.Background(), registryProvider{URL: srv.URL})
	if len(got) != 1 || got[0] != "Person" {
		t.Fatalf("got %v (seen=%v)", got, seen)
	}
	if len(seen) != 2 || seen[0] != "/api/docs/swagger.json" || seen[1] != "/swagger.json" {
		t.Fatalf("seen=%v", seen)
	}
}
