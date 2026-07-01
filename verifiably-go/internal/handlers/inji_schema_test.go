package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// ─── fakeSubjects ─────────────────────────────────────────────────────────────

// provCall records a ProvisionSubject invocation so tests can assert the
// subject id + claims that a handler computed and forwarded.
type provCall struct {
	subjectID string
	claims    map[string]string
}

// fakeSubjects is a hand-rolled SubjectProvisioner for handler tests. Only the
// behaviour each test needs is populated; ApplyAuthcodeSchema / CredentialClaimSpec
// default to no-ops. ProvisionSubject calls are captured for assertions.
type fakeSubjects struct {
	provCalls []provCall
	provErr   error

	listCreds    []map[string]string
	listCredsErr error
	myCreds      []map[string]string
	fieldsByKey  map[string][]string
	scopeByKey   map[string]string

	// Identity registry: GetIdentity reads `identities`; UpsertIdentity writes it
	// and appends to `idUpserts` (reusing provCall: subjectID=individualId,
	// claims=demographics) for assertions.
	identities map[string]map[string]string
	idUpserts  []provCall

	deletedCreds []string // keys passed to DeleteCredential
}

func (f *fakeSubjects) ProvisionSubject(_ context.Context, subjectID string, claims map[string]string) error {
	f.provCalls = append(f.provCalls, provCall{subjectID: subjectID, claims: claims})
	return f.provErr
}
func (f *fakeSubjects) ListCredentials(_ context.Context) ([]map[string]string, error) {
	return f.listCreds, f.listCredsErr
}
func (f *fakeSubjects) CredentialScope(_ context.Context, key string) (string, error) {
	return f.scopeByKey[key], nil
}
func (f *fakeSubjects) CredentialClaimSpec(_ context.Context, _ string) (string, string, string, error) {
	return "", "", "", nil
}
func (f *fakeSubjects) ApplyAuthcodeSchema(_ context.Context, _, _, _, _, _, _ string, _ []string, _, _, _, _ *string, _ string) error {
	return nil
}
func (f *fakeSubjects) ListMyCredentials(_ context.Context, _ string) ([]map[string]string, error) {
	return f.myCreds, nil
}
func (f *fakeSubjects) CredentialFields(_ context.Context, key string) ([]string, error) {
	return f.fieldsByKey[key], nil
}
func (f *fakeSubjects) UpsertIdentity(_ context.Context, individualID string, demographics map[string]string) error {
	if f.identities == nil {
		f.identities = map[string]map[string]string{}
	}
	f.identities[individualID] = demographics
	f.idUpserts = append(f.idUpserts, provCall{subjectID: individualID, claims: demographics})
	return nil
}
func (f *fakeSubjects) GetIdentity(_ context.Context, individualID string) (map[string]string, error) {
	return f.identities[individualID], nil
}
func (f *fakeSubjects) DeleteCredential(_ context.Context, key, _ string) error {
	f.deletedCreds = append(f.deletedCreds, key)
	return nil
}

// ─── registryProviders ────────────────────────────────────────────────────────

func TestRegistryProviders(t *testing.T) {
	t.Run("valid array with discover/entity/searchField", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES",
			`[{"id":"sunbird","label":"Sunbird RC","url":"http://reg:18091","discover":true,"entity":"TestaCardV4","searchField":"individualId"}]`)
		ps := registryProviders()
		if len(ps) != 1 {
			t.Fatalf("len = %d, want 1", len(ps))
		}
		p := ps[0]
		if p.ID != "sunbird" || p.Label != "Sunbird RC" || p.URL != "http://reg:18091" {
			t.Errorf("base fields wrong: %+v", p)
		}
		if !p.Discover {
			t.Error("Discover should be true")
		}
		if p.Entity != "TestaCardV4" {
			t.Errorf("Entity = %q, want TestaCardV4", p.Entity)
		}
		if p.SearchField != "individualId" {
			t.Errorf("SearchField = %q, want individualId", p.SearchField)
		}
	})
	t.Run("unset -> nil", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", "")
		if ps := registryProviders(); ps != nil {
			t.Errorf("want nil, got %v", ps)
		}
	})
	t.Run("whitespace -> nil", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", "   \n  ")
		if ps := registryProviders(); ps != nil {
			t.Errorf("want nil, got %v", ps)
		}
	})
	t.Run("malformed JSON -> nil", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", "{not json")
		if ps := registryProviders(); ps != nil {
			t.Errorf("want nil, got %v", ps)
		}
	})
	t.Run("object instead of array -> nil", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", `{"id":"x"}`)
		if ps := registryProviders(); ps != nil {
			t.Errorf("want nil, got %v", ps)
		}
	})
}

// ─── flattenRecord ─────────────────────────────────────────────────────────────

func TestFlattenRecord(t *testing.T) {
	rec := map[string]any{
		"name":         "Grace",
		"count":        5,
		"score":        4.5,
		"active":       true,
		"nilField":     nil,
		"osid":         "abc-123",
		"osOwner":      "owner-1",
		"_osState":     "PUBLISHED",
		"_osCreatedAt": "2026-01-01",
		"real":         "kept",
	}

	t.Run("stripMeta drops os* and nils, stringifies the rest", func(t *testing.T) {
		got := flattenRecord(rec, true)
		want := map[string]string{
			"name":   "Grace",
			"count":  "5",
			"score":  "4.5",
			"active": "true",
			"real":   "kept",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		for _, k := range []string{"osid", "osOwner", "_osState", "_osCreatedAt", "nilField"} {
			if _, ok := got[k]; ok {
				t.Errorf("key %q should have been dropped", k)
			}
		}
	})

	t.Run("stripMeta=false keeps os* metadata but still drops nils", func(t *testing.T) {
		got := flattenRecord(rec, false)
		if got["osid"] != "abc-123" || got["osOwner"] != "owner-1" || got["_osState"] != "PUBLISHED" {
			t.Errorf("os* metadata should be kept when stripMeta=false: %v", got)
		}
		if _, ok := got["nilField"]; ok {
			t.Error("nil values are always dropped")
		}
	})
}

// ─── sunbird search helpers ────────────────────────────────────────────────────

// readJSON decodes a request body into a generic map for assertions.
func readReqJSON(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode request body: %v (body=%s)", err, b)
	}
	return m
}

func TestFetchRegistrySunbird(t *testing.T) {
	t.Run("sends eq-filter, parses data[] shape, strips os*", func(t *testing.T) {
		var gotFilter map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/MyEntity/search" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			body := readReqJSON(t, r)
			gotFilter, _ = body["filters"].(map[string]any)
			_, _ = io.WriteString(w, `{"totalCount":1,"data":[{"name":"Grace","dob":"1990","osid":"o1","osOwner":"ow","_osState":"PUBLISHED"}]}`)
		}))
		defer srv.Close()

		p := registryProvider{URL: srv.URL, Entity: "MyEntity"}
		got := fetchRegistrySunbird(context.Background(), p, "ID-123")

		// request shape: {"filters":{"individualId":{"eq":"ID-123"}}}
		field, _ := gotFilter["individualId"].(map[string]any)
		if field == nil || field["eq"] != "ID-123" {
			t.Errorf("filter not {individualId:{eq:ID-123}}: %v", gotFilter)
		}
		want := map[string]string{"name": "Grace", "dob": "1990"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v (os* must be stripped)", got, want)
		}
	})

	t.Run("honours a custom searchField", func(t *testing.T) {
		var gotFilter map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotFilter, _ = readReqJSON(t, r)["filters"].(map[string]any)
			_, _ = io.WriteString(w, `{"data":[{"x":"1"}]}`)
		}))
		defer srv.Close()
		p := registryProvider{URL: srv.URL, Entity: "E", SearchField: "testaId"}
		fetchRegistrySunbird(context.Background(), p, "T9")
		field, _ := gotFilter["testaId"].(map[string]any)
		if field == nil || field["eq"] != "T9" {
			t.Errorf("expected filter keyed by testaId: %v", gotFilter)
		}
	})

	t.Run("parses the {<Entity>:[...]} shape", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"MyEntity":[{"alt":"shape"}]}`)
		}))
		defer srv.Close()
		p := registryProvider{URL: srv.URL, Entity: "MyEntity"}
		got := fetchRegistrySunbird(context.Background(), p, "id")
		if got["alt"] != "shape" {
			t.Errorf("alt-shape not parsed: %v", got)
		}
	})

	t.Run("empty result -> nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"totalCount":0,"data":[]}`)
		}))
		defer srv.Close()
		p := registryProvider{URL: srv.URL, Entity: "E"}
		if got := fetchRegistrySunbird(context.Background(), p, "id"); got != nil {
			t.Errorf("want nil, got %v", got)
		}
	})

	t.Run("non-200 -> nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		p := registryProvider{URL: srv.URL, Entity: "E"}
		if got := fetchRegistrySunbird(context.Background(), p, "id"); got != nil {
			t.Errorf("want nil, got %v", got)
		}
	})
}

func TestSunbirdSchemas(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/Schema/search" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		gotBody = readReqJSON(t, r)
		_, _ = io.WriteString(w, `{"data":[{"name":"TestaCardV4"},{"name":"Schema"},{"name":"ZzProbe"},{"name":""},{"name":"FarmerCard"}]}`)
	}))
	defer srv.Close()

	got := sunbirdSchemas(context.Background(), srv.URL)
	want := []string{"TestaCardV4", "FarmerCard"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (Schema, ZzProbe and empty must be skipped)", got, want)
	}
	// {"filters":{}} request body.
	filters, ok := gotBody["filters"].(map[string]any)
	if !ok || len(filters) != 0 {
		t.Errorf("body should be {\"filters\":{}}: %v", gotBody)
	}
}

func TestFetchRegistry(t *testing.T) {
	t.Run("discover enumerates entities and merges results", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/Schema/search":
				_, _ = io.WriteString(w, `{"data":[{"name":"E1"},{"name":"E2"}]}`)
			case "/api/v1/E1/search":
				_, _ = io.WriteString(w, `{"data":[{"a":"1","osid":"x"}]}`)
			case "/api/v1/E2/search":
				_, _ = io.WriteString(w, `{"data":[{"b":"2"}]}`)
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		}))
		defer srv.Close()
		got := fetchRegistry(context.Background(), registryProvider{URL: srv.URL, Discover: true}, "id")
		want := map[string]string{"a": "1", "b": "2"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("entity set -> single search", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/E1/search" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"data":[{"b":"2","osOwner":"x"}]}`)
		}))
		defer srv.Close()
		got := fetchRegistry(context.Background(), registryProvider{URL: srv.URL, Entity: "E1"}, "id")
		if !reflect.DeepEqual(got, map[string]string{"b": "2"}) {
			t.Errorf("got %v, want {b:2}", got)
		}
	})

	t.Run("neither -> legacy GET-by-id flat JSON (no os* strip)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/record/ID5" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"c":"3","n":5,"osid":"keepme"}`)
		}))
		defer srv.Close()
		got := fetchRegistry(context.Background(), registryProvider{URL: srv.URL, Path: "/record/"}, "ID5")
		want := map[string]string{"c": "3", "n": "5", "osid": "keepme"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("legacy non-200 -> nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		if got := fetchRegistry(context.Background(), registryProvider{URL: srv.URL, Path: "/x/"}, "id"); got != nil {
			t.Errorf("want nil, got %v", got)
		}
	})
}

// ─── RegistryCredentials handler ───────────────────────────────────────────────

func TestRegistryCredentials(t *testing.T) {
	f := &fakeSubjects{
		listCreds: []map[string]string{
			{"key": "PersonCredential", "displayName": "Person", "scope": "personcredential_vc_ldp"},
		},
		fieldsByKey: map[string][]string{"PersonCredential": {"fullName", "dob"}},
	}
	h := &H{Subjects: f}

	rr := httptest.NewRecorder()
	h.RegistryCredentials(rr, httptest.NewRequest(http.MethodGet, "/api/registry/credentials", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var out []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	c := out[0]
	if c["key"] != "PersonCredential" || c["displayName"] != "Person" || c["scope"] != "personcredential_vc_ldp" {
		t.Errorf("fields wrong: %v", c)
	}
	fields, _ := c["fields"].([]any)
	if len(fields) != 2 || fields[0] != "fullName" || fields[1] != "dob" {
		t.Errorf("fields = %v, want [fullName dob]", c["fields"])
	}
}

// TestRegistryCredentials_NoSubjects returns an empty JSON array (never null)
// when no provisioner is wired.
func TestRegistryCredentials_NoSubjects(t *testing.T) {
	h := &H{}
	rr := httptest.NewRecorder()
	h.RegistryCredentials(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	if strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Errorf("body = %q, want []", rr.Body.String())
	}
}

// ─── buildAuthcodeArtifacts ────────────────────────────────────────────────────

func TestBuildAuthcodeArtifacts_LDP(t *testing.T) {
	schema := vctypes.Schema{
		Name:            "Person Card",
		Std:             "w3c_vcdm_2",
		AdditionalTypes: []string{"PersonCredential"},
		FieldsSpec:      []vctypes.FieldSpec{{Name: "full_name"}, {Name: "dob"}},
	}
	a := buildAuthcodeArtifacts(schema)

	if a.configKey != "PersonCredential" {
		t.Errorf("configKey = %q, want PersonCredential", a.configKey)
	}
	if a.scope != "personcredential_vc_ldp" {
		t.Errorf("scope = %q, want personcredential_vc_ldp", a.scope)
	}
	if a.credFormat != "ldp_vc" {
		t.Errorf("credFormat = %q, want ldp_vc", a.credFormat)
	}
	if a.credsub == nil {
		t.Error("ldp_vc must carry a credentialSubject display (credsub non-nil)")
	}
	if !reflect.DeepEqual(a.displayOrder, []string{"full_name", "dob"}) {
		t.Errorf("displayOrder = %v", a.displayOrder)
	}
	if !strings.Contains(a.viewDDL, "CREATE OR REPLACE VIEW certify.vc_subject_personcredential") {
		t.Errorf("viewDDL missing view name: %s", a.viewDDL)
	}
	if !strings.Contains(a.viewDDL, `claims->>'full_name' AS "full_name"`) {
		t.Errorf("viewDDL missing field column: %s", a.viewDDL)
	}
	wantSQ := `'personcredential_vc_ldp':'select "full_name", "dob" from certify.vc_subject_personcredential where individual_id=:id'`
	if a.scopeQuery != wantSQ {
		t.Errorf("scopeQuery = %q, want %q", a.scopeQuery, wantSQ)
	}
	if !strings.Contains(a.display, "Person Card") {
		t.Errorf("display should carry the schema name: %s", a.display)
	}
}

func TestBuildAuthcodeArtifacts_SDJWT(t *testing.T) {
	schema := vctypes.Schema{
		Name:       "Health Card",
		Std:        "sd_jwt_vc (IETF)",
		FieldsSpec: []vctypes.FieldSpec{{Name: "hcid"}},
	}
	a := buildAuthcodeArtifacts(schema)
	if a.configKey != "HealthCard" {
		t.Errorf("configKey = %q, want HealthCard (name minus spaces)", a.configKey)
	}
	if a.credFormat != "vc+sd-jwt" {
		t.Errorf("credFormat = %q, want vc+sd-jwt", a.credFormat)
	}
	if a.credsub != nil {
		t.Error("sd-jwt must NOT carry a credentialSubject display (credsub nil)")
	}
	if a.sdJwtVct == nil {
		t.Error("sd-jwt must carry an sd_jwt_vct")
	}
}

func TestBuildAuthcodeArtifacts_EmptyNameFallback(t *testing.T) {
	a := buildAuthcodeArtifacts(vctypes.Schema{Std: "w3c_vcdm_1"})
	if a.configKey != "Credential" {
		t.Errorf("configKey = %q, want Credential", a.configKey)
	}
	if a.scope != "credential_vc_ldp" {
		t.Errorf("scope = %q, want credential_vc_ldp", a.scope)
	}
}

// ─── isAlnum ──────────────────────────────────────────────────────────────────

func TestIsAlnum(t *testing.T) {
	for _, r := range "azAZ09" {
		if !isAlnum(r) {
			t.Errorf("isAlnum(%q) = false, want true", r)
		}
	}
	for _, r := range "_- /.@" {
		if isAlnum(r) {
			t.Errorf("isAlnum(%q) = true, want false", r)
		}
	}
}

// ─── appendBraceEntry ──────────────────────────────────────────────────────────

func TestAppendBraceEntry(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "props.properties")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("insert into non-empty braces uses a comma separator", func(t *testing.T) {
		p := write(t, "myprop={'existing':'1'}\n")
		if err := appendBraceEntry(p, "myprop", "newscope", "'newscope':'2'"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		want := "myprop={'existing':'1','newscope':'2'}\n"
		if string(b) != want {
			t.Errorf("got %q, want %q", b, want)
		}
	})

	t.Run("insert into empty braces uses no separator", func(t *testing.T) {
		p := write(t, "myprop={}\n")
		if err := appendBraceEntry(p, "myprop", "first", "'first':'x'"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		if string(b) != "myprop={'first':'x'}\n" {
			t.Errorf("got %q", b)
		}
	})

	t.Run("idempotent when dupKey already present", func(t *testing.T) {
		p := write(t, "myprop={'first':'x'}\n")
		if err := appendBraceEntry(p, "myprop", "first", "'first':'y'"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		if string(b) != "myprop={'first':'x'}\n" {
			t.Errorf("should be unchanged, got %q", b)
		}
	})

	t.Run("skips comment lines", func(t *testing.T) {
		p := write(t, "#myprop={'commented':'1'}\nmyprop={'real':'1'}\n")
		if err := appendBraceEntry(p, "myprop", "added", "'added':'2'"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		want := "#myprop={'commented':'1'}\nmyprop={'real':'1','added':'2'}\n"
		if string(b) != want {
			t.Errorf("got %q, want %q", b, want)
		}
	})

	t.Run("property not found -> error", func(t *testing.T) {
		p := write(t, "other={}\n")
		if err := appendBraceEntry(p, "myprop", "k", "'k':'v'"); err == nil {
			t.Error("expected error for missing property")
		}
	})

	t.Run("missing file -> error", func(t *testing.T) {
		if err := appendBraceEntry(filepath.Join(t.TempDir(), "nope"), "p", "k", "e"); err == nil {
			t.Error("expected error for missing file")
		}
	})
}
