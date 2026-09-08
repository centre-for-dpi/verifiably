package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/statuslist"
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
	myCredsErr   error // ListMyCredentials error knob
	ledger       []map[string]string
	fieldsByKey  map[string][]string
	scopeByKey   map[string]string

	// Identity registry: GetIdentity reads `identities`; UpsertIdentity writes it
	// and appends to `idUpserts` (reusing provCall: subjectID=individualId,
	// claims=demographics) for assertions.
	identities map[string]map[string]string
	idUpserts  []provCall
	// Identity-registry error knobs (registrar surface); zero values = success.
	idListErr, idGetErr, idUpsertErr, idDeleteErr error

	// Error/format knobs for the ReapplyAuthcodeViews + applyAuthcodeSchema paths.
	fieldsErrByKey map[string]error  // CredentialFields error per key
	formatByKey    map[string]string // CredentialClaimSpec format per key
	specErrByKey   map[string]error  // CredentialClaimSpec error per key
	applyErr       error             // ApplyAuthcodeSchema error
	applyDIDs      []string          // didURL passed to ApplyAuthcodeSchema
	replaceViewErr error             // ReplaceView error

	deletedCreds     []string // keys passed to DeleteCredential
	droppedViewSlugs []string // slugs passed to DeleteCredential (view teardown)
	replacedViews    []string // DDLs passed to ReplaceView
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
func (f *fakeSubjects) CredentialClaimSpec(_ context.Context, key string) (string, string, string, error) {
	return f.formatByKey[key], "", "", f.specErrByKey[key]
}
func (f *fakeSubjects) ApplyAuthcodeSchema(_ context.Context, _, _, _, _, _, _ string, _ []string, _, _, _, _ *string, _, didURL string) error {
	f.applyDIDs = append(f.applyDIDs, didURL)
	return f.applyErr
}
func (f *fakeSubjects) ListMyCredentials(_ context.Context, _ string) ([]map[string]string, error) {
	return f.myCreds, f.myCredsErr
}
func (f *fakeSubjects) ListLedger(_ context.Context, _ []string) ([]map[string]string, error) {
	return f.ledger, nil
}
func (f *fakeSubjects) CredentialFields(_ context.Context, key string) ([]string, error) {
	return f.fieldsByKey[key], f.fieldsErrByKey[key]
}
func (f *fakeSubjects) UpsertIdentity(_ context.Context, individualID string, demographics map[string]string) error {
	if f.idUpsertErr != nil {
		return f.idUpsertErr
	}
	if f.identities == nil {
		f.identities = map[string]map[string]string{}
	}
	f.identities[individualID] = demographics
	f.idUpserts = append(f.idUpserts, provCall{subjectID: individualID, claims: demographics})
	return nil
}
func (f *fakeSubjects) GetIdentity(_ context.Context, individualID string) (map[string]string, error) {
	return f.identities[individualID], f.idGetErr
}
func (f *fakeSubjects) ListIdentities(_ context.Context) ([]map[string]string, error) {
	if f.idListErr != nil {
		return nil, f.idListErr
	}
	out := []map[string]string{}
	for id, demo := range f.identities {
		row := map[string]string{}
		for k, v := range demo {
			row[k] = v
		}
		row["individualId"] = id
		out = append(out, row)
	}
	return out, nil
}
func (f *fakeSubjects) DeleteIdentity(_ context.Context, individualID string) error {
	if f.idDeleteErr != nil {
		return f.idDeleteErr
	}
	delete(f.identities, individualID)
	return nil
}
func (f *fakeSubjects) DeleteCredential(_ context.Context, key, _, slug string) error {
	// SAFETY tripwire: schema.go DeleteSchema follows a successful
	// DeleteCredential with removeBraceEntry on host files + dockerRestart on
	// the REAL docker socket whenever CredentialScope returned a non-empty
	// scope. No hermetic test may get there, so a fake configured with a scope
	// for this key fails loudly instead of silently reaching the restart loop.
	if f.scopeByKey[key] != "" {
		panic("fakeSubjects.DeleteCredential: key " + key + " has a scope — DeleteSchema would reach dockerRestart; keep scope \"\" or return an error")
	}
	f.deletedCreds = append(f.deletedCreds, key)
	f.droppedViewSlugs = append(f.droppedViewSlugs, slug)
	return nil
}
func (f *fakeSubjects) ReplaceView(_ context.Context, ddl string) error {
	f.replacedViews = append(f.replacedViews, ddl)
	return f.replaceViewErr
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

	got := sunbirdSchemas(context.Background(), registryProvider{URL: srv.URL})
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
	a := buildAuthcodeArtifacts(schema, "")

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
	if !strings.Contains(a.viewDDL, "DROP VIEW IF EXISTS certify.vc_subject_personcredential") ||
		!strings.Contains(a.viewDDL, "CREATE VIEW certify.vc_subject_personcredential") {
		t.Errorf("viewDDL must DROP+CREATE the view (not CREATE OR REPLACE): %s", a.viewDDL)
	}
	if !strings.Contains(a.viewDDL, `claims->>'personcredential.full_name' AS "full_name"`) {
		t.Errorf("viewDDL missing namespaced field column: %s", a.viewDDL)
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
	a := buildAuthcodeArtifacts(schema, "")
	if a.configKey != "HealthCard" {
		t.Errorf("configKey = %q, want HealthCard (name minus spaces)", a.configKey)
	}
	if a.credFormat != "vc+sd-jwt" {
		t.Errorf("credFormat = %q, want vc+sd-jwt", a.credFormat)
	}
	// Scope must be format-aware (was hardcoded "_vc_ldp"), so the catalog/wallet
	// don't mislabel this SD-JWT credential as ldp.
	if a.scope != "healthcard_vc_sd_jwt" {
		t.Errorf("scope = %q, want healthcard_vc_sd_jwt", a.scope)
	}
	if a.credsub != nil {
		t.Error("sd-jwt must NOT carry a credentialSubject display (credsub nil)")
	}
	if a.sdJwtVct == nil {
		t.Error("sd-jwt must carry an sd_jwt_vct")
	}
	// Without a token status URL, no status columns are added.
	if strings.Contains(a.scopeQuery, "statusIdx") {
		t.Errorf("no token URL → no statusIdx column, got: %s", a.scopeQuery)
	}
}

func TestBuildAuthcodeArtifacts_SDJWT_TokenStatus(t *testing.T) {
	schema := vctypes.Schema{
		Name:       "Health Card",
		Std:        "sd_jwt_vc (IETF)",
		FieldsSpec: []vctypes.FieldSpec{{Name: "hcid"}},
	}
	const url = "https://verifiably.example/status-list/token/v1"
	a := buildAuthcodeArtifacts(schema, url)
	// The extraction view exposes a coalesced statusIdx (so the unquoted template
	// marker is always a valid number) and the constant statusUri.
	if !strings.Contains(a.viewDDL, `coalesce(claims->>'statusIdx_healthcard','0') AS "statusIdx"`) {
		t.Errorf("viewDDL missing coalesced statusIdx column:\n%s", a.viewDDL)
	}
	if !strings.Contains(a.viewDDL, `'`+url+`' AS "statusUri"`) {
		t.Errorf("viewDDL missing constant statusUri column:\n%s", a.viewDDL)
	}
	if !strings.Contains(a.scopeQuery, `"statusIdx", "statusUri"`) {
		t.Errorf("scopeQuery must select statusIdx + statusUri:\n%s", a.scopeQuery)
	}
}

func TestBuildAuthcodeArtifacts_EmptyNameFallback(t *testing.T) {
	a := buildAuthcodeArtifacts(vctypes.Schema{Std: "w3c_vcdm_1"}, "")
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

// ─── removeBraceEntry ──────────────────────────────────────────────────────────

func TestRemoveBraceEntry(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "props.properties")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	check := func(t *testing.T, p, want string) {
		t.Helper()
		b, _ := os.ReadFile(p)
		if string(b) != want {
			t.Errorf("got %q, want %q", b, want)
		}
	}

	t.Run("removes a middle entry whose value contains commas", func(t *testing.T) {
		p := write(t, `myprop={'a':'1','scope':'select "x", "y" from t where id=:id','b':'2'}`+"\n")
		if err := removeBraceEntry(p, "myprop", "scope"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "myprop={'a':'1','b':'2'}\n")
	})

	t.Run("removes the sole entry -> empty braces", func(t *testing.T) {
		p := write(t, "myprop={'scope':'q'}\n")
		if err := removeBraceEntry(p, "myprop", "scope"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "myprop={}\n")
	})

	t.Run("removes a bare-scope entry with no value", func(t *testing.T) {
		p := write(t, "myprop={'scopeA','scopeB'}\n")
		if err := removeBraceEntry(p, "myprop", "scopeA"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "myprop={'scopeB'}\n")
	})

	t.Run("absent key is a no-op", func(t *testing.T) {
		p := write(t, "myprop={'a':'1'}\n")
		if err := removeBraceEntry(p, "myprop", "nope"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "myprop={'a':'1'}\n")
	})

	t.Run("absent property line is a no-op", func(t *testing.T) {
		p := write(t, "other={'a':'1'}\n")
		if err := removeBraceEntry(p, "myprop", "a"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "other={'a':'1'}\n")
	})

	t.Run("does not match a scope that is a prefix of another", func(t *testing.T) {
		p := write(t, "myprop={'scope':'1','scope_v2':'2'}\n")
		if err := removeBraceEntry(p, "myprop", "scope"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "myprop={'scope_v2':'2'}\n")
	})

	t.Run("round-trips with appendBraceEntry", func(t *testing.T) {
		p := write(t, "myprop={'a':'1'}\n")
		if err := appendBraceEntry(p, "myprop", "scope", `'scope':'select "x","y" from t'`); err != nil {
			t.Fatal(err)
		}
		if err := removeBraceEntry(p, "myprop", "scope"); err != nil {
			t.Fatal(err)
		}
		check(t, p, "myprop={'a':'1'}\n")
	})
}

// ─── config-file env accessors ─────────────────────────────────────────────────

func TestScopeFileEnvAccessors(t *testing.T) {
	t.Setenv("INJI_ESIGNET_SCOPE_FILE", "/tmp/esignet.properties")
	t.Setenv("INJI_CERTIFY_SCOPE_QUERY_FILE", "/tmp/certify.properties")
	if esignetScopeFile() != "/tmp/esignet.properties" || certifyScopeQueryFile() != "/tmp/certify.properties" {
		t.Errorf("got %q / %q", esignetScopeFile(), certifyScopeQueryFile())
	}
}

// ─── ShowIssuerCredentials ─────────────────────────────────────────────────────

func TestShowIssuerCredentials(t *testing.T) {
	t.Run("lists the owner's credentials and the created banner", func(t *testing.T) {
		f := &fakeSubjects{myCreds: []map[string]string{{"key": "PersonCredential", "displayName": "Person", "scope": "personcredential_vc_ldp", "format": "ldp_vc"}}}
		h := &H{Subjects: f, Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_credentials")}
		rr := httptest.NewRecorder()
		h.ShowIssuerCredentials(rr, htmxMainRequest(http.MethodGet, "/issuer/credentials?created=PersonCredential"))
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		for _, want := range []string{"Credential created and live:", "<strong>PersonCredential</strong>", "personcredential_vc_ldp", "<strong>Person</strong>"} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q", want)
			}
		}
		if strings.Contains(body, "not enabled on this deployment") {
			t.Error("enabled deployment must not show the disabled notice")
		}
	})
	t.Run("no provisioner -> disabled notice, no cards", func(t *testing.T) {
		h := &H{Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_credentials")}
		rr := httptest.NewRecorder()
		h.ShowIssuerCredentials(rr, htmxMainRequest(http.MethodGet, "/issuer/credentials"))
		body := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(body, "not enabled on this deployment") || !strings.Contains(body, "created any credentials yet") {
			t.Errorf("status=%d body=%s", rr.Code, body)
		}
	})
}

// ─── RegistryCredentials: nil fields -> [] ─────────────────────────────────────

func TestRegistryCredentials_NilFieldsBecomeEmptyArray(t *testing.T) {
	f := &fakeSubjects{listCreds: []map[string]string{{"key": "Orphan", "displayName": "Orphan", "scope": "orphan_vc_ldp"}}}
	rr := httptest.NewRecorder()
	(&H{Subjects: f}).RegistryCredentials(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	if !strings.Contains(rr.Body.String(), `"fields":[]`) {
		t.Errorf("nil fields must encode as []: %s", rr.Body.String())
	}
}

// ─── registry HTTP client error branches ───────────────────────────────────────

func registryBodyServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchRegistryByEntity_ErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("legacy: unreachable host -> empty", func(t *testing.T) {
		if got := fetchRegistryByEntity(ctx, registryProvider{URL: "http://127.0.0.1:1", Path: "/r/"}, "id"); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("legacy: invalid JSON -> empty", func(t *testing.T) {
		srv := registryBodyServer(t, "{")
		if got := fetchRegistryByEntity(ctx, registryProvider{URL: srv.URL, Path: "/r/"}, "id"); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("legacy: record of only nulls -> empty (no \"\" entry)", func(t *testing.T) {
		srv := registryBodyServer(t, `{"a":null}`)
		if got := fetchRegistryByEntity(ctx, registryProvider{URL: srv.URL, Path: "/r/"}, "id"); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
	t.Run("entity: no hit -> empty map", func(t *testing.T) {
		srv := registryBodyServer(t, `{"data":[]}`)
		if got := fetchRegistryByEntity(ctx, registryProvider{URL: srv.URL, Entity: "Person"}, "id"); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
}

func TestSunbirdSchemas_ErrorBranches(t *testing.T) {
	ctx := context.Background()
	if got := sunbirdSchemas(ctx, registryProvider{URL: "http://127.0.0.1:1"}); got != nil {
		t.Errorf("unreachable: got %v", got)
	}
	srv := registryBodyServer(t, "not json")
	if got := sunbirdSchemas(ctx, registryProvider{URL: srv.URL}); got != nil {
		t.Errorf("invalid JSON: got %v", got)
	}
}

func TestFetchRegistrySunbird_ErrorBranches(t *testing.T) {
	ctx := context.Background()
	if got := fetchRegistrySunbird(ctx, registryProvider{URL: "http://127.0.0.1:1", Entity: "Person"}, "id"); got != nil {
		t.Errorf("unreachable: got %v", got)
	}
	srv := registryBodyServer(t, "{")
	if got := fetchRegistrySunbird(ctx, registryProvider{URL: srv.URL, Entity: "Person"}, "id"); got != nil {
		t.Errorf("invalid JSON: got %v", got)
	}
	srv2 := registryBodyServer(t, `{"data":["scalar"]}`)
	if got := fetchRegistrySunbird(ctx, registryProvider{URL: srv2.URL, Entity: "Person"}, "id"); got != nil {
		t.Errorf("non-object hit: got %v", got)
	}
}

func TestSearchRegistryAll_Envelopes(t *testing.T) {
	ctx := context.Background()
	t.Run("posts empty filters, handles the <entity> envelope, back-fills individualId, skips junk", func(t *testing.T) {
		var gotPath string
		var gotBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotBody = readReqJSON(t, r)
			_, _ = io.WriteString(w, `{"Person":[
				{"studentId":"S1","fullName":"Ada","osid":"x"},
				{"individualId":"I2","studentId":"S2"},
				{"studentId":"","fullName":"NoId"},
				"scalar",
				{"osid":"only-meta","_osState":"x"}
			]}`)
		}))
		defer srv.Close()
		rows := searchRegistryAll(ctx, registryProvider{URL: srv.URL + "/", SearchField: "studentId"}, "Person")
		if gotPath != "/api/v1/Person/search" {
			t.Errorf("path = %s", gotPath)
		}
		if f, ok := gotBody["filters"].(map[string]any); !ok || len(f) != 0 {
			t.Errorf("filters = %v", gotBody)
		}
		want := []map[string]string{
			{"studentId": "S1", "fullName": "Ada", "individualId": "S1"},
			{"individualId": "I2", "studentId": "S2"},
			{"studentId": "", "fullName": "NoId"},
		}
		if !reflect.DeepEqual(rows, want) {
			t.Errorf("rows = %v, want %v", rows, want)
		}
	})
	t.Run("default search field is individualId", func(t *testing.T) {
		srv := registryBodyServer(t, `{"data":[{"individualId":"9"}]}`)
		rows := searchRegistryAll(ctx, registryProvider{URL: srv.URL}, "Person")
		if len(rows) != 1 || rows[0]["individualId"] != "9" {
			t.Errorf("rows = %v", rows)
		}
	})
	t.Run("unreachable, non-200 and invalid JSON -> nil", func(t *testing.T) {
		if got := searchRegistryAll(ctx, registryProvider{URL: "http://127.0.0.1:1"}, "Person"); got != nil {
			t.Errorf("unreachable: %v", got)
		}
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
		defer bad.Close()
		if got := searchRegistryAll(ctx, registryProvider{URL: bad.URL}, "Person"); got != nil {
			t.Errorf("non-200: %v", got)
		}
		junk := registryBodyServer(t, "{")
		if got := searchRegistryAll(ctx, registryProvider{URL: junk.URL}, "Person"); got != nil {
			t.Errorf("invalid JSON: %v", got)
		}
	})
}

func TestFetchRegistryRows_ProviderModes(t *testing.T) {
	ctx := context.Background()
	t.Run("discover enumerates entities; legacy providers are skipped", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/Schema/search":
				_, _ = io.WriteString(w, `{"data":[{"name":"Person"},{"name":"Farmer"}]}`)
			case "/api/v1/Person/search":
				_, _ = io.WriteString(w, `{"data":[{"individualId":"1"}]}`)
			case "/api/v1/Farmer/search":
				_, _ = io.WriteString(w, `{"data":[{"individualId":"2"}]}`)
			default:
				t.Errorf("unexpected path %s (legacy providers must not be queried)", r.URL.Path)
				w.WriteHeader(404)
			}
		}))
		defer srv.Close()
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"d","url":"`+srv.URL+`","discover":true},{"id":"legacy","url":"`+srv.URL+`","path":"/record/"}]`)
		rows, err := fetchRegistryRows(ctx)
		if err != nil || len(rows) != 2 || rows[0]["individualId"] != "1" || rows[1]["individualId"] != "2" {
			t.Errorf("rows=%v err=%v", rows, err)
		}
	})
	t.Run("entity provider with no records -> error", func(t *testing.T) {
		srv := registryBodyServer(t, `{"data":[]}`)
		t.Setenv("VERIFIABLY_REGISTRIES", `[{"id":"e","url":"`+srv.URL+`","entity":"Person"}]`)
		if _, err := fetchRegistryRows(ctx); err == nil || !strings.Contains(err.Error(), "no records") {
			t.Errorf("err = %v", err)
		}
	})
}

// ─── applyAuthcodeSchema ───────────────────────────────────────────────────────

// applyFixture writes the two mounted config files applyAuthcodeSchema edits
// and points the env at them, returning both paths.
func applyFixture(t *testing.T, certify, esignet string) (certifyPath, esignetPath string) {
	t.Helper()
	dir := t.TempDir()
	certifyPath = filepath.Join(dir, "certify.properties")
	esignetPath = filepath.Join(dir, "esignet.properties")
	if err := os.WriteFile(certifyPath, []byte(certify), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(esignetPath, []byte(esignet), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INJI_CERTIFY_SCOPE_QUERY_FILE", certifyPath)
	t.Setenv("INJI_ESIGNET_SCOPE_FILE", esignetPath)
	return certifyPath, esignetPath
}

const (
	applyCertifyProps = "mosip.certify.data-provider-plugin.postgres.scope-query-mapping={'other':'select 1'}\n"
	applyEsignetProps = "mosip.esignet.supported.credential.scopes={'other'}\nmosip.esignet.credential.scope-resource-mapping={'other':'http://x'}\n"
)

func TestApplyAuthcodeSchema(t *testing.T) {
	schema := vctypes.Schema{Name: "Person Card", Std: "w3c_vcdm_2", FieldsSpec: []vctypes.FieldSpec{{Name: "fullName"}}}
	didSrv := func(t *testing.T) {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"id":"did:web:issuer.example"}`)
		}))
		t.Cleanup(srv.Close)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
	}

	// SAFETY: every sub-test must fail BEFORE the dockerRestart loop. The
	// restart talks to the real /var/run/docker.sock, so no test may reach
	// lines 412-417 — they are on the coverage exclusion list.
	t.Run("writes all artifacts and passes the live issuer DID (stops at the absent resource-map property)", func(t *testing.T) {
		didSrv(t)
		certifyPath, esignetPath := applyFixture(t, applyCertifyProps, "mosip.esignet.supported.credential.scopes={'other'}\n")
		f := &fakeSubjects{}
		h := &H{Subjects: f}
		key, err := h.applyAuthcodeSchema(context.Background(), schema, "owner@example.org")
		if err == nil || !strings.HasPrefix(err.Error(), "eSignet resource-map write failed: ") || key != "" {
			t.Fatalf("key=%q err=%v", key, err)
		}
		if !reflect.DeepEqual(f.applyDIDs, []string{"did:web:issuer.example"}) {
			t.Errorf("didURL passed to ApplyAuthcodeSchema = %v", f.applyDIDs)
		}
		cb, _ := os.ReadFile(certifyPath)
		certify := string(cb)
		if !strings.Contains(certify, `'personcard_vc_ldp':'select "fullName" from certify.vc_subject_personcard where individual_id=:id'`) {
			t.Errorf("scope-query mapping not appended: %s", certify)
		}
		eb, _ := os.ReadFile(esignetPath)
		if !strings.Contains(string(eb), "scopes={'other','personcard_vc_ldp'}") {
			t.Errorf("esignet scope not appended: %s", eb)
		}
	})

	t.Run("stale scope-query mapping is replaced, not duplicated", func(t *testing.T) {
		didSrv(t)
		certifyPath, _ := applyFixture(t, "mosip.certify.data-provider-plugin.postgres.scope-query-mapping={'personcard_vc_ldp':'select \"old\" from certify.vc_subject_personcard where individual_id=:id'}\n", "mosip.esignet.supported.credential.scopes={'other'}\n")
		_, err := (&H{Subjects: &fakeSubjects{}}).applyAuthcodeSchema(context.Background(), schema, "o")
		if err == nil || !strings.HasPrefix(err.Error(), "eSignet resource-map write failed: ") {
			t.Fatalf("must stop before the container restart: err=%v", err)
		}
		cb, _ := os.ReadFile(certifyPath)
		if strings.Count(string(cb), "'personcard_vc_ldp'") != 1 || strings.Contains(string(cb), `"old"`) {
			t.Errorf("mapping not replaced: %s", cb)
		}
	})

	t.Run("DB apply failure", func(t *testing.T) {
		didSrv(t)
		applyFixture(t, applyCertifyProps, applyEsignetProps)
		_, err := (&H{Subjects: &fakeSubjects{applyErr: errors.New("db down")}}).applyAuthcodeSchema(context.Background(), schema, "o")
		if err == nil || err.Error() != "DB apply failed: db down" {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("certify scope-query file missing", func(t *testing.T) {
		didSrv(t)
		applyFixture(t, applyCertifyProps, applyEsignetProps)
		t.Setenv("INJI_CERTIFY_SCOPE_QUERY_FILE", filepath.Join(t.TempDir(), "missing.properties"))
		_, err := (&H{Subjects: &fakeSubjects{}}).applyAuthcodeSchema(context.Background(), schema, "o")
		if err == nil || !strings.HasPrefix(err.Error(), "Certify scope-query write failed: ") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("esignet scope file missing", func(t *testing.T) {
		didSrv(t)
		applyFixture(t, applyCertifyProps, applyEsignetProps)
		t.Setenv("INJI_ESIGNET_SCOPE_FILE", filepath.Join(t.TempDir(), "missing.properties"))
		_, err := (&H{Subjects: &fakeSubjects{}}).applyAuthcodeSchema(context.Background(), schema, "o")
		if err == nil || !strings.HasPrefix(err.Error(), "eSignet scope write failed: ") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("esignet resource-mapping property absent", func(t *testing.T) {
		didSrv(t)
		applyFixture(t, applyCertifyProps, "mosip.esignet.supported.credential.scopes={'other'}\n")
		_, err := (&H{Subjects: &fakeSubjects{}}).applyAuthcodeSchema(context.Background(), schema, "o")
		if err == nil || !strings.HasPrefix(err.Error(), "eSignet resource-map write failed: ") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("indexed-mapping write failure (read-only certify file already carrying the scope)", func(t *testing.T) {
		didSrv(t)
		// A brace-less mapping line makes remove/append no-ops (no write), so the
		// first write attempted on the read-only file is the indexed mapping.
		certifyPath, _ := applyFixture(t, "mosip.certify.data-provider-plugin.postgres.scope-query-mapping='personcard_vc_ldp'\n", applyEsignetProps)
		if err := os.Chmod(certifyPath, 0o444); err != nil {
			t.Fatal(err)
		}
		if os.Getuid() == 0 {
			t.Fatal("test must not run as root: read-only file permissions would not be enforced")
		}
		_, err := (&H{Subjects: &fakeSubjects{}}).applyAuthcodeSchema(context.Background(), schema, "o")
		if err == nil || !strings.HasPrefix(err.Error(), "Certify indexed-mapping write failed: ") {
			t.Errorf("err = %v", err)
		}
	})
}

// ─── appendPropertyLine ────────────────────────────────────────────────────────

func TestAppendPropertyLine(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "app.properties")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	t.Run("appends with a newline when the file lacks a trailing one", func(t *testing.T) {
		p := write(t, "a=1")
		if err := appendPropertyLine(p, "k", "v"); err != nil {
			t.Fatal(err)
		}
		if got := read(p); got != "a=1\nk=v\n" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		p := write(t, "")
		if err := appendPropertyLine(p, "k", "v"); err != nil {
			t.Fatal(err)
		}
		if got := read(p); got != "k=v\n" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("existing key (even indented) is idempotent", func(t *testing.T) {
		p := write(t, "  k=old\n")
		if err := appendPropertyLine(p, "k", "v"); err != nil {
			t.Fatal(err)
		}
		if got := read(p); got != "  k=old\n" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("prefix key does not match", func(t *testing.T) {
		p := write(t, "k2=x\n")
		if err := appendPropertyLine(p, "k", "v"); err != nil {
			t.Fatal(err)
		}
		if got := read(p); got != "k2=x\nk=v\n" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("missing file -> error", func(t *testing.T) {
		if err := appendPropertyLine(filepath.Join(t.TempDir(), "nope"), "k", "v"); err == nil {
			t.Error("want error")
		}
	})
}

// ─── slug / adapter guards ─────────────────────────────────────────────────────

func TestInjiConfigKeySlug_NonAlnumFallsBackToCredential(t *testing.T) {
	key, slug := injiConfigKeySlug(vctypes.Schema{Name: "---"})
	if key != "---" || slug != "credential" {
		t.Errorf("got %q/%q", key, slug)
	}
}

func TestAuthcodeSchemasSafe(t *testing.T) {
	if got := (&H{}).authcodeSchemasSafe(context.Background()); got != nil {
		t.Errorf("nil adapter: got %v", got)
	}
	ad := &injiBulkAdapter{schemas: []vctypes.Schema{{ID: "Person"}}}
	got := (&H{Adapter: ad}).authcodeSchemasSafe(context.Background())
	if len(got) != 1 || got[0].ID != "Person" {
		t.Errorf("got %v", got)
	}
}

// ─── ReapplyAuthcodeViews ──────────────────────────────────────────────────────

func reapplyReq(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reapply-views", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestReapplyAuthcodeViews(t *testing.T) {
	keys := ParseAPIKeys("admin:s3cret")
	t.Run("unauthenticated -> 401", func(t *testing.T) {
		rr := httptest.NewRecorder()
		(&H{APIKeys: keys}).ReapplyAuthcodeViews(rr, reapplyReq(""))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status=%d", rr.Code)
		}
	})
	t.Run("no provisioner -> 503", func(t *testing.T) {
		rr := httptest.NewRecorder()
		(&H{APIKeys: keys}).ReapplyAuthcodeViews(rr, reapplyReq("s3cret"))
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "not enabled") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("list failure -> 500", func(t *testing.T) {
		rr := httptest.NewRecorder()
		(&H{APIKeys: keys, Subjects: &fakeSubjects{listCredsErr: errors.New("pg gone")}}).ReapplyAuthcodeViews(rr, reapplyReq("s3cret"))
		if rr.Code != 500 || !strings.Contains(rr.Body.String(), "list credentials: pg gone") {
			t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("rebuilds every view by format and reports per-key failures", func(t *testing.T) {
		tokenStore, err := statuslist.NewStore("token", "v1", filepath.Join(t.TempDir(), "token.json"), "https://issuer.example/status/token/v1")
		if err != nil {
			t.Fatal(err)
		}
		bitStore, err := statuslist.NewStore("bitstring", "v1", filepath.Join(t.TempDir(), "bit.json"), "https://issuer.example/status/bitstring/v1")
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeSubjects{
			listCreds: []map[string]string{
				{"key": "SDCard"}, {"key": "LDCard"}, {"key": "JWTCard"}, {"key": "NoFields"}, {"key": "NoSpec"}, {"key": "ViewFails"},
			},
			fieldsByKey:    map[string][]string{"SDCard": {"a"}, "LDCard": {"b"}, "JWTCard": {"c"}, "NoSpec": {"d"}, "ViewFails": {"e"}},
			fieldsErrByKey: map[string]error{"NoFields": errors.New("no such key")},
			formatByKey:    map[string]string{"SDCard": "vc+sd-jwt", "LDCard": "ldp_vc", "JWTCard": "jwt_vc_json", "ViewFails": "ldp_vc"},
			specErrByKey:   map[string]error{"NoSpec": errors.New("bad spec")},
		}
		// ReplaceView fails only for the last key: flip the error after 3 successes.
		h := &H{APIKeys: keys, Subjects: f, TokenStore: tokenStore, BitstringStore: bitStore}
		f.replaceViewErr = nil
		rr := httptest.NewRecorder()
		// Wrap ReplaceView failure for "ViewFails" via DDL sniffing: the fake's
		// error is global, so run once without error and assert DDLs, then once
		// with the error to assert the failure map.
		h.ReapplyAuthcodeViews(rr, reapplyReq("s3cret"))
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var out struct {
			Reapplied []string          `json:"reapplied"`
			Failed    map[string]string `json:"failed"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(out.Reapplied, []string{"SDCard", "LDCard", "JWTCard", "ViewFails"}) {
			t.Errorf("reapplied = %v", out.Reapplied)
		}
		if out.Failed["NoFields"] != "fields: no such key" || out.Failed["NoSpec"] != "spec: bad spec" {
			t.Errorf("failed = %v", out.Failed)
		}
		if len(f.replacedViews) != 4 {
			t.Fatalf("replacedViews = %d", len(f.replacedViews))
		}
		if !strings.Contains(f.replacedViews[0], "https://issuer.example/status/token/v1") || !strings.Contains(f.replacedViews[0], "vc_subject_sdcard") {
			t.Errorf("SD-JWT view must point at the token list: %s", f.replacedViews[0])
		}
		if !strings.Contains(f.replacedViews[1], "https://issuer.example/status/bitstring/v1") {
			t.Errorf("ldp_vc view must point at the bitstring list: %s", f.replacedViews[1])
		}
		if strings.Contains(f.replacedViews[2], "statusUri") {
			t.Errorf("jwt_vc_json view must be statusless: %s", f.replacedViews[2])
		}

		f.replaceViewErr = errors.New("view boom")
		rr = httptest.NewRecorder()
		h.ReapplyAuthcodeViews(rr, reapplyReq("s3cret"))
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Reapplied) != 0 || out.Failed["ViewFails"] != "view boom" || out.Failed["SDCard"] != "view boom" {
			t.Errorf("reapplied=%v failed=%v", out.Reapplied, out.Failed)
		}
	})
}

// ─── status-list URL / store resolution ────────────────────────────────────────

func TestStatusURLResolution(t *testing.T) {
	tokenStore, err := statuslist.NewStore("token", "v1", filepath.Join(t.TempDir(), "token.json"), "https://issuer.example/status/token/v1")
	if err != nil {
		t.Fatal(err)
	}
	bitStore, err := statuslist.NewStore("bitstring", "v1", filepath.Join(t.TempDir(), "bit.json"), "https://issuer.example/status/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: tokenStore, Kind: "token", DPG: authcodeVendor})
	set.Register(&StatusListEntry{Store: bitStore, Kind: "bitstring", DPG: authcodeVendor})
	h := &H{StatusLists: set}

	if got := h.tokenStatusURL(authcodeVendor); got != "https://issuer.example/status/token/v1" {
		t.Errorf("tokenStatusURL = %q", got)
	}
	if got := h.bitstringStatusURL(authcodeVendor); got != "https://issuer.example/status/bitstring/v1" {
		t.Errorf("bitstringStatusURL = %q", got)
	}
	if got := h.statusURLFor(authcodeVendor, "sd_jwt_vc"); got != "https://issuer.example/status/token/v1" {
		t.Errorf("statusURLFor sd-jwt = %q", got)
	}
	if got := h.statusURLFor(authcodeVendor, "w3c_vcdm_2"); got != "https://issuer.example/status/bitstring/v1" {
		t.Errorf("statusURLFor w3c = %q", got)
	}
	if got := h.statusURLFor(authcodeVendor, "mdl"); got != "" {
		t.Errorf("statusURLFor unknown = %q", got)
	}
	if got := h.statusStoreFor(authcodeVendor, "sd_jwt_vc"); got != statuslist.Backend(tokenStore) {
		t.Errorf("statusStoreFor sd-jwt = %v", got)
	}
	if got := h.statusStoreFor(authcodeVendor, "w3c_vcdm_2"); got != nil {
		t.Errorf("statusStoreFor w3c must be nil (Certify-native), got %v", got)
	}

	empty := &H{}
	if got := empty.statusPublishURL(authcodeVendor, "token"); got != "" {
		t.Errorf("no store: %q", got)
	}
	if got := empty.statusStoreFor(authcodeVendor, "sd_jwt_vc"); got != nil {
		t.Errorf("no store: %v", got)
	}
}

func TestScopeSuffix(t *testing.T) {
	for in, want := range map[string]string{"vc+sd-jwt": "vc_sd_jwt", "dc+sd-jwt": "vc_sd_jwt", "jwt_vc_json": "vc_jwt", "ldp_vc": "vc_ldp", "": "vc_ldp"} {
		if got := scopeSuffix(in); got != want {
			t.Errorf("scopeSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── brace-entry edge cases ────────────────────────────────────────────────────

func TestBraceEntry_EdgeCases(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "props.properties")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("appendBraceEntry: property line without closing brace -> error", func(t *testing.T) {
		p := write(t, "myprop={'a':'1'\n")
		err := appendBraceEntry(p, "myprop", "b", "'b':'2'")
		if err == nil || !strings.Contains(err.Error(), "no '}' on line for myprop") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("removeBraceEntry: missing file -> error", func(t *testing.T) {
		if err := removeBraceEntry(filepath.Join(t.TempDir(), "nope"), "myprop", "a"); err == nil {
			t.Error("want error")
		}
	})
	t.Run("removeBraceEntry: non brace-map line is left alone", func(t *testing.T) {
		p := write(t, "myprop='a'\n")
		if err := removeBraceEntry(p, "myprop", "a"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		if string(b) != "myprop='a'\n" {
			t.Errorf("got %q", b)
		}
	})
}

// ─── dockerRestart ─────────────────────────────────────────────────────────────

// dockerRestart always errors here: either the socket is absent (dial error) or
// the daemon answers 404 for a container name that cannot exist. The success
// path needs a live container and is on the coverage exclusion list.
func TestDockerRestart_ErrorsWithoutContainer(t *testing.T) {
	err := dockerRestart("verifiably-test-no-such-container-" + strings.Repeat("x", 8))
	if err == nil {
		t.Fatal("want error")
	}
	if _, statErr := os.Stat("/var/run/docker.sock"); statErr == nil && !strings.HasPrefix(err.Error(), "404") {
		t.Errorf("with a socket present the daemon must answer 404, got %v", err)
	}
}
