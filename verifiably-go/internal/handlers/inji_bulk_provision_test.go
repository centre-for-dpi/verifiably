package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// injiBulkAdapter is a minimal configurable adapter for the Inji auth-code bulk
// path. Embedding backend.Adapter means any method the tests don't exercise
// panics if called, surfacing unintended dependencies.
type injiBulkAdapter struct {
	backend.Adapter
	schemas         []vctypes.Schema
	dpgs            map[string]vctypes.DPG
	issueBulkCalled bool
}

func (a *injiBulkAdapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) {
	return a.schemas, nil
}
func (a *injiBulkAdapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return a.dpgs, nil
}
func (a *injiBulkAdapter) PrefillSubjectFields(_ context.Context, _ vctypes.Schema) (map[string]string, error) {
	return nil, nil
}
func (a *injiBulkAdapter) IssueBulk(_ context.Context, _ backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	a.issueBulkCalled = true
	return backend.IssueBulkResult{}, nil
}

// ─── injiFormatToStd ───────────────────────────────────────────────────────────

func TestInjiFormatToStd(t *testing.T) {
	cases := map[string]string{
		"ldp_vc":      "w3c_vcdm_2",
		"jwt_vc_json": "w3c_vcdm_2",
		"":            "w3c_vcdm_2",
		"vc+sd-jwt":   "sd_jwt_vc (IETF)",
		"dc+sd-jwt":   "sd_jwt_vc (IETF)",
	}
	for in, want := range cases {
		if got := injiFormatToStd(in); got != want {
			t.Errorf("injiFormatToStd(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── injiRowIdentity ───────────────────────────────────────────────────────────

func TestInjiRowIdentity(t *testing.T) {
	cases := []struct {
		name string
		row  map[string]string
		want string
	}{
		{"individualId wins", map[string]string{"individualId": "1", "uin": "2"}, "1"},
		{"individual_id fallback", map[string]string{"individual_id": "9"}, "9"},
		{"uin fallback", map[string]string{"uin": "7"}, "7"},
		{"id fallback", map[string]string{"id": "5"}, "5"},
		{"trims whitespace", map[string]string{"individualId": "  42 "}, "42"},
		{"none -> empty", map[string]string{"name": "x"}, ""},
		{"blank id ignored", map[string]string{"individualId": "  ", "uin": "8"}, "8"},
	}
	for _, c := range cases {
		if got := injiRowIdentity(c.row); got != c.want {
			t.Errorf("%s: injiRowIdentity = %q, want %q", c.name, got, c.want)
		}
	}
}

// ─── injiOwnerSchemas ──────────────────────────────────────────────────────────

func TestInjiOwnerSchemas(t *testing.T) {
	f := &fakeSubjects{
		myCreds: []map[string]string{
			{"key": "PersonCredential", "displayName": "Person", "scope": "personcredential_vc_ldp", "format": "ldp_vc"},
			{"key": "DiplomaSD", "displayName": "", "scope": "diploma_vc_sd", "format": "vc+sd-jwt"},
		},
		fieldsByKey: map[string][]string{
			"PersonCredential": {"fullName", "dob"},
		},
	}
	h := &H{Subjects: f}
	out := h.injiOwnerSchemas(context.Background(), &Session{})
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	p := out[0]
	if p.ID != "PersonCredential" || p.Name != "Person" || p.Std != "w3c_vcdm_2" || !p.Custom {
		t.Errorf("person card wrong: %+v", p)
	}
	if got := schemaFieldsOfH(p); !reflect.DeepEqual(got, []string{"fullName", "dob"}) {
		t.Errorf("person FieldsSpec = %v, want [fullName dob]", got)
	}
	d := out[1]
	// displayName empty -> falls back to the key; sd-jwt format -> IETF std.
	if d.Name != "DiplomaSD" || d.Std != "sd_jwt_vc (IETF)" {
		t.Errorf("diploma card wrong: %+v", d)
	}
}

// ─── runBulkProvision (via runBulkIssue dispatch) ──────────────────────────────

// stubFragments returns a Templates value defining just the provision-preview
// fragment, so renderFragment writes without parsing the whole issuer_issue.html
// (which needs funcs loadPageTemplate doesn't register). The real assertion is on
// the captured ProvisionSubject calls, not the rendered HTML.
func stubFragments(t *testing.T) *template.Template {
	t.Helper()
	return template.Must(template.New("").Parse(
		`{{define "fragment_issue_provision_preview"}}{{.Provisioned}}/{{.Total}}{{end}}` +
			`{{define "fragment_issue_csv_preview"}}issued:{{.Accepted}}{{end}}`))
}

func TestRunBulkProvision_DispatchAndKeying(t *testing.T) {
	ad := &injiBulkAdapter{
		schemas: []vctypes.Schema{{
			ID:         "PersonCredential",
			Name:       "Person",
			Std:        "w3c_vcdm_2",
			FieldsSpec: []vctypes.FieldSpec{{Name: "fullName"}, {Name: "dob"}},
		}},
		dpgs: map[string]vctypes.DPG{
			"inji-ac": {SchemaApply: "inji_authcode", BulkOnly: true},
		},
	}
	f := &fakeSubjects{scopeByKey: map[string]string{"PersonCredential": "personcredential_vc_ldp"}}
	h := &H{Adapter: ad, Subjects: f, Templates: stubFragments(t)}
	sess := &Session{IssuerDpg: "inji-ac", SchemaID: "PersonCredential"}

	rows := []map[string]string{
		{"individualId": "9090", "fullName": "Grace", "dob": "1906-12-09"},
		{"uin": "7777", "fullName": "Ada"},          // identity via uin; dob absent
		{"fullName": "NoId"},                        // no identity -> rejected
		{"individualId": "5", "foo": "bar"},         // no schema fields -> rejected
	}
	r := httptest.NewRequest(http.MethodPost, "/issuer/issue/csv", nil)
	w := httptest.NewRecorder()

	// Goes through runBulkIssue so the isInjiAuthcode branch is exercised too.
	h.runBulkIssue(w, r, sess, rows, "csv")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Two valid rows provisioned, two rejected.
	if len(f.provCalls) != 2 {
		t.Fatalf("provCalls = %d, want 2 (%#v)", len(f.provCalls), f.provCalls)
	}
	client := defaultAuthCodeClientID()
	if want := esignetSubjectID("9090", client); f.provCalls[0].subjectID != want {
		t.Errorf("row0 subjectID = %q, want %q (esignetSubjectID keyed)", f.provCalls[0].subjectID, want)
	}
	if got, want := f.provCalls[0].claims, (map[string]string{"fullName": "Grace", "dob": "1906-12-09"}); !reflect.DeepEqual(got, want) {
		t.Errorf("row0 claims = %v, want %v", got, want)
	}
	if want := esignetSubjectID("7777", client); f.provCalls[1].subjectID != want {
		t.Errorf("row1 subjectID = %q, want %q", f.provCalls[1].subjectID, want)
	}
	if got, want := f.provCalls[1].claims, (map[string]string{"fullName": "Ada"}); !reflect.DeepEqual(got, want) {
		t.Errorf("row1 claims = %v, want %v (only schema fields present in the row)", got, want)
	}
	if body := w.Body.String(); body != "2/4" {
		t.Errorf("rendered = %q, want 2/4 (provisioned/total)", body)
	}
}

// A DPG that is NOT inji_authcode must take the issue path (Adapter.IssueBulk),
// never the vc_subject provision sink.
func TestRunBulkIssue_NonInjiDoesNotProvision(t *testing.T) {
	ad := &injiBulkAdapter{
		schemas: []vctypes.Schema{{ID: "X", Name: "X"}},
		dpgs:    map[string]vctypes.DPG{"walt": {}}, // no SchemaApply
	}
	f := &fakeSubjects{}
	h := &H{Adapter: ad, Subjects: f, Templates: stubFragments(t)}
	sess := &Session{IssuerDpg: "walt", SchemaID: "X"}
	r := httptest.NewRequest(http.MethodPost, "/issuer/issue/csv", nil)
	w := httptest.NewRecorder()
	h.runBulkIssue(w, r, sess, []map[string]string{{"individualId": "1", "fullName": "A"}}, "csv")

	if !ad.issueBulkCalled {
		t.Error("non-inji DPG should have taken the Adapter.IssueBulk path")
	}
	if len(f.provCalls) != 0 {
		t.Errorf("non-inji DPG provisioned vc_subject: %#v", f.provCalls)
	}
}

// ─── searchRegistryAll / fetchRegistryRows ─────────────────────────────────────

func TestSearchRegistryAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/TestaCardV4/search" {
			http.Error(w, "not found", 404)
			return
		}
		_, _ = w.Write([]byte(`{"data":[
			{"individualId":"111","fullName":"Direct","osid":"abc","_osState":"x"},
			{"testaId":"222","fullName":"Copied"}
		]}`))
	}))
	defer srv.Close()

	p := registryProvider{URL: srv.URL, Entity: "TestaCardV4", SearchField: "testaId"}
	rows := searchRegistryAll(context.Background(), p, "TestaCardV4")
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (%v)", len(rows), rows)
	}
	// Record 1 already has individualId; osid/_os* metadata stripped.
	if rows[0]["individualId"] != "111" || rows[0]["fullName"] != "Direct" {
		t.Errorf("row0 = %v", rows[0])
	}
	if _, ok := rows[0]["osid"]; ok {
		t.Errorf("osid not stripped: %v", rows[0])
	}
	// Record 2 lacks individualId -> copied from the provider's SearchField.
	if rows[1]["individualId"] != "222" {
		t.Errorf("row1 individualId = %q, want 222 (copied from testaId)", rows[1]["individualId"])
	}
}

func TestFetchRegistryRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"individualId":"900","fullName":"Z"}]}`))
	}))
	defer srv.Close()

	t.Run("entity provider pulls rows", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES",
			`[{"id":"r","url":"`+srv.URL+`","entity":"TestaCardV4","searchField":"individualId"}]`)
		rows, err := fetchRegistryRows(context.Background())
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(rows) != 1 || rows[0]["individualId"] != "900" {
			t.Errorf("rows = %v", rows)
		}
	})

	t.Run("no registries -> error", func(t *testing.T) {
		t.Setenv("VERIFIABLY_REGISTRIES", "")
		if _, err := fetchRegistryRows(context.Background()); err == nil {
			t.Error("want error when no registries configured")
		}
	})
}
