package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// ─── fixtures ─────────────────────────────────────────────────────────────────

// schemaTAdapter extends issueAdapter with the catalog calls the schema browser
// and builder make (ListSchemas / SaveCustomSchema / DeleteCustomSchema).
// Unimplemented adapter methods still panic via the embedded nil interface.
type schemaTAdapter struct {
	issueAdapter
	listSchemas []vctypes.Schema
	listErr     error
	saved       []vctypes.Schema
	saveErr     error
	deleted     []string
	deleteErr   error
}

func (a *schemaTAdapter) ListSchemas(_ context.Context, _ string) ([]vctypes.Schema, error) {
	return a.listSchemas, a.listErr
}
func (a *schemaTAdapter) SaveCustomSchema(_ context.Context, s vctypes.Schema) error {
	a.saved = append(a.saved, s)
	return a.saveErr
}
func (a *schemaTAdapter) DeleteCustomSchema(_ context.Context, id string) error {
	a.deleted = append(a.deleted, id)
	return a.deleteErr
}

// schemaTCatalog is a generic custom catalog: one W3C card with an issue-only
// variant, one SD-JWT card, and one stock (non-custom) card that the browser
// must hide.
func schemaTCatalog() []vctypes.Schema {
	return []vctypes.Schema{
		{ID: "badge", Name: "Badge", Desc: "Membership badge", Std: "w3c_vcdm_2", Custom: true,
			FieldsSpec: []vctypes.FieldSpec{{Name: "name", Datatype: "string", Required: true}},
			Variants: []vctypes.SchemaVariant{
				{ID: "badge", Std: "w3c_vcdm_2", Format: "ldp_vc", Label: "JSON-LD", CanPresent: true},
				{ID: "badge-mdoc", Std: "mso_mdoc", Format: "mso_mdoc", Label: "mDoc", CanPresent: false},
			}},
		{ID: "ticket", Name: "Ticket", Desc: "Event ticket", Std: "sd_jwt_vc (IETF)", Custom: true,
			FieldsSpec: []vctypes.FieldSpec{{Name: "seat", Datatype: "string"}}},
		{ID: "stock", Name: "Stock Type", Desc: "Vendor stock credential", Std: "w3c_vcdm_2"},
	}
}

// schemaTSetup builds an H over the schema browser + builder pages with a seeded
// issuer session on "Example DPG". mutate may adjust the session.
func schemaTSetup(t *testing.T, ad *schemaTAdapter, subj *fakeSubjects, mutate func(*Session)) (*H, []*http.Cookie) {
	t.Helper()
	if ad.dpgs == nil {
		ad.dpgs = map[string]vctypes.DPG{"Example DPG": {}}
	}
	h := &H{Adapter: ad, Sessions: NewStore(), Templates: loadPageTemplates(t, "issuer_schema", "issuer_schema_builder")}
	if subj != nil {
		h.Subjects = subj
	}
	cookies := seedSession(t, h, func(s *Session) {
		s.IssuerDpg = "Example DPG"
		if mutate != nil {
			mutate(s)
		}
	})
	return h, cookies
}

// schemaTDo runs fn against a request built from method/path/form (HTMX form
// POST when form != nil, otherwise the given method) carrying cookies.
func schemaTDo(fn func(http.ResponseWriter, *http.Request), method, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = postFormReq(method, path, form)
	} else {
		req = htmxMainRequest(method, path)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}

// schemaTFields returns builder form values for the given (name, datatype) pairs.
func schemaTFields(v url.Values, fields ...[2]string) url.Values {
	for i, f := range fields {
		v.Set("field_name_"+strconv.Itoa(i), f[0])
		v.Set("field_datatype_"+strconv.Itoa(i), f[1])
	}
	return v
}

// ─── pure helpers ─────────────────────────────────────────────────────────────

func TestPromoteVariantOfStd(t *testing.T) {
	s := schemaTCatalog()[0]
	if got := promoteVariantOfStd(s, "w3c_vcdm_2"); got.ID != "badge" {
		t.Errorf("same std must return the schema unchanged, got %q", got.ID)
	}
	if got := promoteVariantOfStd(s, "mso_mdoc"); got.ID != "badge-mdoc" || got.Std != "mso_mdoc" {
		t.Errorf("variant promotion: got id=%q std=%q", got.ID, got.Std)
	}
	if got := promoteVariantOfStd(s, "jwt_vc"); got.ID != "badge" {
		t.Errorf("no matching variant must return the schema unchanged, got %q", got.ID)
	}
}

func TestScenarioByKeyAndDelegationPreset(t *testing.T) {
	if _, ok := scenarioByKey("nope"); ok {
		t.Fatal("unknown scenario key must not be found")
	}
	sc, ok := scenarioByKey("teacher")
	if !ok || sc.TypeName != "TeacherDelegation" {
		t.Fatalf("teacher scenario = %+v ok=%v", sc, ok)
	}

	// A recognised scenario forces identity + fields.
	d := builderData{Scenario: "director", Name: "keep me", ExtraType: "KeepType"}
	applyDelegationPreset(&d)
	if d.Std != "sd_jwt_vc (IETF)" || d.ExtraType != "DirectorAuthority" || d.Name != "Company Director Authority" {
		t.Errorf("scenario preset not applied: %+v", d)
	}
	if !strings.Contains(d.Desc, "suggested role: Director") || len(d.Fields) != 4 || d.Fields[3].Name != "companyRegistrationNumber" {
		t.Errorf("scenario desc/fields: %q %+v", d.Desc, d.Fields)
	}

	// The generic preset guards operator edits.
	g := builderData{ExtraType: " MyType ", Name: "My delegation", Desc: "custom desc"}
	applyDelegationPreset(&g)
	if g.ExtraType != " MyType " || g.Name != "My delegation" || g.Desc != "custom desc" || len(g.Fields) != 3 {
		t.Errorf("generic preset overwrote operator values: %+v", g)
	}
	// …and fills blanks.
	b := builderData{}
	applyDelegationPreset(&b)
	if b.ExtraType != "DelegatedAccessCredential" || b.Name != "Delegated Access Credential" || !strings.HasPrefix(b.Desc, "Delegated-access capability") {
		t.Errorf("generic defaults: %+v", b)
	}
}

func TestBuilderFieldHelpers(t *testing.T) {
	fs := []vctypes.FieldSpec{{Name: " name "}, {Name: ""}}
	if !hasField(fs, "name") || hasField(fs, "other") {
		t.Error("hasField must trim and match by name")
	}
	if allBlank(fs) || !allBlank([]vctypes.FieldSpec{{Name: "  "}, {}}) {
		t.Error("allBlank wrong")
	}
	for name, want := range map[string]bool{"name": true, "_x1": true, "1abc": false, "ñ": false, "a b": false, "": false} {
		if validFieldName(name) != want {
			t.Errorf("validFieldName(%q) = %v, want %v", name, !want, want)
		}
	}
}

func TestCurrentBuilderSchema_Defaults(t *testing.T) {
	sess := &Session{IssuerDpg: "Example DPG"}
	s := currentBuilderSchema(sess, builderData{Fields: []vctypes.FieldSpec{{Name: "  "}, {Name: "x", Datatype: "string"}}})
	if s.Name != "Untitled schema" || s.Desc != "—" || len(s.AdditionalTypes) != 0 || len(s.FieldsSpec) != 1 || s.DPGs[0] != "Example DPG" || !s.Custom {
		t.Errorf("defaults: %+v", s)
	}
	s = currentBuilderSchema(sess, builderData{Name: " Card ", Desc: " d ", ExtraType: " CardType ", IssuerDisplayName: " Org ", Expiry: true})
	if s.Name != "Card" || s.Desc != "d" || s.AdditionalTypes[0] != "CardType" || s.IssuerDisplayName != "Org" || !s.Expires || !strings.HasPrefix(s.ID, "custom-") {
		t.Errorf("trimmed values: %+v", s)
	}
}

func TestBuildJSONSchema_AllStds(t *testing.T) {
	fields := []vctypes.FieldSpec{{Name: "name", Datatype: "string", Required: true}, {Name: "born", Datatype: "string", Format: "date"}, {Name: ""}}
	base := vctypes.Schema{ID: "card", Name: "Card", Desc: "A card", AdditionalTypes: []string{"CardCredential"}, FieldsSpec: fields}
	mk := func(std string) map[string]any {
		s := base
		s.Std = std
		out := buildJSONSchema(s)
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("%s: invalid JSON %v: %s", std, err, out)
		}
		return m
	}
	props := func(m map[string]any) map[string]any { return m["properties"].(map[string]any) }

	v2 := mk("w3c_vcdm_2")
	if _, ok := props(v2)["validFrom"]; !ok {
		t.Errorf("v2 must use validFrom: %v", props(v2))
	}
	cs := props(v2)["credentialSubject"].(map[string]any)
	if req := cs["required"].([]any); len(req) != 1 || req[0] != "name" {
		t.Errorf("required = %v", req)
	}
	if born := cs["properties"].(map[string]any)["born"].(map[string]any); born["format"] != "date" {
		t.Errorf("born format = %v", born)
	}
	if req := v2["required"].([]any); len(req) != 4 {
		t.Errorf("root required = %v", req)
	}
	v1 := mk("w3c_vcdm_1")
	if _, ok := props(v1)["issuanceDate"]; !ok {
		t.Errorf("v1 must use issuanceDate: %v", props(v1))
	}
	if ctx := props(v1)["@context"].(map[string]any)["const"].([]any); ctx[0] != "https://www.w3.org/2018/credentials/v1" {
		t.Errorf("v1 context = %v", ctx)
	}
	sd := mk("sd_jwt_vc (IETF)")
	if vct := props(sd)["vct"].(map[string]any)["const"]; vct != "https://vct.verifiably.local/card" {
		t.Errorf("vct = %v", vct)
	}
	if _, ok := props(sd)["name"]; !ok {
		t.Errorf("sd-jwt must flatten claims: %v", props(sd))
	}
	if req := sd["required"].([]any); len(req) != 1 || req[0] != "type" {
		t.Errorf("sd-jwt root required = %v", req)
	}
	jwt := mk("jwt_vc")
	if _, ok := props(jwt)["vc"]; !ok {
		t.Errorf("jwt_vc must nest vc: %v", props(jwt))
	}
	mdoc := mk("mso_mdoc")
	if dt := props(mdoc)["docType"].(map[string]any)["const"]; dt != "org.verifiably.card" {
		t.Errorf("docType = %v", dt)
	}
	other := mk("something_else")
	if len(props(other)) != 1 {
		t.Errorf("unknown std must only carry type: %v", props(other))
	}
	// Insertion order is preserved.
	raw := buildJSONSchema(vctypes.Schema{ID: "x", Std: "w3c_vcdm_2"})
	if strings.Index(raw, `"$schema"`) > strings.Index(raw, `"title"`) {
		t.Errorf("orderedMap must keep insertion order: %s", raw)
	}
}

func TestOrderedMapMarshal(t *testing.T) {
	b, err := json.Marshal(kv{K: "a", V: 1})
	if err != nil || string(b) != `{"a":1}` {
		t.Errorf("kv marshal = %s, %v", b, err)
	}
	if _, err := json.Marshal(orderedMap{{"bad", make(chan int)}}); err == nil {
		t.Error("unmarshalable value must surface an error")
	}
}

func TestExtractBuilderData(t *testing.T) {
	v := url.Values{
		"name": {"Card"}, "desc": {"d"}, "issuer_display_name": {"Org"}, "extra_type": {"CardType"},
		"std": {"sd_jwt_vc"}, "delegation": {"on"}, "expiry": {"on"}, "scenario": {"poa"},
		"field_name_0": {"born"}, "field_datatype_0": {"string:date"}, "field_required_0": {"on"},
		"field_name_1": {""}, // present but blank → kept as an empty row
		"field_name_2": {"x"},
	}
	req := postFormReq(http.MethodPost, "/issuer/schema/build/preview", v)
	_ = req.ParseForm()
	d := extractBuilderData(req)
	if d.Std != "sd_jwt_vc (IETF)" || !d.Delegation || !d.Expiry || d.Scenario != "poa" || d.Name != "Card" || d.IssuerDisplayName != "Org" {
		t.Errorf("scalar fields: %+v", d)
	}
	if len(d.Fields) != 3 || d.Fields[0].Datatype != "string" || d.Fields[0].Format != "date" || !d.Fields[0].Required {
		t.Errorf("fields: %+v", d.Fields)
	}
	if d.Fields[1].Name != "" || d.Fields[1].Datatype != "string" || d.Fields[2].Name != "x" {
		t.Errorf("blank row / defaults: %+v", d.Fields)
	}
	// No std → w3c default; no rows → nil fields.
	req = postFormReq(http.MethodPost, "/x", url.Values{})
	_ = req.ParseForm()
	if d := extractBuilderData(req); d.Std != "w3c_vcdm_2" || d.Fields != nil {
		t.Errorf("defaults: %+v", d)
	}
}

// ─── browser ──────────────────────────────────────────────────────────────────

func TestShowSchemaBrowser(t *testing.T) {
	t.Run("no DPG → redirect", func(t *testing.T) {
		h, cookies := schemaTSetup(t, &schemaTAdapter{}, nil, func(s *Session) { s.IssuerDpg = "" })
		rr := schemaTDo(h.ShowSchemaBrowser, http.MethodGet, "/issuer/schema", nil, cookies)
		if rr.Code != 200 || rr.Header().Get("HX-Redirect") != "/issuer/dpg" {
			t.Fatalf("code=%d HX-Redirect=%q", rr.Code, rr.Header().Get("HX-Redirect"))
		}
		req := httptest.NewRequest(http.MethodGet, "/issuer/schema", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr = httptest.NewRecorder()
		h.ShowSchemaBrowser(rr, req)
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/issuer/dpg" {
			t.Fatalf("plain redirect: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
		}
	})

	t.Run("catalog renders custom cards only, both page paths", func(t *testing.T) {
		ad := &schemaTAdapter{listSchemas: schemaTCatalog()}
		h, cookies := schemaTSetup(t, ad, nil, func(s *Session) { s.SchemaID = "badge-mdoc"; s.ExpandedSchemaID = "ticket"; s.SchemaFilter = "" })
		rr := schemaTDo(h.ShowSchemaBrowser, http.MethodGet, "/issuer/schema?provisioning=k1&pname=Card+One", nil, cookies)
		body := rr.Body.String()
		if rr.Code != 200 || strings.Contains(body, "<!DOCTYPE") {
			t.Fatalf("HTMX path: code=%d doctype=%v", rr.Code, strings.Contains(body, "<!DOCTYPE"))
		}
		for _, want := range []string{"Badge", "Ticket", "✓ Selected", "Hide JSON", `&#34;vct&#34;`, "format-issue-only", "Provisioning <strong>Card One</strong>", `class="chip active"`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %q", want)
			}
		}
		if strings.Contains(body, "Stock Type") || strings.Contains(body, "pointer-events:none") {
			t.Errorf("stock card shown or Continue disabled: %s", body)
		}
		if !strings.Contains(body, `class="chip active"`) || !strings.Contains(body, ">all</button>") {
			t.Errorf("blank filter must default to the active 'all' chip: %s", body)
		}
		req := httptest.NewRequest(http.MethodGet, "/issuer/schema", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr = httptest.NewRecorder()
		h.ShowSchemaBrowser(rr, req)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<!DOCTYPE") || !strings.Contains(rr.Body.String(), "Badge") {
			t.Fatalf("full page: code=%d", rr.Code)
		}
	})

	t.Run("catalog error → notice banner, empty state", func(t *testing.T) {
		ad := &schemaTAdapter{listErr: errors.New("dial tcp: connection refused")}
		h, cookies := schemaTSetup(t, ad, nil, nil)
		body := schemaTDo(h.ShowSchemaBrowser, http.MethodGet, "/issuer/schema", nil, cookies).Body.String()
		if !strings.Contains(body, "briefly unavailable") || !strings.Contains(body, "No custom schemas yet") {
			t.Errorf("notice/empty state missing: %s", body)
		}
		// Resilient adapters return their custom list alongside the error.
		ad = &schemaTAdapter{listErr: errors.New("boom"), listSchemas: schemaTCatalog()[1:2]}
		h, cookies = schemaTSetup(t, ad, nil, nil)
		body = schemaTDo(h.ShowSchemaBrowser, http.MethodGet, "/issuer/schema", nil, cookies).Body.String()
		if !strings.Contains(body, "Couldn&#39;t fetch catalog from walt.id: boom") || !strings.Contains(body, "Ticket") {
			t.Errorf("partial catalog: %s", body)
		}
	})

	t.Run("Inji auth-code DPG sources cards from the subject store", func(t *testing.T) {
		ad := &schemaTAdapter{issueAdapter: issueAdapter{dpgs: map[string]vctypes.DPG{"Example DPG": {SchemaApply: "inji_authcode"}}}}
		subj := &fakeSubjects{
			myCreds: []map[string]string{
				{"key": "card_vc_ldp", "displayName": "Card", "format": "ldp_vc", "scope": "card_vc_ldp"},
				{"key": "pass_vc_sdjwt", "format": "vc+sd-jwt"},
			},
			fieldsByKey:    map[string][]string{"card_vc_ldp": {"name", "born"}},
			fieldsErrByKey: map[string]error{"pass_vc_sdjwt": errors.New("no fields")},
		}
		h, cookies := schemaTSetup(t, ad, subj, func(s *Session) { s.ExpandedSchemaID = "card_vc_ldp" })
		body := schemaTDo(h.ShowSchemaBrowser, http.MethodGet, "/issuer/schema", nil, cookies).Body.String()
		for _, want := range []string{"Card", "pass_vc_sdjwt", "scope card_vc_ldp", "sd_jwt_vc (IETF)", `&#34;born&#34;`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %q in %s", want, body)
			}
		}
		// Store failure → no cards, not a crash.
		subj.myCredsErr = errors.New("db down")
		body = schemaTDo(h.ShowSchemaBrowser, http.MethodGet, "/issuer/schema", nil, cookies).Body.String()
		if !strings.Contains(body, "No custom schemas yet") || strings.Contains(body, "pass_vc_sdjwt") {
			t.Errorf("store error must yield the empty state: %s", body)
		}
	})
}

func TestSchemaSearchFilterExpandSelect(t *testing.T) {
	ad := &schemaTAdapter{listSchemas: schemaTCatalog()}
	h, cookies := schemaTSetup(t, ad, nil, nil)
	sess := func() *Session {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return sessionOf(h, req)
	}

	// search narrows by name/desc/std, case-insensitively
	body := schemaTDo(h.SchemaSearch, http.MethodGet, "/issuer/schema/search?q=TICKET", nil, cookies).Body.String()
	if !strings.Contains(body, "Ticket") || strings.Contains(body, "Badge") || sess().SchemaQuery != "TICKET" {
		t.Errorf("search: %s", body)
	}
	body = schemaTDo(h.SchemaSearch, http.MethodGet, "/issuer/schema/search?q=zzz", nil, cookies).Body.String()
	if !strings.Contains(body, "No matches.") {
		t.Errorf("no-match copy missing: %s", body)
	}
	_ = schemaTDo(h.SchemaSearch, http.MethodGet, "/issuer/schema/search?q=", nil, cookies)

	// filter via form value promotes the matching variant
	body = schemaTDo(h.SetSchemaFilter, http.MethodPost, "/issuer/schema/filter", url.Values{"filter": {"mso_mdoc"}}, cookies).Body.String()
	if !strings.Contains(body, `data-id="badge-mdoc"`) || strings.Contains(body, "Ticket") || sess().SchemaFilter != "mso_mdoc" {
		t.Errorf("filter mso_mdoc: %s", body)
	}
	// filter via query string
	if schemaTDo(h.SetSchemaFilter, http.MethodPost, "/issuer/schema/filter?filter=sd_jwt_vc+(IETF)", url.Values{}, cookies); sess().SchemaFilter != "sd_jwt_vc (IETF)" {
		t.Errorf("query filter = %q", sess().SchemaFilter)
	}
	// no filter at all → "all"
	if schemaTDo(h.SetSchemaFilter, http.MethodPost, "/issuer/schema/filter", url.Values{}, cookies); sess().SchemaFilter != "all" {
		t.Errorf("default filter = %q", sess().SchemaFilter)
	}

	// expand toggles on, then off
	body = schemaTDo(h.ToggleSchemaExpand, http.MethodPost, "/issuer/schema/expand", url.Values{"id": {"badge"}}, cookies).Body.String()
	if !strings.Contains(body, "Hide JSON") || !strings.Contains(body, "credentialSubject") || sess().ExpandedSchemaID != "badge" {
		t.Errorf("expand on: %s", body)
	}
	body = schemaTDo(h.ToggleSchemaExpand, http.MethodPost, "/issuer/schema/expand", url.Values{"id": {"badge"}}, cookies).Body.String()
	if strings.Contains(body, "Hide JSON") || sess().ExpandedSchemaID != "" {
		t.Errorf("expand off: %s", body)
	}

	// select pushes the OOB continue button + toast
	rr := schemaTDo(h.SelectSchema, http.MethodPost, "/issuer/schema/select", url.Values{"id": {"ticket"}}, cookies)
	if sess().SchemaID != "ticket" || !strings.Contains(rr.Header().Get("HX-Trigger"), "Schema selected") {
		t.Errorf("select: session=%q trigger=%q", sess().SchemaID, rr.Header().Get("HX-Trigger"))
	}
	if !strings.Contains(rr.Body.String(), `hx-swap-oob="true"`) || strings.Contains(rr.Body.String(), "pointer-events:none") {
		t.Errorf("continue OOB: %s", rr.Body.String())
	}
}

// ─── builder ──────────────────────────────────────────────────────────────────

func TestShowSchemaBuilder(t *testing.T) {
	h, cookies := schemaTSetup(t, &schemaTAdapter{}, nil, func(s *Session) { s.IssuerDpg = "" })
	if rr := schemaTDo(h.ShowSchemaBuilder, http.MethodGet, "/issuer/schema/build", nil, cookies); rr.Header().Get("HX-Redirect") != "/issuer/dpg" {
		t.Fatalf("no DPG must redirect: %d %q", rr.Code, rr.Header().Get("HX-Redirect"))
	}
	h, cookies = schemaTSetup(t, &schemaTAdapter{}, nil, nil)
	rr := schemaTDo(h.ShowSchemaBuilder, http.MethodGet, "/issuer/schema/build", nil, cookies)
	body := rr.Body.String()
	if rr.Code != 200 || strings.Count(body, `name="field_name_`) != 2 || !strings.Contains(body, "Untitled schema") || strings.Contains(body, "Relationship scenario") {
		t.Errorf("builder page: %d %s", rr.Code, body)
	}
}

func TestBuilderFragments(t *testing.T) {
	h, cookies := schemaTSetup(t, &schemaTAdapter{}, nil, nil)
	form := schemaTFields(url.Values{"name": {"Card"}, "std": {"w3c_vcdm_1"}}, [2]string{"name", "string"}, [2]string{"born", "string:date"})

	t.Run("delegation toggle", func(t *testing.T) {
		v := url.Values{}
		for k, vs := range form {
			v[k] = vs
		}
		v.Set("delegation", "on")
		v.Set("scenario", "guardian")
		body := schemaTDo(h.BuildDelegationToggle, http.MethodPost, "/issuer/schema/build/delegation", v, cookies).Body.String()
		if !strings.Contains(body, `value="Parental / Guardian Consent"`) || !strings.Contains(body, `value="onBehalfOf"`) || !strings.Contains(body, `<option value="guardian" selected>`) {
			t.Errorf("preset not applied: %s", body)
		}
		body = schemaTDo(h.BuildDelegationToggle, http.MethodPost, "/issuer/schema/build/delegation", form, cookies).Body.String()
		if strings.Contains(body, "Relationship scenario") || !strings.Contains(body, `value="born"`) {
			t.Errorf("toggle off must keep operator fields: %s", body)
		}
	})

	t.Run("preview", func(t *testing.T) {
		body := schemaTDo(h.SchemaPreview, http.MethodPost, "/issuer/schema/build/preview", form, cookies).Body.String()
		if !strings.Contains(body, `id="json-preview"`) || !strings.Contains(body, "issuanceDate") || !strings.Contains(body, `&#34;born&#34;`) {
			t.Errorf("preview: %s", body)
		}
		req := httptest.NewRequest(http.MethodPost, "/issuer/schema/build/preview", strings.NewReader("name=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.SchemaPreview(rr, req)
		if rr.Code != 400 {
			t.Errorf("malformed form must be 400, got %d", rr.Code)
		}
	})

	t.Run("add and remove field", func(t *testing.T) {
		body := schemaTDo(h.AddSchemaField, http.MethodPost, "/issuer/schema/build/add-field", form, cookies).Body.String()
		if strings.Count(body, `name="field_name_`) != 3 {
			t.Errorf("add: want 3 rows: %s", body)
		}
		v := url.Values{}
		for k, vs := range form {
			v[k] = vs
		}
		v.Set("idx", "0")
		body = schemaTDo(h.RemoveSchemaField, http.MethodPost, "/issuer/schema/build/remove-field", v, cookies).Body.String()
		if strings.Count(body, `name="field_name_`) != 1 || !strings.Contains(body, `value="born"`) {
			t.Errorf("remove idx 0: %s", body)
		}
		v.Set("idx", "7")
		body = schemaTDo(h.RemoveSchemaField, http.MethodPost, "/issuer/schema/build/remove-field", v, cookies).Body.String()
		if strings.Count(body, `name="field_name_`) != 2 {
			t.Errorf("out-of-range idx must be ignored: %s", body)
		}
	})
}

func TestSaveSchema(t *testing.T) {
	toast := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("HX-Trigger") }
	good := func() url.Values {
		return schemaTFields(url.Values{"name": {"Card"}, "desc": {"A card"}}, [2]string{"name", "string"})
	}

	t.Run("validation", func(t *testing.T) {
		ad := &schemaTAdapter{}
		h, cookies := schemaTSetup(t, ad, nil, nil)
		if rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", url.Values{"name": {" "}}, cookies); !strings.Contains(toast(rr), "Schema needs a name") {
			t.Errorf("blank name: %q", toast(rr))
		}
		if rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", url.Values{"name": {"Card"}}, cookies); !strings.Contains(toast(rr), "Add at least one claim field") {
			t.Errorf("no fields: %q", toast(rr))
		}
		blank := schemaTFields(url.Values{"name": {"Card"}}, [2]string{" ", "string"})
		if rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", blank, cookies); !strings.Contains(toast(rr), "Add at least one claim field") {
			t.Errorf("all blank: %q", toast(rr))
		}
		bad := schemaTFields(url.Values{"name": {"Card"}}, [2]string{"first name", "string"})
		if rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", bad, cookies); !strings.Contains(toast(rr), `first name`) {
			t.Errorf("invalid field name: %q", toast(rr))
		}
		if len(ad.saved) != 0 {
			t.Errorf("nothing may be saved on validation errors: %+v", ad.saved)
		}
	})

	t.Run("default adapter save, use=1, and adapter error", func(t *testing.T) {
		ad := &schemaTAdapter{}
		h, cookies := schemaTSetup(t, ad, nil, nil)
		rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save?use=1", good(), cookies)
		if rr.Header().Get("HX-Redirect") != "/issuer/schema" || len(ad.saved) != 1 || ad.saved[0].Name != "Card" {
			t.Fatalf("save: redirect=%q saved=%+v", rr.Header().Get("HX-Redirect"), ad.saved)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		sess := sessionOf(h, req)
		if sess.SchemaID != ad.saved[0].ID || sess.ExpandedSchemaID != ad.saved[0].ID {
			t.Errorf("use=1 must select + expand: %q %q vs %q", sess.SchemaID, sess.ExpandedSchemaID, ad.saved[0].ID)
		}
		sess.SchemaID = "other"
		schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", good(), cookies)
		if sess.SchemaID != "other" || sess.ExpandedSchemaID != ad.saved[1].ID {
			t.Errorf("without use=1 selection must be untouched: %q", sess.SchemaID)
		}
		// ListIssuerDpgs failing just means "not auth-code"; the save still goes to the adapter.
		ad.dpgsErr = errors.New("dpgs down")
		ad.saveErr = errors.New("catalog write failed")
		if rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", good(), cookies); !strings.Contains(toast(rr), "catalog write failed") || len(ad.saved) != 3 {
			t.Errorf("adapter error: %q saved=%d", toast(rr), len(ad.saved))
		}
	})

	t.Run("Inji auth-code apply error", func(t *testing.T) {
		// SAFETY: applyAuthcodeSchema restarts real containers on success
		// (inji_schema.go:412-416). fakeSubjects.applyErr makes the very first
		// step (ApplyAuthcodeSchema) fail, so the file writes and the restart
		// loop are never reached. did.json is served from httptest so
		// certifyIssuerDID returns without its retry back-off.
		did := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"id":"did:web:issuer.example"}`)
		}))
		t.Cleanup(did.Close)
		t.Setenv("INJI_CERTIFY_UPSTREAM_URL", did.URL)
		ad := &schemaTAdapter{issueAdapter: issueAdapter{dpgs: map[string]vctypes.DPG{"Example DPG": {SchemaApply: "inji_authcode"}}}}
		subj := &fakeSubjects{applyErr: errors.New("db down")}
		h, cookies := schemaTSetup(t, ad, subj, nil)
		rr := schemaTDo(h.SaveSchema, http.MethodPost, "/issuer/schema/build/save", good(), cookies)
		if !strings.Contains(toast(rr), "DB apply failed: db down") || len(ad.saved) != 0 || len(subj.applyDIDs) != 1 {
			t.Errorf("authcode apply error: toast=%q saved=%d applies=%d", toast(rr), len(ad.saved), len(subj.applyDIDs))
		}
	})
}

// ─── ready / available ────────────────────────────────────────────────────────

func TestSchemaReadyAndAvailable(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/certify/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)
	h, cookies := schemaTSetup(t, &schemaTAdapter{}, nil, nil)
	ctx := context.Background()

	if h.schemaAvailable(ctx, "") {
		t.Error("empty key is never available")
	}
	var nilCtx context.Context
	if h.schemaAvailable(nilCtx, "k") {
		t.Error("request build failure must be not-ready")
	}
	status, body = 503, "restarting"
	if h.schemaAvailable(ctx, "k") {
		t.Error("non-200 must be not-ready")
	}
	status, body = 200, "{not json"
	if h.schemaAvailable(ctx, "k") {
		t.Error("decode error must be not-ready")
	}
	status, body = 200, `{"credential_configurations_supported":{"card_vc_ldp":{}}}`
	if h.schemaAvailable(ctx, "other") || !h.schemaAvailable(ctx, "card_vc_ldp") {
		t.Error("key lookup wrong")
	}
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", "http://127.0.0.1:1")
	if h.schemaAvailable(ctx, "card_vc_ldp") {
		t.Error("connection failure must be not-ready")
	}
	t.Setenv("INJI_CERTIFY_UPSTREAM_URL", srv.URL)

	// Ready → empty body + toast trigger (name falls back to key).
	rr := schemaTDo(h.SchemaReady, http.MethodGet, "/issuer/schema/ready?key=card_vc_ldp", nil, cookies)
	if rr.Code != 200 || rr.Body.Len() != 0 || !strings.Contains(rr.Header().Get("HX-Trigger"), `\"card_vc_ldp\" is ready to use`) || !strings.Contains(rr.Header().Get("HX-Trigger"), `"schemasReady":true`) {
		t.Errorf("ready: code=%d body=%q trigger=%q", rr.Code, rr.Body.String(), rr.Header().Get("HX-Trigger"))
	}
	// Not ready → banner keeps polling.
	rr = schemaTDo(h.SchemaReady, http.MethodGet, "/issuer/schema/ready?key=pending&name=Pending+Card", nil, cookies)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `id="provisioning-banner"`) || !strings.Contains(rr.Body.String(), "Provisioning <strong>Pending Card</strong>") || rr.Header().Get("HX-Trigger") != "" {
		t.Errorf("not ready: code=%d body=%s", rr.Code, rr.Body.String())
	}
}

// ─── delete ───────────────────────────────────────────────────────────────────

func TestDeleteSchema(t *testing.T) {
	// SAFETY: DeleteSchema restarts inji-certify/injiweb-esignet through the
	// real docker socket when Subjects.CredentialScope returns a non-empty
	// scope AND DeleteCredential succeeds (schema.go:677-679). fakeSubjects
	// with no scopeByKey entry returns scope "" for every key, so the
	// teardown + restart block is unreachable in every sub-test below.
	t.Run("no subject store", func(t *testing.T) {
		ad := &schemaTAdapter{listSchemas: schemaTCatalog()}
		h, cookies := schemaTSetup(t, ad, nil, func(s *Session) { s.SchemaID = "ticket"; s.ExpandedSchemaID = "ticket" })
		rr := schemaTDo(h.DeleteSchema, http.MethodPost, "/issuer/schema/delete", url.Values{"id": {"ticket"}}, cookies)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		sess := sessionOf(h, req)
		if rr.Code != 200 || len(ad.deleted) != 1 || ad.deleted[0] != "ticket" || sess.SchemaID != "" || sess.ExpandedSchemaID != "" {
			t.Fatalf("delete: code=%d deleted=%v sess=%q/%q", rr.Code, ad.deleted, sess.SchemaID, sess.ExpandedSchemaID)
		}
		if !strings.Contains(rr.Body.String(), "pointer-events:none") || !strings.Contains(rr.Body.String(), `hx-swap-oob="true"`) {
			t.Errorf("continue must be disabled via OOB: %s", rr.Body.String())
		}
	})

	t.Run("subject store: non-auth-code credential (scope empty) tears down the row only", func(t *testing.T) {
		ad := &schemaTAdapter{listSchemas: schemaTCatalog(), deleteErr: errors.New("ignored")}
		subj := &fakeSubjects{}
		h, cookies := schemaTSetup(t, ad, subj, func(s *Session) { s.SchemaID = "badge"; s.ExpandedSchemaID = "badge" })
		rr := schemaTDo(h.DeleteSchema, http.MethodPost, "/issuer/schema/delete", url.Values{"id": {"ticket"}}, cookies)
		if rr.Code != 200 || len(subj.deletedCreds) != 1 || subj.deletedCreds[0] != "ticket" || subj.droppedViewSlugs[0] != "ticket" {
			t.Fatalf("subject teardown: code=%d deleted=%v slugs=%v", rr.Code, subj.deletedCreds, subj.droppedViewSlugs)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		sess := sessionOf(h, req)
		if sess.SchemaID != "badge" || sess.ExpandedSchemaID != "badge" {
			t.Errorf("deleting another schema must keep the selection: %q %q", sess.SchemaID, sess.ExpandedSchemaID)
		}
		if strings.Contains(rr.Body.String(), "pointer-events:none") {
			t.Errorf("continue must stay enabled: %s", rr.Body.String())
		}
	})
}
