// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// P6-C6: the AnonCreds proof request builder (ADR-061 decision 4).

const (
	farmerSchemaID = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS/anoncreds/v0/SCHEMA/Farmer/1.0"
	farmerCredDef  = "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS/anoncreds/v0/CLAIM_DEF/2107/default" //nolint:gosec // G101: a credential definition id, not a credential.
)

// credeblSchemas is what a live CREDEBL verifier stack answers.
func credeblSchemas(context.Context) []portal.StackSchemas {
	return []portal.StackSchemas{{Stack: "CREDEBL", Schemas: []*backendv1.ProofSchema{{
		Id: farmerSchemaID, Name: "Farmer", Version: "1.0", Attributes: []string{"fullName", "acres"},
		IssuerDid: "did:indy:bcovrin:testnet:Ra8FGb2mXsTg1d4VqVnYpS", Organisation: "Ministry of Agriculture",
		CredentialDefinitions: []string{farmerCredDef},
	}}}}
}

// anonCredsPortal wires the pages with the schemas of the stacks.
func anonCredsPortal(t *testing.T, schemas func(context.Context) []portal.StackSchemas) (*http.ServeMux, *service.Service) {
	t.Helper()
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st, Policy: &policySets{sets: map[string]*policyv1.PolicySet{}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc, Prefix: "/discovery", ProofSchemas: schemas})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux, svc
}

// anonCredsForm reveals the full name and proves at least 10 acres,
// both from the one credential definition of the schema.
func anonCredsForm(action string) url.Values {
	return url.Values{
		"display_name": {"Farmer check"}, "purpose": {"Check the farm."}, "schema": {farmerSchemaID},
		"reveal": {"fullName"}, "op:acres": {">="}, "value:acres": {"10"}, "creddef": {farmerCredDef},
		"trust": {"issuer"}, "action": {action},
	}
}

// TestAnonCredsBuilderPredicates is P6-C6: staff pick a schema of a
// live stack, tick the attributes to reveal, set a predicate, and save.
// The preview shows the proof request the wallet receives, and the saved
// template holds the same request.
func TestAnonCredsBuilderPredicates(t *testing.T) {
	mux, svc := anonCredsPortal(t, credeblSchemas)
	start := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/anoncreds/?schema="+url.QueryEscape(farmerSchemaID), nil))
	body := start.Body.String()
	if start.Code != http.StatusOK {
		t.Fatalf("builder: %d %s", start.Code, body)
	}
	a11ytest.AssertPage(t, body)
	for _, want := range []string{
		`<form method="post" action="/discovery/anoncreds/"`, `hx-post="/discovery/anoncreds/preview"`,
		"Farmer 1.0, CREDEBL", "fullName", "acres", "Ministry of Agriculture", `name="op:acres"`, `name="value:acres"`,
		`href="/discovery/dcql/"`, `href="/discovery/pe/"`, `name="action" value="save"`,
	} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("the builder lacks %q", want)
		}
	}
	frag := postForm(mux, "/discovery/anoncreds/preview", anonCredsForm("preview"), true)
	if frag.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", frag.Code, frag.Body.String())
	}
	a11ytest.AssertFragment(t, frag.Body.String())
	shown := strings.ReplaceAll(previewJSON(t, frag.Body.String()), `\u003e`, ">")
	for _, want := range []string{
		`"requested_predicates":{"pred1":{"name":"acres","p_type":">=","p_value":10`, `"name":"fullName"`,
		`"cred_def_id":"` + farmerCredDef + `"`, `"schema_id":"` + farmerSchemaID + `"`, `"name":"Farmer check"`,
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("the preview lacks %s: %s", want, shown)
		}
	}
	saved := postForm(mux, "/discovery/anoncreds/", anonCredsForm("save"), false)
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Location") != "/discovery/templates/farmer-check?notice=saved" {
		t.Fatalf("save: %d %q %s", saved.Code, saved.Header().Get("Location"), saved.Body.String())
	}
	got, err := svc.GetTemplate(context.Background(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "farmer-check"}))
	if err != nil {
		t.Fatal(err)
	}
	tpl := got.Msg.GetTemplate()
	req := tpl.GetAnoncreds()
	if tpl.GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE || tpl.GetDcql() != "" || !tpl.GetRequireTrustedIssuer() ||
		len(req.GetAttributes()) != 1 || req.GetAttributes()[0].GetNames()[0] != "fullName" ||
		len(req.GetPredicates()) != 1 || req.GetPredicates()[0].GetValue() != 10 || req.GetPredicates()[0].GetRestriction().GetCredDefId() != farmerCredDef {
		t.Fatalf("template = %v", tpl)
	}
	detail := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/templates/farmer-check", nil))
	a11ytest.AssertPage(t, detail.Body.String())
	page := html.UnescapeString(detail.Body.String())
	if !strings.Contains(page, "AnonCreds proof request") || strings.Contains(page, "DCQL query the wallet receives") ||
		strings.Contains(page, "Presentation Exchange 2.0 definition") || !strings.Contains(page, `href="/discovery/anoncreds/?from=farmer-check"`) {
		t.Errorf("the detail page does not show the AnonCreds request")
	}
}

// TestAnonCredsBuilderEditsAVersion: a saved AnonCreds query opens in
// the builder, and a save stores its next version.
func TestAnonCredsBuilderEditsAVersion(t *testing.T) {
	mux, svc := anonCredsPortal(t, credeblSchemas)
	if saved := postForm(mux, "/discovery/anoncreds/", anonCredsForm("save"), false); saved.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", saved.Code)
	}
	edit := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/anoncreds/?from=farmer-check", nil))
	body := html.UnescapeString(edit.Body.String())
	if edit.Code != http.StatusOK || !strings.Contains(body, `value="Farmer check"`) || !strings.Contains(body, `name="id" value="farmer-check"`) {
		t.Fatalf("edit: %d %s", edit.Code, body)
	}
	a11ytest.AssertPage(t, edit.Body.String())
	form := anonCredsForm("save")
	form.Set("id", "farmer-check")
	form.Set("value:acres", "20")
	if again := postForm(mux, "/discovery/anoncreds/", form, false); again.Code != http.StatusSeeOther {
		t.Fatalf("version: %d %s", again.Code, again.Body.String())
	}
	got, err := svc.GetTemplate(context.Background(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "farmer-check"}))
	if err != nil || got.Msg.GetTemplate().GetVersion() != 2 || got.Msg.GetTemplate().GetAnoncreds().GetPredicates()[0].GetValue() != 20 {
		t.Fatalf("version 2 = %v, %v", got, err)
	}
	if missing := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/anoncreds/?from=nothing", nil)); missing.Code != http.StatusNotFound {
		t.Errorf("a missing query: %d", missing.Code)
	}
}

// TestAnonCredsBuilderRefuses: a save names the query, a predicate
// compares with a whole number, and an attribute is either revealed or
// compared.
func TestAnonCredsBuilderRefuses(t *testing.T) {
	mux, _ := anonCredsPortal(t, credeblSchemas)
	for name, change := range map[string]func(url.Values){
		"no name":      func(f url.Values) { f.Del("display_name") },
		"not a number": func(f url.Values) { f.Set("value:acres", "ten") },
		"both":         func(f url.Values) { f.Add("reveal", "acres") },
		"nothing":      func(f url.Values) { f.Del("reveal"); f.Del("op:acres") },
	} {
		form := anonCredsForm("save")
		change(form)
		rec := postForm(mux, "/discovery/anoncreds/", form, false)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `class="error"`) {
			t.Errorf("%s: %d", name, rec.Code)
		}
		a11ytest.AssertPage(t, rec.Body.String())
	}
	none := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/anoncreds/", nil))
	if none.Code != http.StatusOK || !strings.Contains(none.Body.String(), "Pick a schema") {
		t.Errorf("no schema: %d", none.Code)
	}
	a11ytest.AssertPage(t, none.Body.String())
}

// TestAnonCredsBuilderOnlyWithFeature is ADR-034 decision 5: with no
// live stack that lists FEATURE_ANONCREDS_PROOF, the builder and its tab
// do not show.
func TestAnonCredsBuilderOnlyWithFeature(t *testing.T) {
	for name, schemas := range map[string]func(context.Context) []portal.StackSchemas{
		"no hook":  nil,
		"no stack": func(context.Context) []portal.StackSchemas { return nil },
	} {
		mux, _ := anonCredsPortal(t, schemas)
		if rec := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/anoncreds/", nil)); rec.Code != http.StatusNotFound {
			t.Errorf("%s: builder %d", name, rec.Code)
		}
		if rec := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/dcql/", nil)); strings.Contains(rec.Body.String(), "/discovery/anoncreds/") {
			t.Errorf("%s: the DCQL page links the builder", name)
		}
	}
	mux, _ := anonCredsPortal(t, credeblSchemas)
	for _, path := range []string{"/discovery/dcql/", "/discovery/pe/"} {
		if rec := do(mux, httptest.NewRequest(http.MethodGet, path, nil)); !strings.Contains(rec.Body.String(), `href="/discovery/anoncreds/"`) {
			t.Errorf("%s does not link the builder", path)
		}
	}
}
