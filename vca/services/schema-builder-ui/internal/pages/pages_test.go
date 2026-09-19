// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

const document = `{"type":"object","title":"Diploma","properties":{"given_name":{"type":"string","title":"Given name"},"grade":{"type":"integer"}},"required":["given_name"]}`

type harness struct {
	mux      *http.ServeMux
	registry *fake.Registry
	catalog  *fake.Catalog
	pages    *pages.Pages
}

func build(t *testing.T, withCatalog bool) harness {
	t.Helper()
	registry := &fake.Registry{}
	catalog := &fake.Catalog{Entries: []*backendv1.CredentialConfiguration{{
		Id: "diploma_mso_mdoc", Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "DiplomaCredential",
		JsonSchema: document, Display: `[{"Name":"Diploma card","Locale":"en"}]`, SdClaims: []string{"grade"},
	}}}
	opts := service.Options{Registry: registry}
	if withCatalog {
		opts.Catalog = catalog
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	pg, err := pages.New(pages.Options{
		Builder: svc, Registry: registry, RegistryURL: "https://registry.test/portal/", Catalog: withCatalog,
	})
	if err != nil {
		t.Fatalf("pages: %v", err)
	}
	mux := http.NewServeMux()
	pg.Register(mux)
	svc.Cache().Register(mux)
	return harness{mux: mux, registry: registry, catalog: catalog, pages: pg}
}

func get(t *testing.T, h harness, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func post(t *testing.T, h harness, target string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

// formValues is the builder form of one small draft.
func formValues() url.Values {
	return url.Values{
		"type": {"DiplomaCredential"}, "title": {"Diploma"}, "locale": {"en"},
		"wire": {"dc+sd-jwt"}, "expires": {"no"},
		"field.0.name": {"given_name"}, "field.0.label": {"Given name"},
		"field.0.type": {"string"}, "field.0.required": {"yes"}, "field.0.sd": {"yes"},
		"sample": {`{"given_name":"Ada"}`},
	}
}

func TestNewChecksOptions(t *testing.T) {
	if _, err := pages.New(pages.Options{}); err == nil {
		t.Error("pages without a builder must fail")
	}
	svc, err := service.New(service.Options{Registry: &fake.Registry{}})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, serr := pages.New(pages.Options{Builder: svc}); serr == nil {
		t.Error("pages without a registry must fail")
	}
	pg, err := pages.New(pages.Options{Builder: svc, Registry: &fake.Registry{}, Prefix: "pages/"})
	if err != nil {
		t.Fatalf("pages: %v", err)
	}
	if pg.Prefix() != "/pages" {
		t.Errorf("prefix = %q", pg.Prefix())
	}
	if !strings.Contains(pg.String(), "/pages") {
		t.Errorf("string = %q", pg.String())
	}
}

func TestBuilderPage(t *testing.T) {
	h := build(t, true)
	rec := get(t, h, "/builder/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	for _, want := range []string{
		`hx-trigger="input changed delay:250ms"`,
		`hx-post="/builder/preview"`,
		`aria-live="polite"`,
		`id="preview"`,
		`Sample credential JSON`,
		`Wallet card`,
		`PDF preview`,
		`Selectively disclosable`,
		`Allowed values`,
		`https://registry.test/portal/`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page has no %q", want)
		}
	}
}

func TestBuilderPageOpensAStoredSchema(t *testing.T) {
	h := build(t, false)
	post(t, h, "/builder/save", formValues())
	rec := get(t, h, "/builder/?id=schema-1&version=1&notice=saved")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "DiplomaCredential") {
		t.Error("the page must show the stored type")
	}
	if !strings.Contains(body, "The draft version is saved") {
		t.Error("the notice must show")
	}
}

func TestBuilderPageReportsARegistryProblem(t *testing.T) {
	h := build(t, false)
	h.registry.Err = connect.NewError(connect.CodeNotFound, errors.New("gone"))
	if rec := get(t, h, "/builder/?id=nope"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestBuilderPageReportsABrokenStoredDocument(t *testing.T) {
	h := build(t, false)
	post(t, h, "/builder/save", formValues())
	h.registry.Last.JsonSchema = "{"
	if rec := get(t, h, "/builder/?id=schema-1"); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestVersionQueryValue(t *testing.T) {
	h := build(t, false)
	post(t, h, "/builder/save", formValues())
	for _, target := range []string{"/builder/?id=schema-1&version=x", "/builder/?id=schema-1&version=-2"} {
		if rec := get(t, h, target); rec.Code != http.StatusOK {
			t.Errorf("%s gave %d", target, rec.Code)
		}
	}
}

func TestPreviewFragment(t *testing.T) {
	h := build(t, false)
	rec := post(t, h, "/builder/preview", formValues())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertFragment(t, body)
	if !strings.HasPrefix(strings.TrimSpace(body), `<div id="preview"`) {
		t.Errorf("the fragment must be the preview region: %q", body[:60])
	}
	for _, want := range []string{`aria-live="polite"`, "Ada", "/pdf/preview/", "The sample credential matches the schema."} {
		if !strings.Contains(body, want) {
			t.Errorf("the fragment has no %q", want)
		}
	}
}

func TestPreviewServesThePDFDocument(t *testing.T) {
	h := build(t, false)
	body := post(t, h, "/builder/preview", formValues()).Body.String()
	i := strings.Index(body, "/pdf/preview/")
	if i < 0 {
		t.Fatal("no PDF link")
	}
	rest := body[i:]
	ref := rest[:strings.IndexAny(rest, `"<`)]
	rec := get(t, h, ref)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Body.String(), "%PDF-") {
		t.Errorf("body = %q", rec.Body.String()[:8])
	}
}

func TestPreviewReportsProblems(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("sample", `{"grade":"not a number"}`)
	body := post(t, h, "/builder/preview", values).Body.String()
	a11ytest.AssertFragment(t, body)
	if !strings.Contains(body, "Fix these points before you save.") {
		t.Errorf("the fragment must list the problems: %s", body)
	}
}

func TestPreviewWithoutASample(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("sample", "")
	body := post(t, h, "/builder/preview", values).Body.String()
	if !strings.Contains(body, "given_name") {
		t.Errorf("the generated sample must show: %s", body)
	}
}

func TestPreviewWithABrokenSample(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("sample", "{not json")
	body := post(t, h, "/builder/preview", values).Body.String()
	a11ytest.AssertFragment(t, body)
	if !strings.Contains(body, "Fix these points before you save.") {
		t.Errorf("a broken sample must give problems: %s", body)
	}
}

func TestPreviewWithNoField(t *testing.T) {
	h := build(t, false)
	body := post(t, h, "/builder/preview", url.Values{"type": {"T"}}).Body.String()
	a11ytest.AssertFragment(t, body)
	if !strings.Contains(body, "Add at least one field.") {
		t.Errorf("an empty draft must say so: %s", body)
	}
}

func TestAddAndRemoveAField(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("add", "1")
	body := post(t, h, "/builder/fields", values).Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "field_1") {
		t.Errorf("the new field must show: %s", body)
	}
	if !strings.Contains(body, "Field 2") {
		t.Error("the page must number the fields")
	}

	values = formValues()
	values.Set("remove", "0")
	body = post(t, h, "/builder/fields", values).Body.String()
	a11ytest.AssertPage(t, body)
	if strings.Contains(body, "Property name") {
		t.Errorf("the removed field must not show: %s", body)
	}
}

func TestRemoveIgnoresABadIndex(t *testing.T) {
	h := build(t, false)
	for _, bad := range []string{"9", "-1", "x"} {
		values := formValues()
		values.Set("remove", bad)
		body := post(t, h, "/builder/fields", values).Body.String()
		if !strings.Contains(body, "given_name") {
			t.Errorf("remove %q dropped a field", bad)
		}
	}
}

func TestAddGivesAFreeName(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("field.1.name", "field_1")
	values.Set("field.1.type", "string")
	values.Set("add", "1")
	body := post(t, h, "/builder/fields", values).Body.String()
	if !strings.Contains(body, "field_2") {
		t.Errorf("the new name must be free: %s", body)
	}
}

func TestFillTheSample(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("sample", `{"given_name":"kept"}`)
	body := post(t, h, "/builder/sample", values).Body.String()
	a11ytest.AssertPage(t, body)
	if strings.Contains(body, "kept") {
		t.Error("the fill button must replace the sample")
	}
	if !strings.Contains(body, "given_name") {
		t.Error("the generated sample must show")
	}
}

func TestSave(t *testing.T) {
	h := build(t, false)
	rec := post(t, h, "/builder/save", formValues())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	if h.registry.Created != 1 {
		t.Errorf("created = %d", h.registry.Created)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "notice=saved") {
		t.Errorf("location = %q", got)
	}
}

func TestSaveFromHTMX(t *testing.T) {
	h := build(t, false)
	req := httptest.NewRequest(http.MethodPost, "/builder/save", strings.NewReader(formValues().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("HX-Redirect"), "notice=saved") {
		t.Errorf("redirect = %q", rec.Header().Get("HX-Redirect"))
	}
}

func TestSaveAnExistingSchema(t *testing.T) {
	h := build(t, false)
	values := formValues()
	values.Set("id", "schema-1")
	if rec := post(t, h, "/builder/save", values); rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	if h.registry.Updated != 1 {
		t.Errorf("updated = %d", h.registry.Updated)
	}
}

func TestSaveShowsABrokenDraft(t *testing.T) {
	h := build(t, false)
	rec := post(t, h, "/builder/save", url.Values{"title": {"No type"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "credential type is empty") {
		t.Errorf("the page must say what is wrong: %s", body)
	}
}

func TestSaveReportsARegistryProblem(t *testing.T) {
	h := build(t, false)
	h.registry.Err = errors.New("down")
	if rec := post(t, h, "/builder/save", formValues()); rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestImportPageWithACatalog(t *testing.T) {
	h := build(t, true)
	rec := get(t, h, "/builder/import")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	for _, want := range []string{"JSON Schema 2020-12 document", "DiplomaCredential (diploma_mso_mdoc)", "Credential type of the DPG"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page has no %q", want)
		}
	}
}

func TestImportPageWithoutACatalog(t *testing.T) {
	h := build(t, false)
	body := get(t, h, "/builder/import").Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "This deployment has no DPG catalogue.") {
		t.Errorf("the page must say there is no catalogue: %s", body)
	}
}

func TestImportPageWhenTheCatalogFails(t *testing.T) {
	h := build(t, true)
	h.catalog.Err = errors.New("down")
	body := get(t, h, "/builder/import").Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "The DPG catalogue did not answer.") {
		t.Errorf("the page must say the catalogue is down: %s", body)
	}
}

func TestImportPageWithAnEmptyCatalog(t *testing.T) {
	h := build(t, true)
	h.catalog.Entries = nil
	body := get(t, h, "/builder/import").Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "no credential type") {
		t.Errorf("the page must say the catalogue is empty: %s", body)
	}
}

func TestImportADocument(t *testing.T) {
	h := build(t, false)
	rec := post(t, h, "/builder/import", url.Values{"json_schema": {document}, "type": {"DiplomaCredential"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "DiplomaCredential") || !strings.Contains(body, "given_name") {
		t.Errorf("the builder must show the imported draft: %s", body)
	}
	if !strings.Contains(body, "The import is done.") {
		t.Error("the notice must show")
	}
	if h.registry.Created != 0 {
		t.Error("an import must not save on its own")
	}
}

func TestImportShowsWarnings(t *testing.T) {
	h := build(t, false)
	body := post(t, h, "/builder/import", url.Values{
		"json_schema": {`{"type":"object","title":"T","properties":{"a":{"type":"string","minLength":2}}}`},
	}).Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "minLength") {
		t.Errorf("the warning must show: %s", body)
	}
}

func TestImportACatalogEntry(t *testing.T) {
	h := build(t, true)
	body := post(t, h, "/builder/import", url.Values{"catalog_entry_id": {"diploma_mso_mdoc"}}).Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Diploma card") {
		t.Errorf("the catalogue display must show: %s", body)
	}
}

func TestImportRejectsABadSource(t *testing.T) {
	h := build(t, true)
	cases := []struct {
		name   string
		values url.Values
		want   string
	}{
		{"no source", url.Values{}, "names no source"},
		{"broken document", url.Values{"json_schema": {"{"}}, "jsonschema"},
		{"unknown entry", url.Values{"catalog_entry_id": {"nope"}}, "no entry"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := post(t, h, "/builder/import", c.values)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			a11ytest.AssertPage(t, rec.Body.String())
			if !strings.Contains(rec.Body.String(), c.want) {
				t.Errorf("the page must say %q", c.want)
			}
		})
	}
}

func TestFormBodyIsBounded(t *testing.T) {
	h := build(t, false)
	body := "type=" + strings.Repeat("x", pages.MaxFormBytes+10)
	req := httptest.NewRequest(http.MethodPost, "/builder/preview", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestABrokenKitFailsEveryPage checks the error path of every render. A
// Kit that New did not build has no templates, so every component fails.
func TestABrokenKitFailsEveryPage(t *testing.T) {
	registry := &fake.Registry{}
	svc, err := service.New(service.Options{Registry: registry})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	pg, err := pages.New(pages.Options{Builder: svc, Registry: registry, Kit: &components.Kit{}})
	if err != nil {
		t.Fatalf("pages: %v", err)
	}
	mux := http.NewServeMux()
	pg.Register(mux)
	h := harness{mux: mux, registry: registry}

	cases := []struct {
		name   string
		method string
		target string
		values url.Values
	}{
		{"builder", http.MethodGet, "/builder/", nil},
		{"preview", http.MethodPost, "/builder/preview", formValues()},
		{"fields", http.MethodPost, "/builder/fields", formValues()},
		{"sample", http.MethodPost, "/builder/sample", formValues()},
		{"import page", http.MethodGet, "/builder/import", nil},
		{"import", http.MethodPost, "/builder/import", url.Values{"json_schema": {document}}},
		{"import problem", http.MethodPost, "/builder/import", url.Values{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if c.method == http.MethodGet {
				rec = get(t, h, c.target)
			} else {
				rec = post(t, h, c.target, c.values)
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", rec.Code)
			}
		})
	}
}

func TestABrokenKitFailsTheNoPreviewCard(t *testing.T) {
	registry := &fake.Registry{}
	svc, err := service.New(service.Options{Registry: registry})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	pg, err := pages.New(pages.Options{Builder: svc, Registry: registry, Kit: &components.Kit{}})
	if err != nil {
		t.Fatalf("pages: %v", err)
	}
	mux := http.NewServeMux()
	pg.Register(mux)
	values := formValues()
	values.Set("field.0.enum", "")
	values.Set("wire", "nope")
	rec := post(t, harness{mux: mux}, "/builder/preview", values)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestMessageOfAPlainError(t *testing.T) {
	if got := pages.Message(errors.New("plain")); got != "plain" {
		t.Errorf("message = %q", got)
	}
}
