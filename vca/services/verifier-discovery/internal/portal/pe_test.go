// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"bytes"
	"context"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// badgePE asks for a status directive, which DCQL cannot hold.
const badgePE = `{"id": "badge-check", "name": "Staff badge", "purpose": "Check the badge.",
  "input_descriptors": [{"id": "badge", "format": {"jwt_vc_json": {}}, "constraints": {
    "statuses": {"active": {"directive": "required"}},
    "fields": [
      {"path": ["$.vc.type"], "filter": {"type": "array", "contains": {"type": "string", "const": "StaffBadge"}}},
      {"path": ["$.vc.credentialSubject.employee_id"]}]}}]}`

// peShell wires the pages in the verifier frame with three live
// verifier stacks: one reads PE only, one reads both, one reads DCQL.
func peShell(t *testing.T) (*http.ServeMux, *service.Service) {
	t.Helper()
	_, svc, _ := builderPortal(t)
	pair := func(dpg configv1.Dpg, name string, protocols ...backendv1.Protocol) topology.Status {
		pn := topology.PairName(commonv1.Role_ROLE_VERIFIER, dpg)
		return topology.Status{
			Peer: topology.Peer{Pair: pn, Role: commonv1.Role_ROLE_VERIFIER, Dpg: dpg, PublicURL: "https://" + pn + ".labs.example",
				Services: map[string]string{"verifier-auth": "http://" + pn + "-auth:8081"}},
			State:        topology.Live,
			Capabilities: &backendv1.GetCapabilitiesResponse{Protocols: protocols, DpgInfo: &backendv1.DpgInfo{DisplayName: name}},
		}
	}
	snap := topology.Snapshot{Peers: []topology.Status{
		pair(configv1.Dpg_DPG_WALTID, "Legacy stack", backendv1.Protocol_PROTOCOL_OID4VP, backendv1.Protocol_PROTOCOL_OID4VP_PEX),
		pair(configv1.Dpg_DPG_INJI, "Both stack", backendv1.Protocol_PROTOCOL_OID4VP_PEX, backendv1.Protocol_PROTOCOL_OID4VP_DCQL),
		pair(configv1.Dpg_DPG_CREDEBL, "Modern stack", backendv1.Protocol_PROTOCOL_OID4VP_DCQL),
	}}
	peers := []topology.Peer{snap.Peers[0].Peer, snap.Peers[1].Peer, snap.Peers[2].Peer}
	shell := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: peers,
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  peers[0].Auth() + staffshell.JWKSPath, SignOut: "/discovery/signout",
	})
	p, err := portal.New(portal.Options{Client: svc, Prefix: "/discovery", Shell: shell})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux, svc
}

// multipartPost answers one multipart post with an optional file.
func multipartPost(t *testing.T, mux *http.ServeMux, path string, form url.Values, file string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, vs := range form {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if file != "" {
		fw, err := mw.CreateFormFile("file", "badge.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = fw.Write([]byte(file)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, path, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return do(mux, r)
}

// TestPeImportAndEdit imports a definition from a file, validates it,
// converts it with the loss report shown, saves it as a PE query, and
// edits it into a second version (ADR-042 decision 4).
func TestPeImportAndEdit(t *testing.T) {
	mux, svc := peShell(t)
	blank := staffGet(t, mux, "/discovery/pe/new")
	a11ytest.AssertPage(t, blank)
	for _, want := range []string{`enctype="multipart/form-data"`, `name="definition"`, `type="file"`, "Check", "Convert to DCQL", "Save as PE query"} {
		if !strings.Contains(blank, want) {
			t.Errorf("the editor lacks %q", want)
		}
	}

	imported := multipartPost(t, mux, "/discovery/pe/new", url.Values{"action": {"import"}}, badgePE)
	if imported.Code != http.StatusOK {
		t.Fatalf("import: %d %s", imported.Code, imported.Body.String())
	}
	page := imported.Body.String()
	a11ytest.AssertPage(t, page)
	if !strings.Contains(html.UnescapeString(page), `"id": "badge-check"`) || !strings.Contains(page, `value="Staff badge"`) {
		t.Errorf("the import did not fill the editor: %s", page)
	}
	if !strings.Contains(page, "The definition is valid.") {
		t.Error("the import did not validate the file")
	}

	bad := multipartPost(t, mux, "/discovery/pe/new", url.Values{"action": {"validate"}, "definition": {`{"id": 5, "input_descriptors": []}`}}, "")
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "/id: the value must be of type string") {
		t.Errorf("validate: %d %s", bad.Code, bad.Body.String())
	}
	a11ytest.AssertPage(t, bad.Body.String())

	converted := postForm(mux, "/discovery/pe/new", url.Values{"action": {"convert"}, "definition": {badgePE}, "display_name": {"Staff badge"}}, false)
	if converted.Code != http.StatusOK {
		t.Fatalf("convert: %d %s", converted.Code, converted.Body.String())
	}
	body := strings.ReplaceAll(converted.Body.String(), "<wbr>", "")
	a11ytest.AssertPage(t, converted.Body.String())
	for _, want := range []string{"What the conversion loses", "/input_descriptors/0/constraints/statuses", "DCQL has no status directive", "dcql_query", "StaffBadge"} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("the conversion lacks %q", want)
		}
	}

	saved := postForm(mux, "/discovery/pe/new", url.Values{"action": {"save"}, "definition": {badgePE}, "display_name": {"Staff badge"}, "purpose": {"Check the badge."}}, false)
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Location") != "/discovery/pe/edit/staff-badge?notice=saved" {
		t.Fatalf("save: %d %q %s", saved.Code, saved.Header().Get("Location"), saved.Body.String())
	}
	got, err := svc.GetTemplate(context.Background(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "staff-badge"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetTemplate().GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_PE || !strings.Contains(got.Msg.GetTemplate().GetPresentationDefinition(), "badge-check") {
		t.Fatalf("stored %+v", got.Msg.GetTemplate())
	}

	edit := staffGet(t, mux, "/discovery/pe/edit/staff-badge?notice=saved")
	a11ytest.AssertPage(t, edit)
	if !strings.Contains(html.UnescapeString(edit), "badge-check") || !strings.Contains(edit, "Version 1") {
		t.Errorf("the edit page lacks the definition")
	}
	changed := strings.Replace(badgePE, `"statuses": {"active": {"directive": "required"}},`, "", 1)
	again := postForm(mux, "/discovery/pe/edit/staff-badge", url.Values{"action": {"save"}, "definition": {changed}, "display_name": {"Staff badge"}}, false)
	if again.Code != http.StatusSeeOther {
		t.Fatalf("edit save: %d %s", again.Code, again.Body.String())
	}
	v2, err := svc.GetTemplate(context.Background(), connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "staff-badge"}))
	if err != nil {
		t.Fatal(err)
	}
	if v2.Msg.GetTemplate().GetVersion() != 2 || v2.Msg.GetTemplate().GetDcql() == "" {
		t.Errorf("version 2 = %+v", v2.Msg.GetTemplate())
	}

	dcqlSaved := postForm(mux, "/discovery/pe/edit/staff-badge", url.Values{"action": {"save_dcql"}, "definition": {changed}, "display_name": {"Staff badge DCQL"}}, false)
	if dcqlSaved.Code != http.StatusSeeOther || !strings.HasPrefix(dcqlSaved.Header().Get("Location"), "/discovery/templates/staff-badge-dcql") {
		t.Fatalf("save as DCQL: %d %q %s", dcqlSaved.Code, dcqlSaved.Header().Get("Location"), dcqlSaved.Body.String())
	}

	if rec := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/pe/edit/nothing", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("missing query: %d", rec.Code)
	}
	noName := postForm(mux, "/discovery/pe/new", url.Values{"action": {"save"}, "definition": {`{"id": "", "input_descriptors": [{"id": "x", "constraints": {}}]}`}}, false)
	if noName.Code != http.StatusBadRequest {
		t.Errorf("save without a name: %d", noName.Code)
	}
}

// TestPeListShowsStacksThatNeedIt names the live verifier stacks that
// read PE and not DCQL, lists the saved PE queries, and shows the PE
// form of each DCQL query with what it loses.
func TestPeListShowsStacksThatNeedIt(t *testing.T) {
	mux, svc := peShell(t)
	empty := staffGet(t, mux, "/discovery/pe/")
	a11ytest.AssertPage(t, empty)
	if !strings.Contains(empty, "Legacy stack") {
		t.Error("the list does not name the stack that needs PE")
	}
	needs := empty[strings.Index(empty, `id="pe-stacks"`):]
	needs = needs[:strings.Index(needs, "</section>")]
	for _, other := range []string{"Both stack", "Modern stack"} {
		if strings.Contains(needs, other) {
			t.Errorf("%s reads DCQL, yet the list says it needs PE", other)
		}
	}
	if _, err := svc.CreateTemplate(context.Background(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: &discoveryv1.PresentationTemplate{
		DisplayName: "Staff badge", Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE, PresentationDefinition: badgePE,
	}})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTemplate(context.Background(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{Template: &discoveryv1.PresentationTemplate{
		DisplayName: "Licence check", Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
			Type: licenceType, Format: commonv1.Format_FORMAT_DC_SD_JWT, Claims: []string{"licence_class"}, Issuers: []string{"https://issuer.example"},
		}},
	}})); err != nil {
		t.Fatal(err)
	}
	body := staffGet(t, mux, "/discovery/pe/")
	a11ytest.AssertPage(t, body)
	for _, want := range []string{
		"Staff badge", `href="/discovery/pe/edit/staff-badge"`, "Loses parts",
		"Licence check", "input_descriptors", "PE has no list of trusted issuers", `href="/discovery/pe/new?from=licence-check"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	from := staffGet(t, mux, "/discovery/pe/new?from=licence-check")
	a11ytest.AssertPage(t, from)
	if !strings.Contains(html.UnescapeString(from), `"id": "licence-check"`) {
		t.Error("the editor did not load the PE form of the DCQL query")
	}
}

// TestPeEditorRefusals shows each refusal on the editor: no file to
// import, a definition no DCQL query holds, a name that exists, and a
// DCQL query that is not a PE query.
func TestPeEditorRefusals(t *testing.T) {
	mux, _, _ := builderPortal(t)
	noFile := multipartPost(t, mux, "/discovery/pe/new", url.Values{"action": {"import"}}, "")
	if noFile.Code != http.StatusBadRequest || !strings.Contains(noFile.Body.String(), "Pick a JSON file to import.") {
		t.Errorf("import without a file: %d", noFile.Code)
	}
	noFormat := `{"id": "x", "input_descriptors": [{"id": "a", "constraints": {}}]}`
	for _, action := range []string{"convert", "save_dcql"} {
		rec := postForm(mux, "/discovery/pe/new", url.Values{"action": {action}, "definition": {noFormat}, "display_name": {"X"}}, false)
		if rec.Code != http.StatusBadRequest || !strings.Contains(html.UnescapeString(rec.Body.String()), "names no credential format") {
			t.Errorf("%s without a format: %d", action, rec.Code)
		}
	}
	form := url.Values{"action": {"save"}, "definition": {badgePE}, "display_name": {"Badge"}}
	if rec := postForm(mux, "/discovery/pe/new", form, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("first save: %d", rec.Code)
	}
	again := postForm(mux, "/discovery/pe/new", form, false)
	if again.Code != http.StatusBadRequest || !strings.Contains(again.Body.String(), "The service did not save the query.") {
		t.Errorf("second save: %d", again.Code)
	}
	converted := postForm(mux, "/discovery/pe/new", url.Values{"action": {"save_dcql"}, "definition": {badgePE}, "display_name": {"Badge"}}, false)
	if converted.Code != http.StatusBadRequest {
		t.Errorf("DCQL save over a PE name: %d", converted.Code)
	}
	if rec := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/pe/edit/driving", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown query: %d", rec.Code)
	}
	if rec := postForm(mux, "/discovery/dcql/", builderForm("save"), false); rec.Code != http.StatusSeeOther {
		t.Fatalf("DCQL save: %d", rec.Code)
	}
	if rec := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/pe/edit/driving-licence-check", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("a DCQL query in the PE editor: %d", rec.Code)
	}
	if rec := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/pe/new?from=nothing", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("from an unknown query: %d", rec.Code)
	}
	list := do(mux, httptest.NewRequest(http.MethodGet, "/discovery/pe/", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), `id="pe-stacks"`) {
		t.Errorf("the plain list names stacks: %d", list.Code)
	}
	bad := do(mux, httptest.NewRequest(http.MethodPost, "/discovery/pe/new", strings.NewReader("%zz")))
	if bad.Code != http.StatusBadRequest {
		t.Errorf("a broken form: %d", bad.Code)
	}
}
