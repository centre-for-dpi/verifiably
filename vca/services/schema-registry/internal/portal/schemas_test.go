// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// Stack names the adapters report. The tests hold no vendor name
// (ADR-001 decision 4).
const (
	firstStack  = "First stack"
	secondStack = "Second stack"
	thirdStack  = "Third stack"
)

// fakeIssued answers IssuedService.List with a count per schema and
// records the filter and the actor of each call.
type fakeIssued struct {
	mu      sync.Mutex
	counts  map[string]int64
	schemas []string
	actors  []string
	err     error
}

func (f *fakeIssued) List(_ context.Context, req *connect.Request[issuedv1.ListRequest]) (*connect.Response[issuedv1.ListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schemas = append(f.schemas, req.Msg.GetFilter().GetSchemaId())
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&issuedv1.ListResponse{Page: &commonv1.PageResult{TotalSize: f.counts[req.Msg.GetFilter().GetSchemaId()]}}), nil
}

// stack is one issuer pair of a test deployment with its adapter answer.
type stack struct {
	dpg      configv1.Dpg
	name     string
	state    topology.State
	formats  []commonv1.Format
	features []backendv1.Feature
}

// issuerPeer returns the issuer pair of a DPG.
func issuerPeer(dpg configv1.Dpg) topology.Peer {
	pair := topology.PairName(commonv1.Role_ROLE_ISSUER, dpg)
	return topology.Peer{Pair: pair, Role: commonv1.Role_ROLE_ISSUER, Dpg: dpg,
		PublicURL: "https://" + pair + ".labs.example", Services: map[string]string{"issuer-auth": "http://" + pair + "-auth:8081"}}
}

// shellOf builds the issuer shell of the first stack's pair over a
// snapshot of every stack.
func shellOf(stacks ...stack) *staffshell.Shell {
	var peers []topology.Peer
	snap := topology.Snapshot{}
	for _, s := range stacks {
		peer := issuerPeer(s.dpg)
		peers = append(peers, peer)
		st := topology.Status{Peer: peer, State: s.state}
		if s.state == topology.Live {
			st.Capabilities = &backendv1.GetCapabilitiesResponse{
				Formats: s.formats, Features: s.features, Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER},
				DpgInfo: &backendv1.DpgInfo{DisplayName: s.name},
			}
		}
		snap.Peers = append(snap.Peers, st)
	}
	return staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_ISSUER, Peers: peers,
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  peers[0].Auth() + staffshell.JWKSPath, SignOut: "/portal/signout",
	})
}

// configAPI is the feature a stack lists when it takes schemas.
var configAPI = []backendv1.Feature{backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API}

// deployment is three live issuer stacks: the own one takes schemas in
// three formats, the second takes none, the third takes schemas.
func deployment() *staffshell.Shell {
	return shellOf(
		stack{dpg: configv1.Dpg_DPG_WALTID, name: firstStack, state: topology.Live, features: configAPI, formats: []commonv1.Format{
			commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_JWT_VC_JSON, commonv1.Format_FORMAT_MSO_MDOC,
		}},
		stack{dpg: configv1.Dpg_DPG_INJI, name: secondStack, state: topology.Live, formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}},
		stack{dpg: configv1.Dpg_DPG_CREDEBL, name: thirdStack, state: topology.Live, features: configAPI, formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT}},
	)
}

// staffServer wires a portal with a shell and an issued client, and
// signs every request in as one staff member.
func staffServer(t *testing.T, svc *service.Service, shell *staffshell.Shell, issued Issued) http.Handler {
	t.Helper()
	p, err := New(Options{Client: svc, Shell: shell, Issued: issued, BuilderURL: "/builder/"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	sess := staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", CSRF: "tok"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(staffsession.With(r.Context(), sess)))
	})
}

func get(t *testing.T, h http.Handler, target string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", target, rec.Code, rec.Body.String())
	}
	a11ytest.AssertPage(t, rec.Body.String())
	return rec.Body.String()
}

// states builds one schema per life cycle state: a draft, a published
// one, and a retired one. It returns their ids in that order.
func states(t *testing.T, svc *service.Service, draftID string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	mk := func(typ, name string) string {
		resp, err := svc.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
			Type: typ, JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
			Display: []*schemav1.Display{{Name: name, Locale: "en"}},
		}}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.GetSchema().GetId()
	}
	published, retired := mk("FarmerCredential", "Farmer"), mk("LandTitle", "Land title")
	for _, id := range []string{published, retired} {
		if _, err := svc.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: id})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: retired})); err != nil {
		t.Fatal(err)
	}
	return draftID, published, retired
}

// row returns the table row of the list page that links to one schema.
func row(t *testing.T, body, id string) string {
	t.Helper()
	i := strings.Index(body, `href="/portal/schemas/`+id+`?version=`)
	if i < 0 {
		t.Fatalf("the list has no row for %s", id)
	}
	start := strings.LastIndex(body[:i], "<tr")
	end := strings.Index(body[i:], "</tr>")
	return body[start : i+end]
}

// TestSchemaRowActions checks the row of each state: every state takes
// a new version; a draft deletes; a published schema maps, issues and
// retires; a retired one only takes a new version.
func TestSchemaRowActions(t *testing.T) {
	svc, first := registry(t)
	draft, published, retired := states(t, svc, first)
	h := staffServer(t, svc, deployment(), nil)
	body := get(t, h, "/portal/")
	newVersion, issue := msg.T("issuer.schemas.action.version.label"), msg.T("issuer.schemas.action.issue.label")
	retire, remove := msg.T("issuer.schemas.action.retire.label"), msg.T("issuer.schemas.action.delete.label")
	cases := []struct {
		id      string
		want    []string
		without []string
	}{
		{draft, []string{newVersion, `href="/builder/?id=` + draft + `"`, remove,
			`action="/portal/schemas/` + draft + `/delete"`, `name="csrf_token" value="tok"`}, []string{issue, retire}},
		{published, []string{newVersion, issue, `href="/issue/?schema=` + published + `"`, retire,
			`href="/portal/schemas/` + published + `?version=1#actions"`}, []string{remove}},
		{retired, []string{newVersion}, []string{issue, "#actions", remove}},
	}
	for _, c := range cases {
		r := row(t, body, c.id)
		for _, want := range c.want {
			if !strings.Contains(r, want) {
				t.Errorf("%s: the row lacks %q", c.id, want)
			}
		}
		for _, bad := range c.without {
			if strings.Contains(r, bad) {
				t.Errorf("%s: the row has %q", c.id, bad)
			}
		}
	}
	for _, want := range []string{
		msg.T("issuer.schemas.lead"), msg.T("issuer.schemas.builder.label"), `href="/portal/publish"`,
		msg.T("issuer.schemas.status.any.label"), msg.T("issuer.schemas.format.any.label"), msg.T("issuer.schemas.rule"),
		`<span class="hint"><code>` + published + "</code></span>", "v1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	// The delete action removes the draft and says so.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/portal/schemas/"+draft+"/delete", strings.NewReader("version=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal/?notice=deleted" {
		t.Fatalf("delete: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	after := get(t, h, rec.Header().Get("Location"))
	if strings.Contains(after, `/portal/schemas/`+draft+`?`) || !strings.Contains(after, msg.T("issuer.schemas.deleted")) {
		t.Fatal("the deleted draft is still listed, or the page has no notice")
	}
	// A published version cannot go through the form either.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/portal/schemas/"+published+"/delete", strings.NewReader("version=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete of a published version: %d", rec.Code)
	}
}

// TestIssuedCountColumn checks that each row shows the count of the
// issued credentials of its schema, asked of the issued credentials
// service in the name of the staff member, and a dash when it fails.
func TestIssuedCountColumn(t *testing.T) {
	svc, first := registry(t)
	_, published, _ := states(t, svc, first)
	issued := &fakeIssued{counts: map[string]int64{published: 128}}
	h := staffServer(t, svc, deployment(), issued)
	body := get(t, h, "/portal/")
	if !strings.Contains(body, "<th scope=\"col\">"+msg.T("issuer.schemas.column.issued.label")+"</th>") {
		t.Fatal("the table has no issued column")
	}
	if !strings.Contains(row(t, body, published), "<td>128</td>") || !strings.Contains(row(t, body, first), "<td>0</td>") {
		t.Fatal("the rows lack the issued counts")
	}
	if len(issued.schemas) != 3 || issued.actors[0] != "kc|wanjiru" {
		t.Fatalf("calls %v by %v", issued.schemas, issued.actors)
	}
	issued.err = connect.NewError(connect.CodeUnavailable, nil)
	body = get(t, h, "/portal/")
	if !strings.Contains(row(t, body, published), "<td>-</td>") {
		t.Fatal("a failed count shows no dash")
	}
	// Without the issued credentials service the column shows a dash.
	body = get(t, staffServer(t, svc, deployment(), nil), "/portal/")
	if !strings.Contains(row(t, body, published), "<td>-</td>") {
		t.Fatal("no service shows no dash")
	}
}

// postUpload posts the publish form with a file and the fields.
func postUpload(t *testing.T, h http.Handler, file string, fields url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, vs := range fields {
		for _, v := range vs {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if file != "" {
		fw, err := mw.CreateFormFile("file", "farmer.schema.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(file)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/portal/publish", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const farmerDoc = `{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Farmer credential",
"type":"object","properties":{"farmer_id":{"type":"string"},"county":{"type":"string"}},"required":["farmer_id"]}`

// TestPublishFromFile checks the upload: the page takes a JSON Schema
// file, derives the type and the name from its title, publishes it on
// the own stack, and says why a bad file does not go in.
func TestPublishFromFile(t *testing.T) {
	svc, _ := registry(t)
	h := staffServer(t, svc, deployment(), nil)
	body := get(t, h, "/portal/publish")
	for _, want := range []string{`enctype="multipart/form-data"`, `type="file"`, `accept="application/json,.json"`, `name="csrf_token"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the publish page lacks %q", want)
		}
	}
	rec := postUpload(t, h, farmerDoc, url.Values{"formats": {"dc+sd-jwt", "mso_mdoc"}, "target": {"publish"}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=published") {
		t.Fatalf("upload: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	found, err := svc.Search(context.Background(), connect.NewRequest(&schemav1.SearchRequest{Query: "FarmerCredential"}))
	if err != nil || len(found.Msg.GetSchemas()) != 1 {
		t.Fatalf("search %v %v", found, err)
	}
	m := found.Msg.GetSchemas()[0]
	if m.GetState() != schemav1.State_STATE_PUBLISHED || Name(m) != "Farmer credential" || len(m.GetFormats()) != 2 {
		t.Fatalf("stored %v", m)
	}
	// Keep as a draft, with the type and the name from the form.
	rec = postUpload(t, h, farmerDoc, url.Values{"formats": {"jwt_vc_json"}, "target": {"draft"}, "type": {"Farmer2"}, "name": {"Farmer, second"}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=uploaded") {
		t.Fatalf("draft upload: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	found, err = svc.Search(context.Background(), connect.NewRequest(&schemav1.SearchRequest{Query: "Farmer2"}))
	if err != nil || len(found.Msg.GetSchemas()) != 1 || found.Msg.GetSchemas()[0].GetState() != schemav1.State_STATE_DRAFT {
		t.Fatalf("draft %v %v", found, err)
	}
	// Each bad upload renders the form again with the reason.
	for _, c := range []struct {
		file   string
		fields url.Values
		want   string
	}{
		{"", url.Values{"formats": {"dc+sd-jwt"}}, msg.T("issuer.schemas.upload.error.file")},
		{"{", url.Values{"formats": {"dc+sd-jwt"}}, msg.T("issuer.schemas.upload.error.document")},
		{farmerDoc, url.Values{}, msg.T("issuer.schemas.upload.error.formats")},
		{farmerDoc, url.Values{"formats": {"ldp_vc"}}, msg.T("issuer.schemas.upload.error.formats")},
		{`{"type":"object"}`, url.Values{"formats": {"dc+sd-jwt"}}, msg.T("issuer.schemas.upload.error.type")},
	} {
		rec := postUpload(t, h, c.file, c.fields)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("%q %v: %d, want %q in the page", c.file, c.fields, rec.Code, c.want)
		}
		a11ytest.AssertPage(t, rec.Body.String())
	}
}

// TestPublishToStackFollowsCapabilities checks the publish targets: the
// page offers the formats the own stack issues, publishes only on a
// stack whose adapter takes schemas, and links to the other live stacks
// that take them.
func TestPublishToStackFollowsCapabilities(t *testing.T) {
	svc, id := registry(t)
	body := get(t, staffServer(t, svc, deployment(), nil), "/portal/publish")
	for _, want := range []string{
		msg.T("issuer.schemas.target.publish.label", firstStack), `value="jwt_vc_json"`, `value="mso_mdoc"`,
		`href="https://issuer-credebl.labs.example/portal/publish"`, thirdStack,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the publish page lacks %q", want)
		}
	}
	for _, bad := range []string{`value="ldp_vc"`, "issuer-inji.labs.example/portal/publish"} {
		if strings.Contains(body, bad) {
			t.Errorf("the publish page has %q", bad)
		}
	}
	// The detail page of a draft publishes on the own stack.
	detail := get(t, staffServer(t, svc, deployment(), nil), "/portal/schemas/"+id)
	if !strings.Contains(detail, "Publish this version") || !strings.Contains(detail, msg.T("issuer.schemas.target.text", firstStack)) {
		t.Fatal("the draft detail has no publish on the own stack")
	}
	// An own stack whose adapter takes no schema keeps the upload a draft.
	own := shellOf(
		stack{dpg: configv1.Dpg_DPG_INJI, name: secondStack, state: topology.Live, formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}},
		stack{dpg: configv1.Dpg_DPG_WALTID, name: firstStack, state: topology.Live, features: configAPI, formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT}},
	)
	h := staffServer(t, svc, own, nil)
	body = get(t, h, "/portal/publish")
	if strings.Contains(body, msg.T("issuer.schemas.target.publish.label", secondStack)) ||
		!strings.Contains(body, msg.T("issuer.schemas.target.none", secondStack)) ||
		!strings.Contains(body, `href="https://issuer-waltid.labs.example/portal/publish"`) {
		t.Fatal("a stack that takes no schema still offers publish, or hides the other stack")
	}
	rec := postUpload(t, h, farmerDoc, url.Values{"formats": {"ldp_vc"}, "target": {"publish"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), msg.T("issuer.schemas.upload.error.target")) {
		t.Fatalf("publish on a stack that takes no schema: %d", rec.Code)
	}
	detail = get(t, h, "/portal/schemas/"+id)
	if strings.Contains(detail, "Publish this version") || !strings.Contains(detail, msg.T("issuer.schemas.target.none", secondStack)) {
		t.Fatal("the draft detail publishes on a stack that takes no schema")
	}
	// A draft in a format the own stack does not issue cannot publish.
	detail = get(t, staffServer(t, svc, shellOf(
		stack{dpg: configv1.Dpg_DPG_WALTID, name: firstStack, state: topology.Live, features: configAPI, formats: []commonv1.Format{commonv1.Format_FORMAT_MSO_MDOC}},
	), nil), "/portal/schemas/"+id)
	if strings.Contains(detail, "Publish this version") || !strings.Contains(detail, strings.ReplaceAll(msg.T("issuer.schemas.target.formats", firstStack, "dc+sd-jwt"), "+", "&#43;")) {
		t.Fatal("a draft publishes in a format the stack does not issue")
	}
	// A stack that is starting takes no publish yet.
	detail = get(t, staffServer(t, svc, shellOf(stack{dpg: configv1.Dpg_DPG_WALTID, state: topology.Starting}), nil), "/portal/schemas/"+id)
	if strings.Contains(detail, "Publish this version") {
		t.Fatal("a starting stack takes a publish")
	}
}

// TestPublishOnTheOwnStackOnlyWhenItTakesSchemas turns publish on for an
// own stack whose adapter starts to list FEATURE_CREDENTIAL_CONFIG_API,
// with the formats that adapter issues, and keeps it off without it.
func TestPublishOnTheOwnStackOnlyWhenItTakesSchemas(t *testing.T) {
	svc, _ := registry(t)
	formats := []commonv1.Format{commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_VC_SD_JWT}
	with := get(t, staffServer(t, svc, shellOf(
		stack{dpg: configv1.Dpg_DPG_INJI, name: secondStack, state: topology.Live, features: configAPI, formats: formats},
	), nil), "/portal/publish")
	a11ytest.AssertPage(t, with)
	for _, want := range []string{msg.T("issuer.schemas.target.publish.label", secondStack), `value="ldp_vc"`, `value="vc&#43;sd-jwt"`} {
		if !strings.Contains(with, want) {
			t.Errorf("the publish page lacks %q", want)
		}
	}
	without := get(t, staffServer(t, svc, shellOf(
		stack{dpg: configv1.Dpg_DPG_INJI, name: secondStack, state: topology.Live, formats: formats},
	), nil), "/portal/publish")
	if strings.Contains(without, msg.T("issuer.schemas.target.publish.label", secondStack)) ||
		!strings.Contains(without, msg.T("issuer.schemas.target.none", secondStack)) {
		t.Error("publish shows for a stack whose adapter takes no schema")
	}
}
