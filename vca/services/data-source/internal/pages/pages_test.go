// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestSourcesListIsTheSourceStepOfABulkRun proves the list names the
// schema the issue wizard sent, shows the stepper, and lets each source
// start the field map.
func TestSourcesListIsTheSourceStepOfABulkRun(t *testing.T) {
	h := newHarness(t)
	empty := body(t, h.get(t, "/sources/?schema=farmer%402"))
	a11ytest.AssertPage(t, empty)
	for _, want := range []string{"No data source yet.", `href="/sources/new?kind=csv&amp;schema=farmer%402"`, "Farmer registration", `aria-current="step"`} {
		if !strings.Contains(empty, want) {
			t.Errorf("the empty list has no %q", want)
		}
	}
	id := h.addFarmers(t)
	page := body(t, h.get(t, "/sources/?schema=farmer%402"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Farmers of Kiambu 2026", "CSV file", `href="/sources/` + id + `/map?schema=farmer%402"`, "Use this source", `href="/sources/" aria-current="page"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the list has no %q", want)
		}
	}
	plain := body(t, h.get(t, "/sources/?schema=nope"))
	if strings.Contains(plain, "Use this source") || strings.Contains(plain, `aria-current="step"`) {
		t.Error("a schema the registry lacks must not start a run")
	}
}

// TestCreateCsvSourceFromUpload proves an operator adds a CSV source by
// upload: the page keeps the bytes, the service stores the source with
// the default role rules, and the browser goes to its preview.
func TestCreateCsvSourceFromUpload(t *testing.T) {
	h := newHarness(t)
	form := body(t, h.get(t, "/sources/new?kind=csv&schema=farmer%402"))
	a11ytest.AssertPage(t, form)
	for _, want := range []string{`enctype="multipart/form-data"`, `type="file"`, `accept=".csv,text/csv"`, "1 MB at most", `name="csrf_token"`} {
		if !strings.Contains(form, want) {
			t.Errorf("the upload form has no %q", want)
		}
	}
	rec := h.upload(t, map[string]string{"name": "Farmers of Kiambu 2026", "delimiter": "comma", "header": "yes", "schema": "farmer@2"}, farmers)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	list, err := h.svc.List(as(session), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil || len(list.Msg.GetSources()) != 1 {
		t.Fatalf("sources = %v, %v", list, err)
	}
	src := list.Msg.GetSources()[0]
	if loc := rec.Header().Get("Location"); loc != "/sources/"+src.GetId()+"?schema=farmer%402" {
		t.Errorf("location = %q", loc)
	}
	if src.GetDisplayName() != "Farmers of Kiambu 2026" || !src.GetCsv().GetHasHeader() || len(h.saved) != 1 || string(h.saved[0]) != farmers {
		t.Errorf("source = %v, saved %d files", src, len(h.saved))
	}
	if got := src.GetAccess().GetIssue(); len(got) != 1 || got[0] != staffsession.IssuerOperatorRole {
		t.Errorf("issue rule = %v", got)
	}
}

// TestUploadChecksTheFile proves the page refuses a file over the cap, a
// file that is not CSV, and a form without a name, and keeps no source.
func TestUploadChecksTheFile(t *testing.T) {
	h := newHarness(t)
	big := strings.Repeat("a,b\n", 2000)
	for name, c := range map[string]struct {
		fields map[string]string
		file   string
		want   string
	}{
		"too large": {map[string]string{"name": "Big"}, big, "The file is larger than 1 MB."},
		"not csv":   {map[string]string{"name": "Bad"}, "\xff\xfe\x00", "VCA cannot read this file as CSV."},
		"no name":   {map[string]string{"name": " "}, farmers, "Type a name."},
	} {
		page := body(t, h.upload(t, c.fields, c.file))
		if !strings.Contains(page, c.want) || !strings.Contains(page, `aria-invalid="true"`) {
			t.Errorf("%s: the form has no error %q", name, c.want)
		}
		a11ytest.AssertPage(t, page)
	}
	list, err := h.svc.List(as(session), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil || len(list.Msg.GetSources()) != 0 {
		t.Fatalf("a refused upload became a source: %v %v", list, err)
	}
	if rec := h.upload(t, map[string]string{"name": "Huge"}, strings.Repeat("x", 3<<20)); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "larger than") {
		t.Errorf("a body over the cap: status %d", rec.Code)
	}
}

// TestSqlSourceKeepsASecretReference proves a database source holds the
// name of the secret of its connection string, never a value.
func TestSqlSourceKeepsASecretReference(t *testing.T) {
	h := newHarness(t)
	form := body(t, h.get(t, "/sources/new?kind=sql"))
	a11ytest.AssertPage(t, form)
	if !strings.Contains(form, "This build of VCA holds no database driver.") || strings.Contains(form, `type="password"`) {
		t.Error("the form must say the build has no driver and ask for no secret value")
	}
	bad := body(t, h.post(t, pages.NewPath+"/sql", url.Values{"name": {"Registry"}, "driver": {"postgres"}, "secret-store": {"env"}, "secret-name": {"postgres://user:pw@db"}, "query": {"DELETE FROM farmers"}}))
	for _, want := range []string{"Type the name of an environment variable in capitals", "Type one SELECT statement."} {
		if !strings.Contains(bad, want) {
			t.Errorf("the refused form has no %q", want)
		}
	}
	rec := h.post(t, pages.NewPath+"/sql", url.Values{"name": {"Farmer registry"}, "driver": {"postgres"}, "secret-store": {"file"}, "secret-name": {"farmers-dsn"},
		"query": {"SELECT full_name, farmer_id FROM farmers"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	list, err := h.svc.List(as(session), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	dsn := list.Msg.GetSources()[0].GetSql().GetDsn()
	if dsn.GetName() != "farmers-dsn" || dsn.GetStore().String() != "STORE_FILE" {
		t.Errorf("dsn reference = %v", dsn)
	}
}

// TestHttpSourceFollowsTheAllowlist proves the page names the hosts of
// the allowlist and refuses an address outside it.
func TestHttpSourceFollowsTheAllowlist(t *testing.T) {
	h := newHarness(t)
	form := body(t, h.get(t, "/sources/new?kind=http"))
	a11ytest.AssertPage(t, form)
	if !strings.Contains(form, "registry.agriculture.go.ke, .coop.example") {
		t.Error("the form must list the allowed hosts")
	}
	for raw, want := range map[string]string{
		"https://evil.example/farmers":            "This host is not on the allowlist",
		"http://registry.agriculture.go.ke/x":     "Use an address that starts with https.",
		"https://registry.agriculture.go.ke%zz/x": "Type a full address that starts with https.",
	} {
		page := body(t, h.post(t, pages.NewPath+"/http", url.Values{"name": {"Registry"}, "url": {raw}, "rows-path": {"/data"}}))
		if !strings.Contains(page, want) {
			t.Errorf("%s: no %q", raw, want)
		}
	}
	page := body(t, h.post(t, pages.NewPath+"/http", url.Values{"name": {"Registry"}, "url": {"https://registry.agriculture.go.ke/farmers"}, "rows-path": {"data"}, "auth": {"bearer"}, "secret-name": {""}}))
	if !strings.Contains(page, "Start the path with a slash") {
		t.Error("a rows path without a slash must fail")
	}
	rec := h.post(t, pages.NewPath+"/http", url.Values{"name": {"Cooperative register"}, "url": {"https://members.coop.example/api/farmers"},
		"method": {"GET"}, "rows-path": {"/data/items"}, "auth": {"bearer"}, "secret-store": {"env"}, "secret-name": {"COOP_API_TOKEN"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	h.opts.AllowHosts = nil
	h.build(t)
	none := body(t, h.post(t, pages.NewPath+"/http", url.Values{"name": {"Registry"}, "url": {"https://registry.agriculture.go.ke/x"}}))
	if !strings.Contains(none, "No host is on the allowlist yet.") || !strings.Contains(none, "holds no host") {
		t.Error("an empty allowlist must say so")
	}
}

// TestPreviewMasksValues proves the source page shows the fields with
// their types and masked rows, and never a value in the clear.
func TestPreviewMasksValues(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	page := body(t, h.get(t, "/sources/"+id))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Full Name", "Yes or no", "W***********i", "F*****2", "3 of 3 rows", "Map the fields"} {
		if !strings.Contains(page, want) {
			t.Errorf("the preview has no %q", want)
		}
	}
	for _, clear := range []string{"Wanjiku Njeri", "FM-0042", "Otieno"} {
		if strings.Contains(page, clear) {
			t.Errorf("the preview shows %q in the clear", clear)
		}
	}
	h.sess = viewer
	viewer := body(t, h.get(t, "/sources/"+id))
	if !strings.Contains(viewer, "Your role sees the field names only.") || strings.Contains(viewer, `id="preview-rows"`) {
		t.Error("a viewer must see the field names and no rows")
	}
	if rec := h.get(t, "/sources/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown source: %d", rec.Code)
	}
}

// TestFieldMapSaves proves the map page suggests fields by name, saves
// the transforms, and sends the browser to the run.
func TestFieldMapSaves(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	ask := body(t, h.get(t, "/sources/"+id+"/map"))
	a11ytest.AssertPage(t, ask)
	if !strings.Contains(ask, `value="farmer@2"`) {
		t.Fatal("the map page must ask for a schema first")
	}
	page := body(t, h.get(t, "/sources/"+id+"/map?schema=farmer%402"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Full name, fullName", "address.county", `<option value="Full Name" selected>`, "A whole number. The schema needs it.", `<option value="date_dmy">`} {
		if !strings.Contains(page, want) {
			t.Errorf("the map page has no %q", want)
		}
	}
	rec := h.post(t, "/sources/"+id+"/map", mapForm())
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sources/"+id+"/run?schema=farmer%402" {
		t.Fatalf("status %d location %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	saved, err := h.svc.GetFieldMap(as(session), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id, SchemaId: "farmer"}))
	if err != nil {
		t.Fatal(err)
	}
	fm := service.FieldMapFromProto(saved.Msg.GetFieldMap())
	rules := map[string]mapping.Rule{}
	for _, r := range fm.Rules {
		rules[r.Property] = r
	}
	if fm.SchemaVersion != 2 || len(fm.Rules) != 7 {
		t.Fatalf("field map = %+v", fm)
	}
	if r := rules["dateOfBirth"]; r.Transform != mapping.DateFormat || r.Params[mapping.ParamInputLayout] != "02/01/2006" || r.Params[mapping.ParamOutputLayout] != "2006-01-02" {
		t.Errorf("date rule = %+v", r)
	}
	if r := rules["farmerID"]; r.Transform != mapping.Upper || r.SourceFields[0] != "Farmer ID" {
		t.Errorf("id rule = %+v", r)
	}
	again := body(t, h.get(t, "/sources/"+id+"/map?schema=farmer%402"))
	if !strings.Contains(again, `<option value="upper" selected>`) || !strings.Contains(again, `<option value="date_dmy" selected>`) {
		t.Error("the map page must show the saved transforms")
	}
}

// TestFieldMapChecksEachClaim proves a required claim needs a field, a
// fixed value needs a value, and a join names fields of the source.
func TestFieldMapChecksEachClaim(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	form := url.Values{"schema": {"farmer@2"}, "field.fullName": {"Full Name"}, "transform.fullName": {"concat"}, "value.fullName": {"Nope"},
		"field.farmerID": {"Missing column"}, "transform.organic": {"constant"}, "field.crops": {"Crops"}, "transform.crops": {"lower"},
		"transform.address.county": {"constant"}, "value.address.county": {"Kiambu"}}
	page := body(t, h.post(t, "/sources/"+id+"/map", form))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Fix the field map", "Pick a source field. The schema needs this claim.", "Pick a field of this source.", "Type the fixed value.", "Name fields of this source"} {
		if !strings.Contains(page, want) {
			t.Errorf("the refused map has no %q", want)
		}
	}
	if _, err := h.svc.GetFieldMap(as(session), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id, SchemaId: "farmer"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a refused map must not be saved: %v", err)
	}
	form = mapForm()
	form.Set("transform.fullName", "concat")
	form.Set("value.fullName", "County")
	form.Set("transform.dateOfBirth", "date_mdy")
	form.Set("transform.address.county", "constant")
	form.Set("value.address.county", "Kiambu")
	if rec := h.post(t, "/sources/"+id+"/map", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	again := body(t, h.get(t, "/sources/"+id+"/map?schema=farmer%402"))
	for _, want := range []string{`<option value="concat" selected>`, `value="County"`, `<option value="date_mdy" selected>`, `<option value="constant" selected>`, `value="Kiambu"`} {
		if !strings.Contains(again, want) {
			t.Errorf("the saved map has no %q", want)
		}
	}
}

// TestBulkRunKeepsJSONTypes proves a run fills the claims through the
// field map with their JSON types, as a single issue does: the text 12
// reaches the integer claim as 12. The call names the staff member in
// the actor header.
func TestBulkRunKeepsJSONTypes(t *testing.T) {
	h := newHarness(t)
	id := h.mapFarmers(t)
	form := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	a11ytest.AssertPage(t, form)
	for _, want := range []string{"Farmers of Kiambu 2026, CSV file", "7 of 7.", `value="CHANNEL_OID4VCI_PREAUTH" aria-describedby="channel-hint" checked`, `value="CHANNEL_PDF"`, `<option value="FORMAT_VC_SD_JWT">`, "Start the run"} {
		if !strings.Contains(form, want) {
			t.Errorf("the run form has no %q", want)
		}
	}
	if strings.Contains(form, "CHANNEL_DC_API") {
		t.Error("a bulk run has no browser of the holder, so no Digital Credentials API")
	}
	rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_OID4VCI_PREAUTH"}, "format": {"FORMAT_VC_SD_JWT"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sources/"+id+"/runs/job-7?schema=farmer%402" {
		t.Fatalf("status %d location %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	h.wait(t)
	req := h.issuance.requests[0]
	if req.GetSchemaId() != "farmer" || req.GetSchemaVersion() != 2 || req.GetChannel() != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH || req.GetNative() || len(req.GetItems()) != 3 {
		t.Fatalf("batch = %v", req)
	}
	if h.issuance.actors[0] != session.Subject {
		t.Errorf("actor = %q, want the staff member", h.issuance.actors[0])
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(req.GetItems()[0].GetSubjectData()), &first); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"fullName": "Wanjiku Njeri", "farmerID": "FM-0042", "dateOfBirth": "1984-03-12", "hectares": 12.0, "organic": true,
		"crops": []any{"tea", "maize"}, "address": map[string]any{"county": "Kiambu"}}
	if b1, b2 := mustJSON(t, first), mustJSON(t, want); b1 != b2 {
		t.Errorf("row 1 = %s\nwant    %s", b1, b2)
	}
	if !strings.Contains(req.GetItems()[0].GetSubjectData(), `"hectares":12,`) {
		t.Errorf("the integer claim must travel as a number: %s", req.GetItems()[0].GetSubjectData())
	}
	if third := req.GetItems()[2]; third.GetRow() != 3 || !strings.Contains(third.GetSubjectData(), `"hectares":"twelve"`) {
		t.Errorf("row 3 = %v, want the text for the schema check to name", third)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestBulkRunNeedsAMapAndAChannel proves the run page sends the browser
// to the missing step, and refuses a channel the pair lacks.
func TestBulkRunNeedsAMapAndAChannel(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	if rec := h.get(t, "/sources/"+id+"/run?schema=farmer%402"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sources/"+id+"/map?schema=farmer%402" {
		t.Errorf("no map: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := h.get(t, "/sources/"+id+"/run"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/sources/"+id+"/map" {
		t.Errorf("no schema: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	h.post(t, "/sources/"+id+"/map", mapForm())
	page := body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_OID4VCI_AUTHCODE"}}))
	if !strings.Contains(page, "Pick one of the delivery channels.") || len(h.issuance.requests) != 0 {
		t.Error("a channel the adapter does not list must not start a run")
	}
	h.issuance.startErr = connect.NewError(connect.CodeUnavailable, context.DeadlineExceeded)
	page = body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_PDF"}}))
	if !strings.Contains(page, "The issuance service did not start the run.") {
		t.Error("a failed start must say so")
	}
	h.opts.Issuance = nil
	h.build(t)
	page = body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	if !strings.Contains(page, "This pair has no issuance service") || strings.Contains(page, "Start the run") {
		t.Error("a pair without the issuance service must not offer a start")
	}
}

// TestBulkNativeOptionOnlyWithFeature proves the bulk import of the
// stack shows only when the adapter lists FEATURE_BULK_NATIVE, and that
// it asks the issuance service for a native batch of documents.
func TestBulkNativeOptionOnlyWithFeature(t *testing.T) {
	h := newHarness(t)
	id := h.mapFarmers(t)
	without := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	if strings.Contains(without, `value="native"`) || strings.Contains(without, "bulk import") {
		t.Error("the native option must hide without the feature")
	}
	// A forged form without the feature runs through VCA.
	h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "method": {"native"}, "channel": {"CHANNEL_PDF"}})
	h.wait(t)
	if h.issuance.requests[0].GetNative() {
		t.Error("a pair without the feature must not ask for a native batch")
	}

	h = newHarness(t, backendv1.Feature_FEATURE_BULK_NATIVE)
	id = h.mapFarmers(t)
	with := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	a11ytest.AssertPage(t, with)
	if !strings.Contains(with, `value="native"`) || !strings.Contains(with, stackName+" bulk import") {
		t.Fatal("the native option must show with the feature")
	}
	rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "method": {"native"}, "channel": {"CHANNEL_OID4VCI_PREAUTH"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	h.wait(t)
	if req := h.issuance.requests[0]; !req.GetNative() || req.GetChannel() != backendv1.Channel_CHANNEL_PDF {
		t.Errorf("native batch = %v", req)
	}
}

// TestBulkRunShowsProgress proves the progress page refreshes itself
// through htmx every two seconds while the run goes on, keeps a refresh
// link for a browser without JavaScript, and offers the export when the
// run is over.
func TestBulkRunShowsProgress(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	h.issuance.progress = &issuancev1.IssueBatchResponse{JobId: "job-7", Total: 40, Processed: 12, Accepted: 11, Rejected: 1}
	h.issuance.rows = runRows()
	path := "/sources/" + id + "/runs/job-7"
	page := body(t, h.get(t, path+"?schema=farmer%402"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{
		`hx-get="` + path + `/progress"`, `hx-trigger="every 2s"`, `hx-swap="outerHTML"`, `href="` + path + `"`,
		"Row 12 of 40", "The run goes on.", "Farmer registration", `href="/issue/offers/offer-1"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the progress page has no %q", want)
		}
	}
	if strings.Contains(page, "offers.csv") {
		t.Error("the export waits for the end of the run")
	}
	fragment := body(t, h.get(t, path+"/progress"))
	a11ytest.AssertFragment(t, fragment)
	if !strings.HasPrefix(strings.TrimSpace(fragment), `<section class="block" id="progress"`) || strings.Contains(fragment, "<html") {
		t.Errorf("the fragment is not the progress block: %.120s", fragment)
	}
	h.issuance.progress = &issuancev1.IssueBatchResponse{JobId: "job-7", Total: 3, Processed: 3, Accepted: 2, Rejected: 1, Done: true}
	done := body(t, h.get(t, path+"/progress"))
	a11ytest.AssertFragment(t, done)
	if strings.Contains(done, "hx-trigger") || !strings.Contains(done, path+"/offers.csv") || !strings.Contains(done, "2 credentials issued, 1 rows failed.") {
		t.Errorf("a finished run must stop the refresh and offer the export: %s", done)
	}
	for _, a := range h.issuance.actors {
		if a != session.Subject {
			t.Errorf("GetBatch actor = %q", a)
		}
	}
	if rec := h.get(t, "/sources/"+id+"/runs/job-8"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown job: %d", rec.Code)
	}
}

// TestBulkRowFailureListed proves the failed rows show with their
// problem in the progress block and in the result of each row.
func TestBulkRowFailureListed(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	h.issuance.progress = &issuancev1.IssueBatchResponse{JobId: "job-7", Total: 3, Processed: 3, Accepted: 2, Rejected: 1, Done: true}
	h.issuance.rows = runRows()
	h.issuance.next = "50"
	page := body(t, h.get(t, "/sources/"+id+"/runs/job-7"))
	a11ytest.AssertPage(t, page)
	failed := page[strings.Index(page, `id="failed-rows"`):strings.Index(page, `id="results"`)]
	if !strings.Contains(failed, "Amina Hassan") || !strings.Contains(failed, "/hectares: the value must have type integer") || strings.Contains(failed, "Wanjiku") {
		t.Errorf("the failed rows = %s", failed)
	}
	results := page[strings.Index(page, `id="results"`):]
	for _, want := range []string{"Wanjiku Njeri", "Issued", "Failed", `href="/sources/` + id + `/runs/job-7?page=50"`} {
		if !strings.Contains(results, want) {
			t.Errorf("the results have no %q", want)
		}
	}
	later := body(t, h.get(t, "/sources/"+id+"/runs/job-7?page=50"))
	if !strings.Contains(later, "Later row") {
		t.Error("the next page must show the next rows")
	}
}

// TestOffersExportCSV proves the export lists every row with its offer
// link, transaction code, document link, and problem, and keeps a
// spreadsheet from reading a value as a formula.
func TestOffersExportCSV(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	h.issuance.progress = &issuancev1.IssueBatchResponse{JobId: "job-7", Total: 3, Processed: 3, Done: true}
	h.issuance.rows = runRows()
	h.issuance.next = "50"
	rec := h.get(t, "/sources/"+id+"/runs/job-7/offers.csv")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		rec.Header().Get("Content-Disposition") != `attachment; filename="offers-job-7.csv"` {
		t.Fatalf("status %d headers %v", rec.Code, rec.Header())
	}
	records, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 || strings.Join(records[0], ",") != "row,label,result,offer_id,offer_link,transaction_code,document_link,problem" {
		t.Fatalf("records = %v", records)
	}
	if r := records[1]; r[2] != "issued" || r[3] != "offer-1" || r[5] != "493817" || !strings.HasPrefix(r[4], "openid-credential-offer://") {
		t.Errorf("row 1 = %v", r)
	}
	if r := records[2]; r[4] != `'=HYPERLINK("x")` || r[6] != "https://issuer.example/issuance/pdf/d2" {
		t.Errorf("row 2 = %v", r)
	}
	if r := records[3]; r[2] != "failed" || !strings.Contains(r[7], "/hectares") {
		t.Errorf("row 3 = %v", r)
	}
	if records[4][1] != "Later row" {
		t.Errorf("the export must read every page: %v", records[4])
	}
}

// TestViewerCannotAddOrRun proves an issuer viewer gets the page that
// names the operator role for every action that changes something.
func TestViewerCannotAddOrRun(t *testing.T) {
	h := newHarness(t)
	id := h.mapFarmers(t)
	h.sess = viewer
	for _, path := range []string{pages.NewPath + "/sql", pages.NewPath + "/http", pages.NewPath + "/csv", "/sources/" + id + "/map", "/sources/" + id + "/run", "/sources/" + id + "/delete"} {
		rec := h.post(t, path, url.Values{"schema": {"farmer@2"}})
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Operator role needed") {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
}

// TestDeleteRemovesTheSource proves an operator deletes a source.
func TestDeleteRemovesTheSource(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	if rec := h.post(t, "/sources/"+id+"/delete", nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != pages.Prefix {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := h.post(t, "/sources/"+id+"/delete", nil); rec.Code != http.StatusNotFound {
		t.Errorf("a second delete: %d", rec.Code)
	}
}

func TestNewChecksItsOptions(t *testing.T) {
	h := newHarness(t)
	for name, change := range map[string]func(*pages.Options){
		"kit":     func(o *pages.Options) { o.Kit = nil },
		"shell":   func(o *pages.Options) { o.Shell = nil },
		"sources": func(o *pages.Options) { o.Sources = nil },
	} {
		o := h.opts
		change(&o)
		if _, err := pages.New(o); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
