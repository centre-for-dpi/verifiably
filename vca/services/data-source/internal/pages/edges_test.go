// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// brokenSchemas fails every call, as a registry that does not answer.
type brokenSchemas struct{}

func (brokenSchemas) List(context.Context, *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
}

func (brokenSchemas) Get(context.Context, *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
}

// addHTTP adds an HTTP source the service cannot read: the service has
// no allowlist.
func (h *harness) addHTTP(t *testing.T) string {
	t.Helper()
	res, err := h.svc.Create(as(session), connect.NewRequest(&datasourcev1.CreateRequest{Source: &datasourcev1.Source{
		DisplayName: "Cooperative register", Access: &datasourcev1.Source_Access{Issue: []string{"issuer-operator"}, ViewFields: []string{"issuer-operator"}},
		Kind: &datasourcev1.Source_Http{Http: &datasourcev1.HttpSource{Url: "https://members.coop.example/api"}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.GetSource().GetId()
}

func TestEveryKindShowsInTheList(t *testing.T) {
	h := newHarness(t)
	h.addFarmers(t)
	h.addHTTP(t)
	if _, err := h.svc.Create(as(session), connect.NewRequest(&datasourcev1.CreateRequest{Source: &datasourcev1.Source{
		DisplayName: "Farmer registry", Access: &datasourcev1.Source_Access{ViewFields: []string{"issuer-operator"}}, Kind: &datasourcev1.Source_Sql{Sql: &datasourcev1.SqlSource{Driver: "postgres",
			Dsn: &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_ENV, Name: "FARMERS_DSN"}, Query: "SELECT 1"}},
	}})); err != nil {
		t.Fatal(err)
	}
	page := body(t, h.get(t, "/sources/"))
	for _, want := range []string{"CSV file", "Database", "HTTP API", "Open"} {
		if !strings.Contains(page, want) {
			t.Errorf("the list has no %q", want)
		}
	}
}

func TestAnUnknownKindShowsTheCsvForm(t *testing.T) {
	h := newHarness(t)
	page := body(t, h.get(t, "/sources/new?kind=ftp"))
	if !strings.Contains(page, `type="file"`) {
		t.Error("an unknown kind must show the CSV form")
	}
}

func TestSqlFormListsTheDrivers(t *testing.T) {
	h := newHarness(t)
	h.opts.Drivers = []string{"pgx", "sqlite"}
	h.build(t)
	page := body(t, h.get(t, "/sources/new?kind=sql"))
	a11ytest.AssertPage(t, page)
	if !strings.Contains(page, `<option value="pgx">pgx</option>`) || strings.Contains(page, "holds no database driver") {
		t.Error("a build with drivers must list them")
	}
	empty := body(t, h.post(t, pages.NewPath+"/sql", url.Values{"name": {"Registry"}, "query": {"SELECT 1"}}))
	if !strings.Contains(empty, "Type the name of the driver.") || !strings.Contains(empty, "Type the name of an environment variable") {
		t.Error("a form without a driver and a secret must say so")
	}
}

func TestUploadWithoutASaverKeepsADataURL(t *testing.T) {
	h := newHarness(t)
	h.opts.SaveCSV = nil
	h.build(t)
	if rec := h.upload(t, map[string]string{"name": "Farmers", "delimiter": "semicolon", "header": "no"}, "a;b\nc;d\n"); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	list, err := h.svc.List(as(session), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	csv := list.Msg.GetSources()[0].GetCsv()
	if !strings.HasPrefix(csv.GetFileRef(), reader.DataPrefix) || csv.GetDelimiter() != ";" || csv.GetHasHeader() {
		t.Errorf("csv = %v", csv)
	}
	if rec := h.upload(t, map[string]string{"name": "Empty"}, "  \n"); !strings.Contains(rec.Body.String(), "Pick a CSV file") {
		t.Error("an empty file must fail")
	}
	r := h.post(t, pages.NewPath+"/csv", url.Values{"name": {"No file"}})
	if r.Code != http.StatusBadRequest {
		t.Errorf("a form that is not multipart: %d", r.Code)
	}
}

func TestTheServiceRefusesABadSource(t *testing.T) {
	h := newHarness(t)
	page := body(t, h.post(t, pages.NewPath+"/http", url.Values{"name": {"Registry"}, "url": {"https://registry.agriculture.go.ke/x"}, "method": {"PUT"}}))
	if !strings.Contains(page, "The service refused the source.") {
		t.Error("a source the service refuses must say so")
	}
}

func TestSourceThatCannotBeReadSaysSo(t *testing.T) {
	h := newHarness(t)
	id := h.addHTTP(t)
	page := body(t, h.get(t, "/sources/"+id+"?schema=farmer%402"))
	a11ytest.AssertPage(t, page)
	if !strings.Contains(page, "VCA cannot read the source now.") || !strings.Contains(page, `aria-current="step"`) {
		t.Error("an unreadable source must say so")
	}
	if mapPage := body(t, h.get(t, "/sources/"+id+"/map?schema=farmer%402")); !strings.Contains(mapPage, "VCA cannot read the source now.") {
		t.Error("the map of an unreadable source must say so")
	}
	if _, err := h.svc.SetFieldMap(as(session), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: &datasourcev1.FieldMap{
		SourceId: id, SchemaId: "farmer", SchemaVersion: 2, Rules: []*datasourcev1.FieldMap_Rule{{Property: "fullName", SourceFields: []string{"name"}}},
	}})); err != nil {
		t.Fatal(err)
	}
	page = body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_PDF"}}))
	if !strings.Contains(page, "VCA cannot read the source now.") || !strings.Contains(page, "Unknown now") {
		t.Error("a run of an unreadable source must say so")
	}
}

func TestARegistryThatFailsFailsThePage(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	h.opts.Schemas = brokenSchemas{}
	h.build(t)
	for _, path := range []string{"/sources/?schema=farmer%402", "/sources/new?schema=farmer%402", "/sources/" + id + "?schema=farmer%402", "/sources/" + id + "/map"} {
		if rec := h.get(t, path); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
	if rec := h.post(t, "/sources/"+id+"/map", url.Values{"schema": {"farmer@2"}}); rec.Code != http.StatusInternalServerError {
		t.Errorf("save: status %d", rec.Code)
	}
	h.opts.Schemas = nil
	h.build(t)
	page := body(t, h.get(t, "/sources/"+id+"/map"))
	if !strings.Contains(page, "The schema registry has no published schema.") {
		t.Error("a pair without a registry must say so")
	}
	if rec := h.post(t, "/sources/"+id+"/map", url.Values{"schema": {"farmer@2"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a map without a schema: %d", rec.Code)
	}
}

func TestMapOfASchemaWithoutJsonSchema(t *testing.T) {
	h := newHarness(t)
	h.schemas.published = append(h.schemas.published, &schemav1.Schema{Id: "land", Version: 1, Type: "LandTitle"},
		&schemav1.Schema{Id: "bad", Version: 1, JsonSchema: "{"})
	id := h.addFarmers(t)
	page := body(t, h.get(t, "/sources/"+id+"/map?schema=land%401"))
	if !strings.Contains(page, "This schema holds no JSON Schema") || !strings.Contains(page, "LandTitle") {
		t.Error("a schema without JSON Schema must say so")
	}
	if rec := h.get(t, "/sources/"+id+"/map?schema=bad%401"); rec.Code != http.StatusBadRequest {
		t.Errorf("a broken JSON Schema: %d", rec.Code)
	}
	if rec := h.post(t, "/sources/"+id+"/map", url.Values{"schema": {"land@1"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("an empty map: %d %s", rec.Code, rec.Body.String())
	}
	page = body(t, h.get(t, "/sources/"+id+"/run?schema=land%401"))
	if !strings.Contains(page, "0 of 0.") {
		t.Error("the run must count the claims")
	}
	if rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"land@1"}, "channel": {"CHANNEL_PDF"}}); rec.Code != http.StatusSeeOther {
		t.Errorf("a run without a JSON Schema: %d %s", rec.Code, rec.Body.String())
	}
	h.wait(t)
	if got := h.issuance.requests[0].GetItems()[0].GetSubjectData(); got != "{}" {
		t.Errorf("subject data = %s", got)
	}
	for _, path := range []string{"/sources/nope/map?schema=farmer%402", "/sources/nope/run?schema=farmer%402"} {
		if rec := h.get(t, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if rec := h.post(t, "/sources/nope/map", mapForm()); rec.Code != http.StatusNotFound {
		t.Errorf("save the map of an unknown source: %d", rec.Code)
	}
}

func TestAnEmptySourceHasNothingToRun(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.Create(as(session), connect.NewRequest(&datasourcev1.CreateRequest{Source: &datasourcev1.Source{
		DisplayName: "Empty", Access: &datasourcev1.Source_Access{Issue: []string{"issuer-operator"}, ViewFields: []string{"issuer-operator"}, PreviewRows: []string{"issuer-operator"}},
		Kind: &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: reader.DataPrefix + encode([]byte("Full Name\n")), HasHeader: true}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	id := res.Msg.GetSource().GetId()
	if rec := h.post(t, "/sources/"+id+"/map", url.Values{"schema": {"farmer@2"}, "field.fullName": {"Full Name"},
		"transform.farmerID": {"constant"}, "value.farmerID": {"FM"}, "transform.hectares": {"constant"}, "value.hectares": {"1"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("map: %d %s", rec.Code, rec.Body.String())
	}
	page := body(t, h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_PDF"}}))
	if !strings.Contains(page, "The source holds no row") {
		t.Error("an empty source must say so")
	}
}

func TestAPairTheProbeDoesNotSee(t *testing.T) {
	h := newHarness(t)
	h.snap = topology.Snapshot{}
	h.build(t)
	id := h.mapFarmers(t)
	page := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	if strings.Contains(page, "CHANNEL_OID4VCI_PREAUTH") || !strings.Contains(page, "CHANNEL_PDF") || !strings.Contains(page, "this stack") {
		t.Error("without the probe the run offers the document channel of VCA only")
	}
}

func TestProgressNamesOtherFormatsAndOddJobs(t *testing.T) {
	h := newHarness(t)
	h.schemas.published[0].Formats = append(h.schemas.published[0].Formats, commonv1.Format_FORMAT_LDP_VC_BBS)
	h.snap.Peers[0].Capabilities.Formats = append(h.snap.Peers[0].Capabilities.Formats, commonv1.Format_FORMAT_LDP_VC_BBS)
	h.schemas.published[0].Display = nil
	id := h.mapFarmers(t)
	page := body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	if !strings.Contains(page, ">ldp_vc_bbs<") || !strings.Contains(page, "FarmerRegistration") {
		t.Error("the run must name every format and fall back to the schema type")
	}
	h.schemas.published[0].Type = ""
	page = body(t, h.get(t, "/sources/"+id+"/run?schema=farmer%402"))
	if !strings.Contains(page, "farmer, version 2.") {
		t.Error("a schema without a name or a type shows its id")
	}
	h.issuance.progress = &issuancev1.IssueBatchResponse{Done: true}
	rec := h.get(t, "/sources/"+id+"/runs/job-7/offers.csv")
	if rec.Header().Get("Content-Disposition") != `attachment; filename="offers-job-7.csv"` {
		t.Errorf("disposition = %q", rec.Header().Get("Content-Disposition"))
	}
	if rec := h.get(t, "/sources/"+id+"/runs/job%3B8/offers.csv"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown job: %d", rec.Code)
	}
	if rec := h.get(t, "/sources/"+id+"/runs/job-9/progress"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown job: %d", rec.Code)
	}
	h.opts.Issuance = nil
	h.build(t)
	if rec := h.get(t, "/sources/"+id+"/runs/job-7"); rec.Code != http.StatusNotFound {
		t.Errorf("no issuance service: %d", rec.Code)
	}
	if rec := h.post(t, "/sources/"+id+"/run", url.Values{"schema": {"farmer@2"}, "channel": {"CHANNEL_PDF"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a run without the issuance service: %d", rec.Code)
	}
	if rec := h.get(t, "/sources/nope/runs/job-7"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown source: %d", rec.Code)
	}
}

func TestProgressWithoutASchemaInTheQuery(t *testing.T) {
	h := newHarness(t)
	id := h.addFarmers(t)
	h.issuance.progress = &issuancev1.IssueBatchResponse{Total: 1, Processed: 1, Accepted: 1, Done: true}
	h.issuance.rows = []*issuancev1.BatchRow{{Row: 1, Label: "Wanjiku Njeri", Offer: &issuancev1.Offer{}}}
	h.issuance.next = "50"
	page := body(t, h.get(t, "/sources/"+id+"/runs/job-7"))
	if !strings.Contains(page, "The rows of Farmers of Kiambu 2026 become credentials.") || !strings.Contains(page, "No offer.") ||
		!strings.Contains(page, `href="/sources/`+id+`/runs/job-7?page=50"`) {
		t.Error("the progress page without a schema must still name the source")
	}
}
