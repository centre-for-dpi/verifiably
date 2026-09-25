// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// stackName is the name the adapter of the pair reports. The tests hold
// no vendor name (ADR-001 decision 4).
const stackName = "First stack"

// farmers is the CSV file of the tests. The third row holds a number the
// schema cannot take.
const farmers = "Full Name,Farmer ID,Date of birth,Hectares,Organic,Crops,County\n" +
	"Wanjiku Njeri,FM-0042,12/03/1984,12,true,tea;maize,Kiambu\n" +
	"Otieno Ouma,FM-0043,01/07/1979,8,false,coffee,Nyeri\n" +
	"Amina Hassan,FM-0044,23/11/1990,twelve,true,maize,Kiambu\n"

// farmerSchema is the published schema of the tests.
func farmerSchema() *schemav1.Schema {
	return &schemav1.Schema{
		Id: "farmer", Version: 2, Type: "FarmerRegistration", State: schemav1.State_STATE_PUBLISHED,
		Formats: []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_JWT_VC_JSON},
		Display: []*schemav1.Display{{Name: "Farmer registration", Locale: "en"}},
		JsonSchema: `{"type":"object","properties":{
		  "fullName":{"type":"string","title":"Full name"},
		  "farmerID":{"type":"string"},
		  "dateOfBirth":{"type":"string","format":"date"},
		  "hectares":{"type":"integer","minimum":0},
		  "organic":{"type":"boolean"},
		  "crops":{"type":"array","items":{"type":"string"}},
		  "address":{"type":"object","properties":{"county":{"type":"string"}}}},
		  "required":["fullName","farmerID","hectares"]}`,
	}
}

// fakeSchemas answers as the schema registry.
type fakeSchemas struct {
	published []*schemav1.Schema
}

func (f *fakeSchemas) List(context.Context, *connect.Request[schemav1.ListRequest]) (*connect.Response[schemav1.ListResponse], error) {
	return connect.NewResponse(&schemav1.ListResponse{Schemas: f.published}), nil
}

func (f *fakeSchemas) Get(_ context.Context, req *connect.Request[schemav1.GetRequest]) (*connect.Response[schemav1.GetResponse], error) {
	for _, s := range f.published {
		if s.GetId() == req.Msg.GetId() && (req.Msg.GetVersion() == 0 || req.Msg.GetVersion() == s.GetVersion()) {
			return connect.NewResponse(&schemav1.GetResponse{Schema: s}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no schema"))
}

// fakeIssuance stands in for the IssuanceService of the pair. It records
// each batch with its actor header, and answers GetBatch from the rows
// the test sets.
type fakeIssuance struct {
	issuancev1connect.UnimplementedIssuanceServiceHandler
	mu       sync.Mutex
	requests []*issuancev1.IssueBatchRequest
	actors   []string
	done     chan struct{}
	// startErr fails IssueBatch before the first message.
	startErr error
	// progress, rows and failed answer GetBatch.
	progress *issuancev1.IssueBatchResponse
	rows     []*issuancev1.BatchRow
	next     string
}

func (f *fakeIssuance) IssueBatch(_ context.Context, req *connect.Request[issuancev1.IssueBatchRequest], stream *connect.ServerStream[issuancev1.IssueBatchResponse]) error {
	f.mu.Lock()
	f.requests = append(f.requests, req.Msg)
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	f.mu.Unlock()
	defer close(f.done)
	if f.startErr != nil {
		return f.startErr
	}
	total := int64(len(req.Msg.GetItems()))
	if err := stream.Send(&issuancev1.IssueBatchResponse{JobId: "job-7", Total: total}); err != nil {
		return err
	}
	return stream.Send(&issuancev1.IssueBatchResponse{JobId: "job-7", Total: total, Processed: total, Accepted: total, Done: true})
}

func (f *fakeIssuance) GetBatch(_ context.Context, req *connect.Request[issuancev1.GetBatchRequest]) (*connect.Response[issuancev1.GetBatchResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, req.Header().Get(auditlog.ActorHeader))
	if req.Msg.GetJobId() != "job-7" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no job"))
	}
	out := &issuancev1.GetBatchResponse{Progress: f.progress, Page: &commonv1.PageResult{}}
	for _, r := range f.rows {
		if !req.Msg.GetFailedOnly() || r.GetError() != nil {
			out.Rows = append(out.Rows, r)
		}
	}
	if !req.Msg.GetFailedOnly() && req.Msg.GetPage().GetPageToken() == "" {
		out.Page.NextPageToken = f.next
	}
	if req.Msg.GetPage().GetPageToken() != "" {
		out.Rows = []*issuancev1.BatchRow{{Row: 51, Label: "Later row", Offer: &issuancev1.Offer{Id: "offer-51"}}}
	}
	return connect.NewResponse(out), nil
}

// issuerCaps is the answer of the adapter of the pair.
func issuerCaps(features ...backendv1.Feature) *backendv1.GetCapabilitiesResponse {
	return &backendv1.GetCapabilitiesResponse{
		Adapter: "dpg-adapter", Roles: []commonv1.Role{commonv1.Role_ROLE_ISSUER},
		Formats:  []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_JWT_VC_JSON},
		Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
		Features: features, DpgInfo: &backendv1.DpgInfo{DisplayName: stackName},
	}
}

// harness holds the pages of one test, over a real service with a
// memory store.
type harness struct {
	svc      *service.Service
	schemas  *fakeSchemas
	issuance *fakeIssuance
	sess     staffsession.Session
	opts     pages.Options
	snap     topology.Snapshot
	peers    []topology.Peer
	mux      *http.ServeMux
	saved    [][]byte
}

// session is the staff member of every request: an issuer operator.
var session = staffsession.Session{Subject: "kc|wanjiru", Name: "Wanjiru Kamau", ID: "sid-1", CSRF: "csrf-1",
	Roles: []string{staffsession.IssuerOperatorRole}}

// viewer is an issuer viewer: it sees the field names and changes nothing.
var viewer = staffsession.Session{Subject: "kc|viewer", Name: "Otieno Viewer", ID: "sid-2", CSRF: "csrf-2", Roles: []string{"issuer-viewer"}}

// newHarness builds the pages of the first issuer pair.
func newHarness(t *testing.T, features ...backendv1.Feature) *harness {
	t.Helper()
	st, err := store.Open(sharedstore.MemoryDoc())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st, Reader: reader.Reader{}, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{svc: svc, schemas: &fakeSchemas{published: []*schemav1.Schema{farmerSchema()}},
		issuance: &fakeIssuance{done: make(chan struct{})}, sess: session}
	_, handler := issuancev1connect.NewIssuanceServiceHandler(h.issuance)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	pair := topology.PairName(commonv1.Role_ROLE_ISSUER, configv1.Dpg_DPG_WALTID)
	own := topology.Peer{Pair: pair, Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://" + pair + ".labs.example",
		Services: map[string]string{"issuer-auth": "http://" + pair + "-auth:8081", "data-source": "http://data-source:8083"}}
	h.peers = []topology.Peer{own}
	h.snap = topology.Snapshot{Peers: []topology.Status{{Peer: own, State: topology.Live, Capabilities: issuerCaps(features...)}}}
	h.opts = pages.Options{
		Sources: svc, Schemas: h.schemas, Issuance: issuancev1connect.NewIssuanceServiceClient(srv.Client(), srv.URL),
		AllowHosts: []string{"registry.agriculture.go.ke", ".coop.example"}, UploadMaxBytes: 4096,
		SaveCSV: func(data []byte) (string, error) {
			h.saved = append(h.saved, data)
			return reader.DataPrefix + encode(data), nil
		},
	}
	h.build(t)
	return h
}

// build makes the pages from the options and the snapshot of h.
func (h *harness) build(t *testing.T) {
	t.Helper()
	kit, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	h.opts.Kit = kit
	h.opts.Shell = staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_ISSUER, Peers: h.peers,
		Snapshot: func(context.Context) topology.Snapshot { return h.snap },
		JWKSURL:  h.peers[0].Auth() + staffshell.JWKSPath, SignOut: pages.SignOutPath,
	})
	p, err := pages.New(h.opts)
	if err != nil {
		t.Fatal(err)
	}
	h.mux = http.NewServeMux()
	p.Register(h.mux)
}

// fixedNow is the clock of the service.
var fixedNow = time.Date(2026, 9, 25, 9, 30, 0, 0, time.UTC)

func (h *harness) do(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	r = r.WithContext(staffsession.With(r.Context(), h.sess))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec
}

// get answers one GET as a signed in staff member.
func (h *harness) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, httptest.NewRequest(http.MethodGet, path, nil))
}

// post answers one form POST as a signed in staff member.
func (h *harness) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(t, r)
}

// upload posts a CSV file with the fields of the form.
func (h *harness) upload(t *testing.T, fields map[string]string, file string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	part, err := w.CreateFormFile("file", "farmers.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(file)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, pages.NewPath+"/csv", &body)
	r.Header.Set("Content-Type", w.FormDataContentType())
	return h.do(t, r)
}

// body returns the body of a 200 answer.
func body(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// as returns a context with the principal of the session, as the pages
// call the service.
func as(s staffsession.Session) context.Context {
	return authz.WithPrincipal(context.Background(), authz.FromSession(s))
}

// addFarmers adds the CSV source of the tests through the service and
// returns its id.
func (h *harness) addFarmers(t *testing.T) string {
	t.Helper()
	res, err := h.svc.Create(as(session), connect.NewRequest(&datasourcev1.CreateRequest{Source: &datasourcev1.Source{
		DisplayName: "Farmers of Kiambu 2026",
		Access:      &datasourcev1.Source_Access{ViewFields: []string{"issuer-viewer", staffsession.IssuerOperatorRole}, PreviewRows: []string{staffsession.IssuerOperatorRole}, Issue: []string{staffsession.IssuerOperatorRole}},
		Kind:        &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: reader.DataPrefix + encode([]byte(farmers)), HasHeader: true}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.GetSource().GetId()
}

// mapForm is the field map form of the tests: every claim of the farmer
// schema from its column.
func mapForm() url.Values {
	return url.Values{
		"schema":                {"farmer@2"},
		"field.fullName":        {"Full Name"},
		"transform.fullName":    {"trim"},
		"field.farmerID":        {"Farmer ID"},
		"transform.farmerID":    {"upper"},
		"field.dateOfBirth":     {"Date of birth"},
		"transform.dateOfBirth": {"date_dmy"},
		"field.hectares":        {"Hectares"},
		"field.organic":         {"Organic"},
		"field.crops":           {"Crops"},
		"field.address.county":  {"County"},
	}
}

// mapFarmers saves the field map of the tests and returns the source id.
func (h *harness) mapFarmers(t *testing.T) string {
	t.Helper()
	id := h.addFarmers(t)
	rec := h.post(t, "/sources/"+id+"/map", mapForm())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save the map: status %d %s", rec.Code, rec.Body.String())
	}
	return id
}

// wait blocks until the fake issuance service ended its stream.
func (h *harness) wait(t *testing.T) {
	t.Helper()
	select {
	case <-h.issuance.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the run never reached the issuance service")
	}
}

// runRows are the rows of a run with one failed row.
func runRows() []*issuancev1.BatchRow {
	return []*issuancev1.BatchRow{
		{Row: 1, Label: "Wanjiku Njeri", Offer: &issuancev1.Offer{Id: "offer-1", OfferUri: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2F1", Pin: "493817"}},
		{Row: 2, Label: "Otieno Ouma", Offer: &issuancev1.Offer{Id: "offer-2", OfferUri: "=HYPERLINK(\"x\")", Link: "https://issuer.example/issuance/pdf/d2"}},
		{Row: 3, Label: "Amina Hassan", Error: &commonv1.Error{Code: "VCA-ISSUANCE-ROW", Message: "the claims do not match the schema: /hectares: the value must have type integer"}},
	}
}

// encode returns the base64 text of data.
func encode(data []byte) string { return base64.StdEncoding.EncodeToString(data) }
