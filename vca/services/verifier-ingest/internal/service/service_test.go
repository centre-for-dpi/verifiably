// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// clock is the fixed time of the tests.
var clock = time.Unix(1700000000, 0).UTC()

// query is a small DCQL query.
const query = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://a.example/pid"]}}]}`

// sdjwtSample is an SD-JWT VC with one disclosure.
const sdjwtSample = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQifQ.c2ln~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFzaGEiXQ~"

// fakeDiscovery answers one template.
type fakeDiscovery struct {
	discoveryv1connect.UnimplementedDiscoveryServiceHandler
	dcql string
	err  error
}

func (f fakeDiscovery) GetTemplate(context.Context, *connect.Request[discoveryv1.GetTemplateRequest]) (*connect.Response[discoveryv1.GetTemplateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&discoveryv1.GetTemplateResponse{Template: &discoveryv1.PresentationTemplate{
		Id: "age-check", Version: 3, Dcql: f.dcql,
	}}), nil
}

// build wires a service over a memory store.
func build(t *testing.T, opts service.Options) (*service.Service, *txn.Store) {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	opts.Store = store
	if opts.SigningKey == nil {
		opts.SigningKey = key
	}
	if opts.BaseURL == "" {
		opts.BaseURL = "https://verify.example"
	}
	if opts.ClientID == "" {
		opts.ClientID = "https://verify.example"
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return clock }
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func TestNewRejectsMissingParts(t *testing.T) {
	if _, err := service.New(service.Options{}); err == nil {
		t.Error("a service needs a store")
	}
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.New(service.Options{Store: store}); err == nil {
		t.Error("a service needs a signing key")
	}
}

func TestIngestCarriers(t *testing.T) {
	svc, _ := build(t, service.Options{})
	ctx := context.Background()
	resp, err := svc.Ingest(ctx, connect.NewRequest(&ingestv1.IngestRequest{
		Payload: []byte(sdjwtSample), Carrier: ingestv1.Carrier_CARRIER_JSON,
	}))
	if err != nil {
		t.Fatal(err)
	}
	p := resp.Msg.GetPresentation()
	if p.GetCarrier() != ingestv1.Carrier_CARRIER_JSON || p.GetFormat() != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Errorf("presentation = %+v", p)
	}
	if p.GetDetectedType() != ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL || len(p.GetCredentials()) != 1 {
		t.Errorf("presentation = %+v", p)
	}
	if p.GetRef() == "" || p.GetInputHash() == "" || p.GetReceivedAt() == nil {
		t.Errorf("presentation = %+v", p)
	}
	if len(resp.Msg.GetSteps()) == 0 {
		t.Error("the answer names the decoder steps")
	}
	if _, err := svc.Ingest(ctx, connect.NewRequest(&ingestv1.IngestRequest{})); err == nil {
		t.Error("an empty payload wants an error")
	}
}

func TestIngestXML(t *testing.T) {
	svc, _ := build(t, service.Options{XML: ingest.XMLConfig{Path: "root.vc"}})
	ctx := context.Background()
	doc := "<root><vc>" + sdjwtSample + "</vc></root>"
	resp, err := svc.Ingest(ctx, connect.NewRequest(&ingestv1.IngestRequest{Payload: []byte(doc)}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetPresentation().GetCarrier() != ingestv1.Carrier_CARRIER_XML {
		t.Errorf("carrier = %v", resp.Msg.GetPresentation().GetCarrier())
	}
	other := "<envelope><body>" + sdjwtSample + "</body></envelope>"
	resp, err = svc.Ingest(ctx, connect.NewRequest(&ingestv1.IngestRequest{
		Payload: []byte(other),
		Xml:     &ingestv1.XmlConfig{Xpath: "envelope.body", Encoding: ingestv1.XmlConfig_ENCODING_TEXT},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetPresentation().GetFormat() != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Errorf("the request configuration wins, got %+v", resp.Msg.GetPresentation())
	}
	base64Doc := "<root><vc>ZXlKaGJHY2lPaUpGVXpJMU5pSjkuZTMwLmMybG4=</vc></root>"
	if _, err := svc.Ingest(ctx, connect.NewRequest(&ingestv1.IngestRequest{
		Payload: []byte(base64Doc),
		Xml:     &ingestv1.XmlConfig{Xpath: "root.vc", Encoding: ingestv1.XmlConfig_ENCODING_BASE64},
	})); err != nil {
		t.Fatalf("a base64 credential must decode: %v", err)
	}
}

func TestIngestResolvesRequestURI(t *testing.T) {
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	object := oid4vp.Request{
		ClientID: "https://wallet.example", ResponseURI: "https://wallet.example/r",
		ResponseMode: oid4vp.ResponseModeDirectPost, Nonce: "n9", State: "s9", DCQL: query,
		IssuedAt: clock, ExpiresAt: clock.Add(time.Minute),
	}
	token, err := object.Sign(key, "k")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte(token))
	}))
	defer server.Close()
	svc, _ := build(t, service.Options{Fetcher: oid4vp.Fetcher{
		Allow: oid4vp.Allowlist{Hosts: []string{"127.0.0.1"}, AllowPlainHTTP: true},
	}})
	request := "openid4vp://authorize?client_id=x&request_uri=" + urlEscape(server.URL)
	resp, err := svc.Ingest(context.Background(), connect.NewRequest(&ingestv1.IngestRequest{Payload: []byte(request)}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Msg.GetPresentation().GetPayload()), `"nonce":"n9"`) {
		t.Errorf("the answer carries the request object claims, got %s", resp.Msg.GetPresentation().GetPayload())
	}
	if !strings.Contains(strings.Join(resp.Msg.GetSteps(), ","), "request_uri") {
		t.Errorf("steps = %v", resp.Msg.GetSteps())
	}
}

// urlEscape escapes one query value.
func urlEscape(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, ":", "%3A"), "/", "%2F")
}

func TestIngestKeepsRequestWhenFetchFails(t *testing.T) {
	svc, _ := build(t, service.Options{})
	request := "openid4vp://authorize?client_id=x&request_uri=https%3A%2F%2Fevil.example%2Fr"
	resp, err := svc.Ingest(context.Background(), connect.NewRequest(&ingestv1.IngestRequest{Payload: []byte(request)}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Msg.GetPresentation().GetPayload()), "request_uri") {
		t.Errorf("the parameters stay, got %s", resp.Msg.GetPresentation().GetPayload())
	}
	if strings.Contains(strings.Join(resp.Msg.GetSteps(), ","), "request_uri") {
		t.Error("a refused fetch adds no step")
	}
	// A request without a request URI needs no fetch.
	plain := "openid4vp://authorize?client_id=x&nonce=n1"
	if _, err := svc.Ingest(context.Background(), connect.NewRequest(&ingestv1.IngestRequest{Payload: []byte(plain)})); err != nil {
		t.Fatal(err)
	}
}

func TestIngestResolveRejectsBadObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("not a token"))
	}))
	defer server.Close()
	svc, _ := build(t, service.Options{Fetcher: oid4vp.Fetcher{
		Allow: oid4vp.Allowlist{Hosts: []string{"127.0.0.1"}, AllowPlainHTTP: true},
	}})
	request := "openid4vp://authorize?client_id=x&request_uri=" + urlEscape(server.URL)
	resp, err := svc.Ingest(context.Background(), connect.NewRequest(&ingestv1.IngestRequest{Payload: []byte(request)}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(resp.Msg.GetSteps(), ","), "jwt") {
		t.Error("a request object that does not parse adds no step")
	}
}

func TestCreateRequestFromQuery(t *testing.T) {
	svc, store := build(t, service.Options{RequestTTL: time.Minute})
	ctx := context.Background()
	resp, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetTransactionId() == "" || resp.Msg.GetNonce() == "" {
		t.Fatalf("response = %+v", resp.Msg)
	}
	if !strings.HasPrefix(resp.Msg.GetRequestUri(), "https://verify.example"+service.RequestPath) {
		t.Errorf("request uri = %q", resp.Msg.GetRequestUri())
	}
	if !strings.HasPrefix(resp.Msg.GetQrPayload(), "openid4vp://authorize?") {
		t.Errorf("qr payload = %q", resp.Msg.GetQrPayload())
	}
	if resp.Msg.GetExpiresAt().AsTime() != clock.Add(time.Minute) {
		t.Errorf("expires at = %v", resp.Msg.GetExpiresAt().AsTime())
	}
	record, err := store.Get(ctx, resp.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if record.State != txn.StatePending || record.ResponseMode != oid4vp.ResponseModeDirectPost {
		t.Errorf("transaction = %+v", record)
	}
	token, err := svc.RequestObject(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oid4vp.ReadRequestObject(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["nonce"] != record.Nonce || claims["state"] != record.StateParam {
		t.Errorf("claims = %v", claims)
	}
	if claims["response_uri"] != "https://verify.example"+service.ResponsePath {
		t.Errorf("response uri = %v", claims["response_uri"])
	}
}

func TestCreateRequestFromTemplate(t *testing.T) {
	svc, store := build(t, service.Options{Discovery: fakeDiscovery{dcql: query}})
	ctx := context.Background()
	resp, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "age-check", ResponseMode: "direct_post.jwt",
	}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, resp.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if record.TemplateVersion != 3 || record.ResponseMode != oid4vp.ResponseModeDirectPostJWT {
		t.Errorf("transaction = %+v", record)
	}
}

func TestCreateRequestRejects(t *testing.T) {
	ctx := context.Background()
	svc, _ := build(t, service.Options{})
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		ResponseMode: "fragment", Dcql: query,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bad response mode wants invalid argument, got %v", err)
	}
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		Dcql: "{",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a broken query wants invalid argument, got %v", err)
	}
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a request with no query and no template wants invalid argument, got %v", err)
	}
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "age-check",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a template without a discovery service wants failed precondition, got %v", err)
	}
	broken, _ := build(t, service.Options{Discovery: fakeDiscovery{err: errors.New("down")}})
	if _, err := broken.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{
		TemplateId: "age-check",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a discovery error wants failed precondition, got %v", err)
	}
}

func TestRequestObjectErrors(t *testing.T) {
	ctx := context.Background()
	now := clock
	svc, store := build(t, service.Options{RequestTTL: time.Minute, Now: func() time.Time { return now }})
	resp, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestObject(ctx, "missing"); !errors.Is(err, txn.ErrNotFound) {
		t.Errorf("a missing transaction wants ErrNotFound, got %v", err)
	}
	now = clock.Add(2 * time.Minute)
	if _, err := svc.RequestObject(ctx, resp.Msg.GetTransactionId()); !errors.Is(err, txn.ErrNotFound) {
		t.Errorf("an expired request wants ErrNotFound, got %v", err)
	}
	if _, err := store.Get(ctx, resp.Msg.GetTransactionId()); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveDirectPost(t *testing.T) {
	ctx := context.Background()
	svc, store := build(t, service.Options{RequestTTL: time.Minute, RedirectURI: "https://verify.example/done"})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, created.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: record.StateParam, VpToken: sdjwtSample,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetRedirectUri() != "https://verify.example/done" {
		t.Errorf("redirect = %q", resp.Msg.GetRedirectUri())
	}
	p := resp.Msg.GetPresentation()
	if p.GetTransactionId() != record.ID || p.GetNonce() != record.Nonce {
		t.Errorf("presentation = %+v", p)
	}
	if len(p.GetCredentials()) != 1 {
		t.Errorf("presentation = %+v", p)
	}
	state, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: record.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetState() != ingestv1.GetTransactionResponse_STATE_RECEIVED {
		t.Errorf("state = %v", state.Msg.GetState())
	}
	if state.Msg.GetPresentation() == nil {
		t.Error("the answer carries the presentation")
	}
}

func TestReceiveDirectPostRefusedAndErrors(t *testing.T) {
	ctx := context.Background()
	now := clock
	svc, store := build(t, service.Options{RequestTTL: time.Minute, Now: func() time.Time { return now }})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, created.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: "unknown", VpToken: sdjwtSample,
	})); connect.CodeOf(serr) != connect.CodeNotFound {
		t.Errorf("an unknown state wants not found, got %v", serr)
	}
	if _, serr := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: record.StateParam,
	})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Errorf("an answer without a token wants invalid argument, got %v", serr)
	}
	if _, serr := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: record.StateParam, VpToken: " ",
	})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Errorf("a blank token wants invalid argument, got %v", serr)
	}
	refused, err := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: record.StateParam, Error: "access_denied",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if refused.Msg.GetPresentation() != nil {
		t.Error("a refusal carries no presentation")
	}
	state, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: record.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetState() != ingestv1.GetTransactionResponse_STATE_REFUSED {
		t.Errorf("state = %v", state.Msg.GetState())
	}
	// A second request that expires before the answer.
	second, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, err := store.Get(ctx, second.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	now = clock.Add(2 * time.Minute)
	if _, serr := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: secondRecord.StateParam, VpToken: sdjwtSample,
	})); connect.CodeOf(serr) != connect.CodeDeadlineExceeded {
		t.Errorf("an expired request wants deadline exceeded, got %v", serr)
	}
	expired, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{
		TransactionId: secondRecord.ID,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if expired.Msg.GetState() != ingestv1.GetTransactionResponse_STATE_EXPIRED {
		t.Errorf("state = %v", expired.Msg.GetState())
	}
}

func TestReceiveDirectPostUsesResponseJWT(t *testing.T) {
	ctx := context.Background()
	svc, store := build(t, service.Options{RequestTTL: time.Minute})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query}))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, created.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: record.StateParam, ResponseJwt: sdjwtSample,
	})); err != nil {
		t.Fatalf("the response member is the fallback: %v", err)
	}
}

func TestGetTransactionNotFound(t *testing.T) {
	svc, _ := build(t, service.Options{})
	if _, err := svc.GetTransaction(context.Background(), connect.NewRequest(&ingestv1.GetTransactionRequest{
		TransactionId: "missing",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Error("a missing transaction wants not found")
	}
}

func TestReadyAndStore(t *testing.T) {
	svc, store := build(t, service.Options{})
	if !svc.Ready() || svc.Store() != store {
		t.Error("the service is ready and exposes its store")
	}
}

func TestConversions(t *testing.T) {
	carriers := map[ingestv1.Carrier]ingest.Carrier{
		ingestv1.Carrier_CARRIER_OID4VP_RESPONSE: ingest.CarrierOID4VPResponse,
		ingestv1.Carrier_CARRIER_OID4VP_REQUEST:  ingest.CarrierOID4VPRequest,
		ingestv1.Carrier_CARRIER_IMAGE:           ingest.CarrierImage,
		ingestv1.Carrier_CARRIER_PDF:             ingest.CarrierPDF,
		ingestv1.Carrier_CARRIER_XML:             ingest.CarrierXML,
		ingestv1.Carrier_CARRIER_JSON:            ingest.CarrierJSON,
		ingestv1.Carrier_CARRIER_QR:              ingest.CarrierQR,
		ingestv1.Carrier_CARRIER_QR_CLAIM169:     ingest.CarrierClaim169,
		ingestv1.Carrier_CARRIER_UNSPECIFIED:     ingest.CarrierUnknown,
	}
	for in, want := range carriers {
		if got := service.CarrierOf(in); got != want {
			t.Errorf("CarrierOf(%v) = %q", in, got)
		}
		if want != ingest.CarrierUnknown {
			if got := service.ProtoCarrier(want); got != in {
				t.Errorf("ProtoCarrier(%q) = %v", want, got)
			}
		}
	}
	if service.CarrierOf(ingestv1.Carrier_CARRIER_OID4VP) != ingest.CarrierOID4VPResponse { //nolint:staticcheck // the deprecated value stays readable
		t.Error("the deprecated value still reads as an OID4VP response")
	}
	if service.ProtoCarrier("tape") != ingestv1.Carrier_CARRIER_UNSPECIFIED {
		t.Error("an unknown carrier is unspecified")
	}
	detected := map[ingest.DetectedType]ingestv1.DetectedType{
		ingest.TypeCredential:   ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL,
		ingest.TypePresentation: ingestv1.DetectedType_DETECTED_TYPE_PRESENTATION,
		ingest.TypeRequest:      ingestv1.DetectedType_DETECTED_TYPE_PRESENTATION,
		ingest.TypeCWTClaim169:  ingestv1.DetectedType_DETECTED_TYPE_CWT_CLAIM169,
		ingest.TypePixelPass:    ingestv1.DetectedType_DETECTED_TYPE_PIXELPASS,
		ingest.TypeUnknown:      ingestv1.DetectedType_DETECTED_TYPE_UNKNOWN,
	}
	for in, want := range detected {
		if got := service.ProtoDetected(in); got != want {
			t.Errorf("ProtoDetected(%q) = %v", in, got)
		}
	}
	formats := []string{"vc+sd-jwt", "dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc"}
	for _, name := range formats {
		if service.ProtoFormat(name) == commonv1.Format_FORMAT_UNSPECIFIED {
			t.Errorf("ProtoFormat(%q) is unspecified", name)
		}
	}
	if service.ProtoFormat("bogus") != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Error("an unknown format is unspecified")
	}
	if service.RecordToProto(nil, "x") != nil {
		t.Error("no record gives no message")
	}
}

func TestFormatName(t *testing.T) {
	cases := map[vc.Format]string{
		vc.FormatSDJWT:  "dc+sd-jwt",
		vc.FormatJWT:    "jwt_vc_json",
		vc.FormatJSONLD: "ldp_vc",
		vc.FormatMdoc:   "mso_mdoc",
		vc.FormatJSON:   "json",
	}
	for format, want := range cases {
		if got := service.FormatName(format); got != want {
			t.Errorf("FormatName(%q) = %q", format, got)
		}
	}
	if service.FormatName(vc.FormatUnknown) != "" {
		t.Error("an empty format has no name")
	}
}

func TestRecordWritesJSON(t *testing.T) {
	record := service.ToRecord(ingest.Result{
		Carrier: ingest.CarrierQR, Detected: ingest.TypeCredential,
		Credentials: []ingest.Credential{{Payload: []byte("x")}},
	}, "ref", "nonce", clock)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"ref":"ref"`) {
		t.Errorf("record = %s", data)
	}
}
