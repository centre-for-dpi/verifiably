// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/delivery"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

// fixedTime is the clock of the tests.
var fixedTime = time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

// farmerSchema is the published schema of the tests.
func farmerSchema() *schemav1.Schema {
	return &schemav1.Schema{
		Id:      "farmer",
		Version: 3,
		Type:    "https://issuer.example.org/credentials/FarmerCredential",
		JsonSchema: `{"type":"object","properties":{
          "fullName":{"type":"string"},"farmerID":{"type":"string"}},
          "required":["fullName","farmerID"]}`,
		Formats:          []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT},
		SdClaims:         []string{"fullName", "farmerID"},
		SearchableClaims: []string{"farmerID"},
		Display:          []*schemav1.Display{{Locale: "en", Name: "Farmer Credential"}},
	}
}

// harness holds the service under test and its fakes.
type harness struct {
	service  *service.Service
	adapter  *fakeAdapter
	schemas  *fakeSchemas
	status   *fakeStatus
	recorder *fakeRecorder
	rows     *fakeRows
	sent     *[]delivery.Message
	store    *offers.Store
	rpc      issuancev1connect.IssuanceServiceClient
}

// newHarness wires the service with fakes.
func newHarness(t *testing.T, change func(*service.Options, *harness)) *harness {
	t.Helper()
	adapter := &fakeAdapter{
		capabilities: allChannels(),
		offer: &backendv1.CreateOfferResponse{
			OfferUri: "openid-credential-offer://issuer.example.org?credential_offer_uri=https%3A%2F%2Fx",
			OfferId:  "adapter-offer-1",
			Pin:      "4821",
		},
		credential: &backendv1.IssueResponse{
			Credential: &commonv1.Credential{
				Format:  commonv1.Format_FORMAT_LDP_VC,
				Payload: []byte(`{"type":["VerifiableCredential","FarmerCredential"],"credentialSubject":{"fullName":"Ada Lovelace"}}`),
			},
		},
	}
	sent := &[]delivery.Message{}
	h := &harness{
		adapter:  adapter,
		schemas:  &fakeSchemas{schema: farmerSchema()},
		status:   &fakeStatus{answer: &statusv1.AllocateIndexResponse{ListId: "list-1", Index: 12, Url: "https://status.example.org/token/1"}},
		recorder: &fakeRecorder{},
		rows:     &fakeRows{},
	}
	h.sent = sent
	kv := store.Memory()
	h.store = offers.New(kv, func() time.Time { return fixedTime })
	ids := 0
	recorder := delivery.SenderFunc(func(_ context.Context, m delivery.Message) error {
		if err := m.Validate(); err != nil {
			return err
		}
		*sent = append(*sent, m)
		return nil
	})
	opts := service.Options{
		Capabilities: clients.NewCapabilityCache(adapter, time.Minute, func() time.Time { return fixedTime }),
		Issuer:       adapter,
		Schemas:      h.schemas,
		Status:       h.status,
		Recorder:     h.recorder,
		Rows:         h.rows,
		Delivery: delivery.NewRegistry(map[delivery.Channel]delivery.Sender{
			delivery.ChannelOID4VCI: recorder,
			delivery.ChannelPDF:     recorder,
			delivery.ChannelLink:    recorder,
			delivery.ChannelEmail:   recorder,
			delivery.ChannelSMS:     delivery.SMS(),
		}),
		Store:          h.store,
		AdapterName:    "dpg-adapter-test",
		PublicURL:      "https://issuance.example.org",
		DocumentIssuer: "Ministry of Agriculture",
		OfferTTL:       2 * time.Hour,
		PageSizeMax:    2,
		Now:            func() time.Time { return fixedTime },
		NewID: func() string {
			ids++
			return fmt.Sprintf("id-%d", ids)
		},
	}
	if change != nil {
		change(&opts, h)
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	h.service = svc
	return h
}

// wantCode fails when err does not carry the Connect code.
func wantCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("the call returned no error, want the code %v", code)
	}
	if got := connect.CodeOf(err); got != code {
		t.Fatalf("code = %v, want %v: %v", got, code, err)
	}
}

// issue issues one credential over the channel.
func (h *harness) issue(t *testing.T, channel backendv1.Channel, change func(*issuancev1.IssueRequest)) *issuancev1.Offer {
	t.Helper()
	req := &issuancev1.IssueRequest{
		SchemaId:      "farmer",
		SubjectData:   `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Subject:       &commonv1.Subject{Ref: "ref-1"},
		Delivery:      &issuancev1.Delivery{Channel: channel},
		StatusPurpose: "revocation",
	}
	if change != nil {
		change(req)
	}
	resp, err := h.service.Issue(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return resp.Msg.GetOffer()
}

func TestNewChecksItsInput(t *testing.T) {
	full := func() service.Options {
		adapter := &fakeAdapter{capabilities: allChannels()}
		return service.Options{
			Capabilities: clients.NewCapabilityCache(adapter, time.Minute, nil),
			Issuer:       adapter,
			Recorder:     &fakeRecorder{},
			Store:        offers.New(store.Memory(), nil),
			Delivery:     delivery.NewRegistry(nil),
		}
	}
	cases := map[string]func(*service.Options){
		"capabilities": func(o *service.Options) { o.Capabilities = nil },
		"issuer":       func(o *service.Options) { o.Issuer = nil },
		"store":        func(o *service.Options) { o.Store = nil },
		"delivery":     func(o *service.Options) { o.Delivery = nil },
		"recorder":     func(o *service.Options) { o.Recorder = nil },
	}
	for name, drop := range cases {
		opts := full()
		drop(&opts)
		if _, err := service.New(opts); err == nil {
			t.Fatalf("New accepted a missing %s", name)
		}
	}
	svc, err := service.New(full())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !svc.Ready() {
		t.Fatal("the service is not ready")
	}
}

func TestIssueOverTheWalletChannel(t *testing.T) {
	h := newHarness(t, nil)
	offer := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if offer.GetState() != issuancev1.Offer_STATE_PENDING {
		t.Fatalf("state = %v", offer.GetState())
	}
	if !strings.HasPrefix(offer.GetOfferUri(), "openid-credential-offer://") {
		t.Fatalf("offer URI = %q", offer.GetOfferUri())
	}
	if offer.GetPin() != "4821" {
		t.Fatalf("pin = %q", offer.GetPin())
	}
	if offer.GetRecordId() != "record-1" {
		t.Fatalf("record id = %q", offer.GetRecordId())
	}
	if offer.GetCreatedAt() == nil || offer.GetExpiresAt() == nil {
		t.Fatal("the times are missing")
	}
	spec := h.adapter.lastSpec()
	if spec.GetConfigurationId() != "https://issuer.example.org/credentials/FarmerCredential" {
		t.Fatalf("configuration = %q", spec.GetConfigurationId())
	}
	if spec.GetFormat() != commonv1.Format_FORMAT_VC_SD_JWT {
		t.Fatalf("format = %v, the schema names it", spec.GetFormat())
	}
	if spec.GetStatus().GetKind() != backendv1.StatusListBinding_KIND_TOKEN {
		t.Fatalf("an SD-JWT uses the IETF token status list, got %v", spec.GetStatus().GetKind())
	}
	if spec.GetStatus().GetIndex() != 12 {
		t.Fatalf("status index = %d", spec.GetStatus().GetIndex())
	}
	record := h.recorder.last()
	if record.GetDpg() != "dpg-adapter-test" || record.GetSchemaVersion() != 3 {
		t.Fatalf("record = %v", record)
	}
	if record.GetSubject().GetRef() != "ref-1" {
		t.Fatalf("the record must carry the subject reference, got %v", record.GetSubject())
	}
	if len(record.GetSearchableClaims()) != 1 || record.GetSearchableClaims()["farmerID"] != "FM-0001" {
		t.Fatalf("the record keeps the searchable claims only, got %v", record.GetSearchableClaims())
	}
	if record.GetHash() == "" {
		t.Fatal("the record has no hash")
	}
	if len(*h.sent) != 0 {
		t.Fatal("the wallet channel sends no message")
	}
}

func TestIssueOverTheEmailChannel(t *testing.T) {
	h := newHarness(t, nil)
	offer := h.issue(t, backendv1.Channel_CHANNEL_EMAIL, func(r *issuancev1.IssueRequest) {
		r.Delivery.Email = "ada@example.org"
		r.Delivery.Locale = "en"
	})
	if offer.GetState() != issuancev1.Offer_STATE_DELIVERED {
		t.Fatalf("state = %v", offer.GetState())
	}
	if len(*h.sent) != 1 {
		t.Fatalf("messages = %d", len(*h.sent))
	}
	message := (*h.sent)[0]
	if message.Channel != delivery.ChannelEmail || message.Address != "ada@example.org" {
		t.Fatalf("message = %+v", message)
	}
	if !strings.Contains(message.Body, "4821") {
		t.Fatalf("the message %q does not carry the transaction code", message.Body)
	}
	// The adapter still builds a pre-authorized offer for an email.
	if h.adapter.channels[0] != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH {
		t.Fatalf("channel = %v", h.adapter.channels[0])
	}
}

func TestIssueOverTheSmsChannelReportsTheMissingGateway(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Delivery: &issuancev1.Delivery{
			Channel: backendv1.Channel_CHANNEL_SMS, Phone: "+254700000000",
		},
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !errors.Is(err, delivery.ErrNotConfigured) {
		t.Fatalf("error = %v, want ErrNotConfigured", err)
	}
}

func TestIssueOverTheEmailChannelNeedsAnAddress(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_EMAIL},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestIssueOverTheDocumentChannel(t *testing.T) {
	h := newHarness(t, nil)
	offer := h.issue(t, backendv1.Channel_CHANNEL_PDF, nil)
	if offer.GetState() != issuancev1.Offer_STATE_DELIVERED {
		t.Fatalf("state = %v", offer.GetState())
	}
	if offer.GetPdfRef() == "" {
		t.Fatal("the offer has no document reference")
	}
	if !strings.HasPrefix(offer.GetLink(), "https://issuance.example.org/issuance/pdf/") {
		t.Fatalf("link = %q", offer.GetLink())
	}
	if offer.GetCredential().GetFormat() != commonv1.Format_FORMAT_LDP_VC {
		t.Fatalf("format = %v", offer.GetCredential().GetFormat())
	}
	document, ok := h.service.Document(context.Background(), offer.GetPdfRef())
	if !ok {
		t.Fatal("the document is missing")
	}
	if !bytes.HasPrefix(document, []byte("%PDF-1.4")) {
		t.Fatalf("the document is not a PDF: %q", document[:8])
	}
	if !bytes.Contains(document, []byte("/XObject")) {
		t.Fatal("the document carries no QR image")
	}
	if _, ok := h.service.Document(context.Background(), "does-not-exist"); ok {
		t.Fatal("an unknown reference must not resolve")
	}
}

func TestIssueOverTheLinkChannelSendsTheLink(t *testing.T) {
	h := newHarness(t, nil)
	offer := h.issue(t, backendv1.Channel_CHANNEL_LINK, nil)
	if offer.GetLink() == "" {
		t.Fatal("the offer has no link")
	}
	if len(*h.sent) != 1 {
		t.Fatalf("messages = %d", len(*h.sent))
	}
	if (*h.sent)[0].Channel != delivery.ChannelLink {
		t.Fatalf("channel = %s", (*h.sent)[0].Channel)
	}
	if len((*h.sent)[0].Attachment) == 0 {
		t.Fatal("the message carries no document")
	}
}

func TestIssueChecksTheClaimsAgainstTheSchema(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada Lovelace"}`,
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "farmerID") {
		t.Fatalf("the error %q does not name the missing claim", err)
	}
}

func TestIssueChecksItsInput(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	cases := []*issuancev1.IssueRequest{
		{SchemaId: "farmer"},
		{SchemaId: "farmer", SubjectData: "not json"},
		{SchemaId: "farmer", SubjectData: "{}"},
		{SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`},
		{
			SchemaId: "farmer", SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
			StatusPurpose: "unknown",
		},
		{
			SchemaId: "farmer", SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
			Format: commonv1.Format_FORMAT_MSO_MDOC,
		},
		{
			SchemaId: "farmer", SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
			Delivery: &issuancev1.Delivery{Channel: backendv1.Channel(99)},
		},
	}
	for i, req := range cases {
		if _, err := h.service.Issue(ctx, connect.NewRequest(req)); err == nil {
			t.Fatalf("case %d was accepted", i)
		} else {
			wantCode(t, err, connect.CodeInvalidArgument)
		}
	}
}

func TestIssueRefusesAChannelTheAdapterLacks(t *testing.T) {
	h := newHarness(t, func(o *service.Options, h *harness) {
		h.adapter.capabilities = &backendv1.GetCapabilitiesResponse{
			Formats:  []commonv1.Format{commonv1.Format_FORMAT_VC_SD_JWT},
			Channels: []backendv1.Channel{backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
		}
	})
	ctx := context.Background()
	_, err := h.service.Issue(ctx, connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_PDF},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = h.service.Issue(ctx, connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestIssueReportsAFailureOfEveryService(t *testing.T) {
	failure := connect.NewError(connect.CodeUnavailable, errors.New("down"))
	cases := map[string]func(*harness){
		"capabilities": func(h *harness) { h.adapter.capabilityErr = failure },
		"schema":       func(h *harness) { h.schemas.err = failure },
		"status":       func(h *harness) { h.status.err = failure },
		"adapter":      func(h *harness) { h.adapter.offerErr = failure },
	}
	for name, breakIt := range cases {
		h := newHarness(t, nil)
		breakIt(h)
		_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
			SchemaId:    "farmer",
			SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
			Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
		}))
		if err == nil {
			t.Fatalf("the failure of the %s service was accepted", name)
		}
		wantCode(t, err, connect.CodeUnavailable)
	}
}

func TestIssueContinuesWhenTheRecordFails(t *testing.T) {
	h := newHarness(t, nil)
	h.recorder.err = errors.New("the log is full")
	offer := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if offer.GetRecordId() != "" {
		t.Fatalf("record id = %q", offer.GetRecordId())
	}
	if offer.GetOfferUri() == "" {
		t.Fatal("the citizen must still get the offer")
	}
}

func TestIssueWithoutASchemaRegistryOrAStatusService(t *testing.T) {
	h := newHarness(t, func(o *service.Options, _ *harness) {
		o.Schemas = nil
		o.Status = nil
	})
	offer := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if offer.GetOfferUri() == "" {
		t.Fatal("the offer is missing")
	}
	if spec := h.adapter.lastSpec(); spec.GetStatus() != nil {
		t.Fatal("without a status service the credential is not revocable")
	}
}

func TestIssueWithTheStatusPurposeNone(t *testing.T) {
	h := newHarness(t, nil)
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, func(r *issuancev1.IssueRequest) {
		r.StatusPurpose = "none"
	})
	if spec := h.adapter.lastSpec(); spec.GetStatus() != nil {
		t.Fatal("the purpose none makes the credential not revocable")
	}
	if len(h.status.requests) != 0 {
		t.Fatal("the purpose none allocates no index")
	}
}

func TestIssueUsesTheBitstringListForAW3cFormat(t *testing.T) {
	h := newHarness(t, nil)
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, func(r *issuancev1.IssueRequest) {
		r.Format = commonv1.Format_FORMAT_LDP_VC
	})
	if got := h.status.requests[0].GetKind(); got != statusv1.Kind_KIND_BITSTRING {
		t.Fatalf("kind = %v", got)
	}
	if spec := h.adapter.lastSpec(); spec.GetStatus().GetKind() != backendv1.StatusListBinding_KIND_BITSTRING {
		t.Fatalf("binding = %v", spec.GetStatus().GetKind())
	}
}

func TestIssueReadsTheStatusPurpose(t *testing.T) {
	for name, want := range map[string]statusv1.Purpose{
		"":           statusv1.Purpose_PURPOSE_REVOCATION,
		"revocation": statusv1.Purpose_PURPOSE_REVOCATION,
		"suspension": statusv1.Purpose_PURPOSE_SUSPENSION,
		"message":    statusv1.Purpose_PURPOSE_MESSAGE,
	} {
		h := newHarness(t, nil)
		h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, func(r *issuancev1.IssueRequest) {
			r.StatusPurpose = name
		})
		if got := h.status.requests[0].GetPurpose(); got != want {
			t.Fatalf("the purpose %q gave %v, want %v", name, got, want)
		}
	}
}

func TestGetOfferReturnsTheStoredOffer(t *testing.T) {
	h := newHarness(t, nil)
	created := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	resp, err := h.service.GetOffer(context.Background(),
		connect.NewRequest(&issuancev1.GetOfferRequest{Id: created.GetId()}))
	if err != nil {
		t.Fatalf("GetOffer: %v", err)
	}
	if resp.Msg.GetOffer().GetOfferUri() != created.GetOfferUri() {
		t.Fatalf("offer = %v", resp.Msg.GetOffer())
	}
}

func TestGetOfferChecksItsInput(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.service.GetOffer(context.Background(),
		connect.NewRequest(&issuancev1.GetOfferRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = h.service.GetOffer(context.Background(),
		connect.NewRequest(&issuancev1.GetOfferRequest{Id: "does-not-exist"}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestIssueOverTheSmsChannelWithAWorkingGateway(t *testing.T) {
	h := newHarness(t, func(o *service.Options, h *harness) {
		sender := delivery.SenderFunc(func(_ context.Context, m delivery.Message) error {
			if err := m.Validate(); err != nil {
				return err
			}
			*h.sent = append(*h.sent, m)
			return nil
		})
		o.Delivery = delivery.NewRegistry(map[delivery.Channel]delivery.Sender{
			delivery.ChannelSMS: sender,
		})
	})
	offer := h.issue(t, backendv1.Channel_CHANNEL_SMS, func(r *issuancev1.IssueRequest) {
		r.Delivery.Phone = "+254700000000"
	})
	if offer.GetState() != issuancev1.Offer_STATE_DELIVERED {
		t.Fatalf("state = %v", offer.GetState())
	}
	if len(*h.sent) != 1 || (*h.sent)[0].Address != "+254700000000" {
		t.Fatalf("messages = %v", *h.sent)
	}
}

func TestIssueOverTheDocumentChannelReportsAFailedAdapter(t *testing.T) {
	h := newHarness(t, nil)
	h.adapter.issueErr = connect.NewError(connect.CodeUnimplemented, errors.New("no credential"))
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_PDF},
	}))
	wantCode(t, err, connect.CodeUnimplemented)
}

func TestIssueOverTheDocumentChannelReportsAFailedDelivery(t *testing.T) {
	h := newHarness(t, func(o *service.Options, _ *harness) {
		o.Delivery = delivery.NewRegistry(map[delivery.Channel]delivery.Sender{
			delivery.ChannelLink: delivery.SenderFunc(func(context.Context, delivery.Message) error {
				return errors.New("the disk is full")
			}),
		})
	})
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
		Delivery:    &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_LINK},
	}))
	wantCode(t, err, connect.CodeInternal)
}

func TestIssueWithoutAPublicUrlGivesNoLink(t *testing.T) {
	h := newHarness(t, func(o *service.Options, _ *harness) { o.PublicURL = "" })
	offer := h.issue(t, backendv1.Channel_CHANNEL_PDF, nil)
	if offer.GetLink() != "" {
		t.Fatalf("link = %q", offer.GetLink())
	}
}

func TestIssueUsesTheDisplayNameOfTheSchemaInTheDocument(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema.Display = nil
	offer := h.issue(t, backendv1.Channel_CHANNEL_PDF, nil)
	document, ok := h.service.Document(context.Background(), offer.GetPdfRef())
	if !ok {
		t.Fatal("the document is missing")
	}
	if !bytes.Contains(document, []byte("/Title (")) {
		t.Fatal("the document has no title")
	}
}

func TestIssueReportsASchemaTheRegistryDoesNotHave(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema = nil
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
	}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestIssueReportsABrokenJsonSchema(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema.JsonSchema = "{"
	_, err := h.service.Issue(context.Background(), connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId:    "farmer",
		SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`,
	}))
	wantCode(t, err, connect.CodeInternal)
}

func TestIssueUsesTheSchemaIdWhenTheSchemaNamesNoType(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema.Type = ""
	h.schemas.schema.Display = nil
	h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	if got := h.adapter.lastSpec().GetConfigurationId(); got != "farmer" {
		t.Fatalf("configuration = %q", got)
	}
}

func TestTheLabelOfARowFallsBackToTheFirstClaim(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema.JsonSchema = ""
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer",
		Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"zeta":"last","alpha":"first"}`},
		},
	})
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	jobID := sent[0].GetJobId()
	page, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: jobID,
	}))
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if page.Msg.GetRows()[0].GetLabel() != "first" {
		t.Fatalf("label = %q, the first claim name wins", page.Msg.GetRows()[0].GetLabel())
	}
}

func TestTheLabelOfAnEmptyRow(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema.JsonSchema = ""
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer",
		Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"zeta":""}`},
		},
	})
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	page, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: sent[0].GetJobId(),
	}))
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if page.Msg.GetRows()[0].GetLabel() != "(empty row)" {
		t.Fatalf("label = %q", page.Msg.GetRows()[0].GetLabel())
	}
}
