// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

const testdata = "../../testdata"

// newService starts the fake and returns the service under test.
func newService(t *testing.T, change func(*service.Options)) (*service.Service, *fake.Server) {
	t.Helper()
	f := fake.New(testdata)
	t.Cleanup(f.Close)
	client := credebl.New(credebl.Options{
		HTTP: dpgclient.New(dpgclient.Options{
			BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {},
		}),
		Account:  credebl.Account{Email: "admin@example.org", Password: "secret", CryptoKey: "key"},
		OrgID:    "org-1",
		IssuerID: "issuer-1",
	})
	opts := service.Options{
		Client:      client,
		Store:       store.Memory(),
		DpgVersion:  "2.x",
		PublicURL:   "https://credebl.example.org",
		InternalURL: "http://credebl-agent:8001",
		DefaultPin:  "0000",
		PageSizeMax: 1,
		Now:         func() time.Time { return time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC) },
	}
	if change != nil {
		change(&opts)
	}
	svc, err := service.New(opts)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	return svc, f
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

func TestNewChecksItsInput(t *testing.T) {
	if _, err := service.New(service.Options{Store: store.Memory()}); err == nil {
		t.Fatal("New accepted a missing client")
	}
	client := credebl.New(credebl.Options{HTTP: dpgclient.New(dpgclient.Options{BaseURL: "http://x"})})
	if _, err := service.New(service.Options{Client: client}); err == nil {
		t.Fatal("New accepted a missing store")
	}
	svc, err := service.New(service.Options{Client: client, Store: store.Memory()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !svc.Ready() {
		t.Fatal("the service is not ready")
	}
}

func TestGetCapabilitiesReportsTheDcqlSupport(t *testing.T) {
	svc, _ := newService(t, nil)
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	msg := resp.Msg
	if msg.GetAdapter() != service.AdapterName || msg.GetDpgVersion() != "2.x" {
		t.Fatalf("adapter %q version %q", msg.GetAdapter(), msg.GetDpgVersion())
	}
	if !hasProtocol(msg.GetProtocols(), backendv1.Protocol_PROTOCOL_OID4VP_DCQL) {
		t.Fatal("CREDEBL reads DCQL, which the answer must list")
	}
	if len(msg.GetChannels()) != 1 ||
		msg.GetChannels()[0] != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH {
		t.Fatalf("channels = %v", msg.GetChannels())
	}
	if len(msg.GetRoles()) != 2 {
		t.Fatalf("roles = %v", msg.GetRoles())
	}
}

func hasProtocol(list []backendv1.Protocol, want backendv1.Protocol) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

func TestTheHolderRoleIsNotAvailable(t *testing.T) {
	svc, _ := newService(t, nil)
	ctx := context.Background()
	calls := []func() error{
		func() error {
			_, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{}))
			return err
		},
		func() error {
			_, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{}))
			return err
		},
		func() error {
			_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{}))
			return err
		},
		func() error {
			_, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{}))
			return err
		},
		func() error {
			_, err := svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{}))
			return err
		},
	}
	for i, call := range calls {
		err := call()
		wantCode(t, err, connect.CodeUnimplemented)
		if !strings.Contains(err.Error(), "wallet") {
			t.Fatalf("call %d: the message %q does not say why", i, err)
		}
	}
}

func TestTheRpcsCredeblNeverSupportsAnswerUnimplemented(t *testing.T) {
	svc, _ := newService(t, nil)
	ctx := context.Background()
	_, err := svc.Issue(ctx, connect.NewRequest(&backendv1.IssueRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.GetIssuanceStatus(ctx, connect.NewRequest(&backendv1.GetIssuanceStatusRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.Revoke(ctx, connect.NewRequest(&backendv1.RevokeRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
}

// farmerSchema is the JSON Schema of the recorded template.
const farmerSchema = `{"type":"object","properties":{
  "fullName":{"type":"string"},"farmerID":{"type":"string"},"hectares":{"type":"number"}}}`

func TestRegisterCredentialConfigurationStoresTheSchemaAndTheTemplate(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{
				Id:         "NewCredential",
				Format:     commonv1.Format_FORMAT_DC_SD_JWT,
				Type:       "https://credebl.example.org/credentials/NewCredential",
				JsonSchema: farmerSchema,
				SdClaims:   []string{"fullName"},
			},
		}))
	if err != nil {
		t.Fatalf("RegisterCredentialConfiguration: %v", err)
	}
	if resp.Msg.GetId() != "d4e8a1f7-3b62-4c95-8d07-1f5a9e2b6c30" {
		t.Fatalf("id = %q, want the template identifier", resp.Msg.GetId())
	}
	var template map[string]any
	if err := f.RequestJSON("/v1/orgs/org-1/oid4vc/issuer-1/template", &template); err != nil {
		t.Fatalf("read the template request: %v", err)
	}
	if template["format"] != "dc+sd-jwt" || template["signerOption"] != "DID" {
		t.Fatalf("template = %v", template)
	}
	body := mustAs[map[string]any](t, template["template"])
	if body["vct"] != "https://credebl.example.org/credentials/NewCredential" {
		t.Fatalf("template body = %v", body)
	}
	attributes := mustAs[[]any](t, body["attributes"])
	if len(attributes) != 3 {
		t.Fatalf("attributes = %v", attributes)
	}
	first := mustAs[map[string]any](t, attributes[0])
	if first["key"] != "farmerID" {
		t.Fatalf("the attributes must come in a stable order, got %v", attributes)
	}
	var schema map[string]any
	if err := f.RequestJSON("/v1/orgs/org-1/schemas", &schema); err != nil {
		t.Fatalf("read the schema request: %v", err)
	}
	if schema["type"] != "json" {
		t.Fatalf("schema = %v", schema)
	}
}

func TestRegisterCredentialConfigurationKeepsAnExistingTemplate(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{
				Id:         "FarmerCredential",
				Format:     commonv1.Format_FORMAT_DC_SD_JWT,
				JsonSchema: farmerSchema,
			},
		}))
	if err != nil {
		t.Fatalf("RegisterCredentialConfiguration: %v", err)
	}
	if resp.Msg.GetId() != "8e5a2c41-9f37-4c0b-b1ad-72d9e6c85f13" {
		t.Fatalf("id = %q, want the template that already exists", resp.Msg.GetId())
	}
	if f.Request("/v1/orgs/org-1/schemas") != nil {
		t.Fatal("an existing template must store no schema again")
	}
}

func TestRegisterCredentialConfigurationChecksItsInput(t *testing.T) {
	svc, _ := newService(t, nil)
	ctx := context.Background()
	cases := []*backendv1.CredentialConfiguration{
		nil,
		{Id: "x", Format: commonv1.Format_FORMAT_MSO_MDOC, JsonSchema: farmerSchema},
		{Id: "x", Format: commonv1.Format_FORMAT_DC_SD_JWT},
		{Id: "x", Format: commonv1.Format_FORMAT_DC_SD_JWT, JsonSchema: "{"},
		{Id: "x", Format: commonv1.Format_FORMAT_DC_SD_JWT, JsonSchema: `{"type":"object"}`},
	}
	for i, cfg := range cases {
		_, err := svc.RegisterCredentialConfiguration(ctx,
			connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{Configuration: cfg}))
		wantCode(t, err, connect.CodeInvalidArgument)
		_ = i
	}
}

func TestRegisterCredentialConfigurationReportsAFailure(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/template", http.StatusBadGateway)
	_, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{
				Id: "NewCredential", Format: commonv1.Format_FORMAT_DC_SD_JWT, JsonSchema: farmerSchema,
			},
		}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestRegisterCredentialConfigurationReportsAFailedSchemaAndTemplate(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/schemas", http.StatusBadRequest)
	request := connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
		Configuration: &backendv1.CredentialConfiguration{
			Id: "NewCredential", Format: commonv1.Format_FORMAT_DC_SD_JWT, JsonSchema: farmerSchema,
		},
	})
	_, err := svc.RegisterCredentialConfiguration(context.Background(), request)
	wantCode(t, err, connect.CodeInvalidArgument)
	// The first call is the listing, the second is the template write.
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/template", 0, http.StatusBadRequest)
	_, err = svc.RegisterCredentialConfiguration(context.Background(), request)
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateOfferRewritesTheOfferOntoThePublicHost(t *testing.T) {
	svc, f := newService(t, nil)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "FarmerCredential",
			SubjectData:     `{"fullName":"Ada Lovelace","farmerID":"FM-0001","hectares":4}`,
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if strings.Contains(resp.Msg.GetOfferUri(), "credebl-agent") {
		t.Fatalf("offer URI = %q, a wallet cannot reach the internal host", resp.Msg.GetOfferUri())
	}
	if !strings.Contains(resp.Msg.GetOfferUri(), "credebl.example.org") {
		t.Fatalf("offer URI = %q", resp.Msg.GetOfferUri())
	}
	if resp.Msg.GetPin() != "8143" {
		t.Fatalf("pin = %q", resp.Msg.GetPin())
	}
	if resp.Msg.GetChannel() != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH {
		t.Fatalf("channel = %v", resp.Msg.GetChannel())
	}
	var body map[string]any
	if err := f.RequestJSON("/v1/orgs/org-1/oid4vc/issuer-1/create-offer", &body); err != nil {
		t.Fatalf("read the offer request: %v", err)
	}
	credentials := mustAs[[]any](t, body["credentials"])
	first := mustAs[map[string]any](t, credentials[0])
	if first["templateId"] != "8e5a2c41-9f37-4c0b-b1ad-72d9e6c85f13" {
		t.Fatalf("the offer must name the template identifier, got %v", first)
	}
}

func TestCreateOfferRefusesAValidityWindow(t *testing.T) {
	svc, _ := newService(t, nil)
	_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "FarmerCredential",
			SubjectData:     `{"fullName":"Ada"}`,
			Validity: &commonv1.ValidityWindow{
				ValidUntil: timestamppb.New(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "validity window") {
		t.Fatalf("the error %q must name the reason", err)
	}
}

func TestCreateOfferChecksItsInput(t *testing.T) {
	svc, _ := newService(t, nil)
	ctx := context.Background()
	_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "x"}, Channel: backendv1.Channel_CHANNEL_PDF,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "x", SubjectData: "not json"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "x"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "Unknown", SubjectData: `{"a":"b"}`},
	}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestCreateOfferReportsAFailure(t *testing.T) {
	svc, f := newService(t, nil)
	request := connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential", SubjectData: `{"fullName":"Ada"}`},
	})
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/create-offer", http.StatusBadGateway)
	_, err := svc.CreateOffer(context.Background(), request)
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/template", http.StatusBadGateway)
	_, err = svc.CreateOffer(context.Background(), request)
	wantCode(t, err, connect.CodeUnavailable)
}

func TestGetIssuerMetadataBuildsTheDocument(t *testing.T) {
	svc, _ := newService(t, nil)
	resp, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	if resp.Msg.GetIssuer() != "https://credebl.example.org" {
		t.Fatalf("issuer = %q", resp.Msg.GetIssuer())
	}
	if len(resp.Msg.GetConfigurations()) != 2 {
		t.Fatalf("configurations = %d", len(resp.Msg.GetConfigurations()))
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(resp.Msg.GetMetadataJson()), &document); err != nil {
		t.Fatalf("the metadata is not JSON: %v", err)
	}
	entries := mustAs[map[string]any](t, document["credential_configurations_supported"])
	if len(entries) != 2 {
		t.Fatalf("entries = %v", entries)
	}
	entry := mustAs[map[string]any](t, entries["8e5a2c41-9f37-4c0b-b1ad-72d9e6c85f13"])
	if entry["format"] != "dc+sd-jwt" || entry["vct"] == nil || entry["claims"] == nil {
		t.Fatalf("entry = %v", entry)
	}
}

func TestGetIssuerMetadataUsesTheGatewayWithoutAPublicUrl(t *testing.T) {
	svc, f := newService(t, func(o *service.Options) { o.PublicURL = "" })
	resp, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	if resp.Msg.GetIssuer() != f.URL() {
		t.Fatalf("issuer = %q", resp.Msg.GetIssuer())
	}
}

func TestGetIssuerMetadataReportsAFailure(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/template", http.StatusNotFound)
	_, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestListCredentialTypesPagesTheTemplates(t *testing.T) {
	svc, _ := newService(t, nil)
	ctx := context.Background()
	first, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if len(first.Msg.GetConfigurations()) != 1 || first.Msg.GetPage().GetNextPageToken() != "1" {
		t.Fatalf("page = %v", first.Msg)
	}
	last, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{
		Page: &commonv1.Pagination{PageToken: "1"},
	}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if last.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatal("the last page has a next token")
	}
	past, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{
		Page: &commonv1.Pagination{PageToken: "9"},
	}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if len(past.Msg.GetConfigurations()) != 0 {
		t.Fatal("a token past the end returns no entry")
	}
}

func TestListCredentialTypesReportsAFailure(t *testing.T) {
	svc, f := newService(t, nil)
	f.SetStatus("/v1/orgs/org-1/oid4vc/issuer-1/template", http.StatusBadGateway)
	_, err := svc.ListCredentialTypes(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestRecordedAnswersAreValidJson(t *testing.T) {
	entries, err := os.ReadDir(testdata)
	if err != nil {
		t.Fatalf("read the testdata directory: %v", err)
	}
	count := 0
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(testdata, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if !json.Valid(raw) {
			t.Fatalf("%s is not valid JSON", e.Name())
		}
		count++
	}
	if count < 10 {
		t.Fatalf("the recorded answers are %d, want at least 10", count)
	}
}
