// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

const testdata = "../../testdata"

// fixedTime is the clock of the tests.
var fixedTime = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

// roles says which Inji services the test wires.
type roles struct {
	certify bool
	verify  bool
}

// both wires the issuer and the verifier.
var both = roles{certify: true, verify: true}

// serviceOptions are the options a test can change.
type serviceOptions = service.Options

// newService starts the fake and returns the service under test.
func newService(t *testing.T, r roles) (*service.Service, *fake.Server) {
	t.Helper()
	return newServiceWith(t, r, nil)
}

// newServiceWith starts the fake and returns the service under test with
// the options that change sets.
func newServiceWith(t *testing.T, r roles, change func(*serviceOptions)) (*service.Service, *fake.Server) {
	t.Helper()
	f := fake.New(testdata)
	t.Cleanup(f.Close)
	client := func(on bool) *dpgclient.Client {
		if !on {
			return nil
		}
		return dpgclient.New(dpgclient.Options{
			BaseURL: f.URL(), HTTP: f.Client(), Retries: -1, Sleep: func(time.Duration) {},
		})
	}
	ids := 0
	opts := service.Options{
		Certify:    inji.NewCertify(client(r.certify), ""),
		Verify:     inji.NewVerify(client(r.verify), "did:web:verify.example:v1:verify", f.URL()),
		Store:      store.Memory(),
		DpgVersion: "0.14.0",
		Versions: map[string]string{
			"certify": "0.14.0", "esignet": "1.5.1", "mock-identity": "0.10.1",
			"verify-service": "0.16.0", "verify-ui": "0.16.0", "keycloak": "25.0",
		},
		PublicURL:           "https://adapter.example",
		AuthorizationServer: "https://esignet.example/v1/esignet",
		OfferTTL:            15 * time.Minute,
		PageSizeMax:         1,
		Now:                 func() time.Time { return fixedTime },
		NewID: func() string {
			ids++
			return "id-" + string(rune('0'+ids))
		},
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
	if _, err := service.New(service.Options{}); err == nil {
		t.Fatal("New accepted a missing store")
	}
	if _, err := service.New(service.Options{Store: store.Memory()}); err == nil {
		t.Fatal("New accepted a service without a role")
	}
}

func TestNewFillsTheDefaults(t *testing.T) {
	svc, err := service.New(service.Options{
		Store: store.Memory(),
		Verify: inji.NewVerify(dpgclient.New(dpgclient.Options{BaseURL: "http://v.example"}),
			"did:x", ""),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !svc.Ready() {
		t.Fatal("the service is not ready")
	}
}

func TestGetCapabilitiesListsEveryWiredRole(t *testing.T) {
	svc, _ := newService(t, both)
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	msg := resp.Msg
	if msg.GetAdapter() != service.AdapterName || msg.GetDpgVersion() != "0.14.0" {
		t.Fatalf("adapter %q version %q", msg.GetAdapter(), msg.GetDpgVersion())
	}
	if len(msg.GetRoles()) != 2 {
		t.Fatalf("roles = %v", msg.GetRoles())
	}
	if !hasChannel(msg.GetChannels(), backendv1.Channel_CHANNEL_PDF) {
		t.Fatal("the adapter runs the whole flow itself, so the document channel works")
	}
	if !hasChannel(msg.GetChannels(), backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE) {
		t.Fatal("an identity provider turns the authorization code channel on")
	}
	if !hasFormat(msg.GetFormats(), commonv1.Format_FORMAT_LDP_VC) {
		t.Fatal("Inji Certify issues JSON-LD credentials")
	}
}

func TestGetCapabilitiesOfAVerifierOnlyDeployment(t *testing.T) {
	svc, _ := newService(t, roles{verify: true})
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	if len(resp.Msg.GetRoles()) != 1 || len(resp.Msg.GetChannels()) != 0 {
		t.Fatalf("answer = %v", resp.Msg)
	}
}

func hasChannel(list []backendv1.Channel, want backendv1.Channel) bool {
	for _, c := range list {
		if c == want {
			return true
		}
	}
	return false
}

func hasFormat(list []commonv1.Format, want commonv1.Format) bool {
	for _, f := range list {
		if f == want {
			return true
		}
	}
	return false
}

func TestTheHolderRoleIsNotAvailable(t *testing.T) {
	svc, _ := newService(t, both)
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

func TestTheRpcsInjiNeverSupportsAnswerUnimplemented(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	_, err := svc.GetIssuanceStatus(ctx, connect.NewRequest(&backendv1.GetIssuanceStatusRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
}

func TestEveryIssuerCallNeedsTheIssuerUrl(t *testing.T) {
	svc, _ := newService(t, roles{verify: true})
	ctx := context.Background()
	_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.Issue(ctx, connect.NewRequest(&backendv1.IssueRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.GetIssuerMetadata(ctx, connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
}

func TestEveryVerifierCallNeedsTheVerifierUrl(t *testing.T) {
	svc, _ := newService(t, roles{certify: true})
	ctx := context.Background()
	_, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
	_, err = svc.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{}))
	wantCode(t, err, connect.CodeUnimplemented)
}

// farmerSpec is one issue spec of the recorded catalogue.
func farmerSpec() *backendv1.IssueSpec {
	return &backendv1.IssueSpec{
		ConfigurationId: "FarmerCredential",
		SubjectData:     `{"fullName":"Ada Lovelace","farmerID":"FM-0001","district":"Nakuru"}`,
		Status: &backendv1.StatusListBinding{
			Kind:       backendv1.StatusListBinding_KIND_BITSTRING,
			Index:      12,
			PublishUrl: "https://status.example.org/bitstring/1",
		},
		Validity: &commonv1.ValidityWindow{
			ValidFrom:  timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			ValidUntil: timestamppb.New(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
	}
}

func TestCreateOfferStagesTheClaimsAndTheMarkers(t *testing.T) {
	svc, f := newService(t, both)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(),
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if !strings.HasPrefix(resp.Msg.GetOfferUri(), "openid-credential-offer://") {
		t.Fatalf("offer URI = %q", resp.Msg.GetOfferUri())
	}
	if resp.Msg.GetChannel() != backendv1.Channel_CHANNEL_OID4VCI_PREAUTH {
		t.Fatalf("channel = %v", resp.Msg.GetChannel())
	}
	if resp.Msg.GetOfferId() == "" {
		t.Fatal("the offer has no id")
	}
	if resp.Msg.GetExpiresAt() == nil {
		t.Fatal("the offer has no end time")
	}
	var body struct {
		ConfigurationID string         `json:"credential_configuration_id"`
		Claims          map[string]any `json:"claims"`
	}
	if err := f.RequestJSON("/v1/certify/pre-authorized-data", &body); err != nil {
		t.Fatalf("read the staging request: %v", err)
	}
	if body.ConfigurationID != "FarmerCredential" {
		t.Fatalf("configuration = %q", body.ConfigurationID)
	}
	if body.Claims["statusIdx"] != "12" || body.Claims["statusUri"] != "https://status.example.org/bitstring/1" {
		t.Fatalf("claims = %v; the markers keep the template resolvable", body.Claims)
	}
	if body.Claims["validFrom"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("claims = %v", body.Claims)
	}
	if body.Claims["fullName"] != "Ada Lovelace" {
		t.Fatalf("claims = %v", body.Claims)
	}
}

func TestCreateOfferChecksItsInput(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential"}, Channel: backendv1.Channel_CHANNEL_SMS,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "Unknown", SubjectData: `{"a":"b"}`},
	}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential", SubjectData: "not json"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "FarmerCredential"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateOfferReportsAStagingFailure(t *testing.T) {
	svc, f := newService(t, both)
	f.SetStaged(fake.StagedOfferError)
	_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(),
	}))
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/v1/certify/issuance/.well-known/openid-credential-issuer", http.StatusBadGateway)
	_, err = svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(),
	}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestCreateOfferHostsTheAuthorizationCodeOffer(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	resp, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec:    farmerSpec(),
		Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if !strings.Contains(resp.Msg.GetOfferUri(), "credential_offer_uri=") {
		t.Fatalf("offer URI = %q", resp.Msg.GetOfferUri())
	}
	if !strings.Contains(resp.Msg.GetOfferUri(), "adapter.example") {
		t.Fatalf("offer URI = %q, the wallet must reach this adapter", resp.Msg.GetOfferUri())
	}
	document, ok := svc.HostedOffer(ctx, resp.Msg.GetOfferId())
	if !ok {
		t.Fatal("the offer document is missing")
	}
	var offer map[string]any
	if err := json.Unmarshal([]byte(document), &offer); err != nil {
		t.Fatalf("the offer document is not JSON: %v", err)
	}
	grants := mustAs[map[string]any](t, offer["grants"])
	grant := mustAs[map[string]any](t, grants["authorization_code"])
	if grant["authorization_server"] != "https://esignet.example/v1/esignet" {
		t.Fatalf("grant = %v", grant)
	}
	if _, ok := svc.HostedOffer(ctx, "does-not-exist"); ok {
		t.Fatal("an unknown offer must not resolve")
	}
}

func TestHostedOfferExpires(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	client := dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1})
	now := fixedTime
	svc, err := service.New(service.Options{
		Certify:   inji.NewCertify(client, ""),
		Store:     store.Memory(),
		PublicURL: "https://adapter.example",
		OfferTTL:  time.Minute,
		Now:       func() time.Time { return now },
		NewID:     func() string { return "offer-1" },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec:    farmerSpec(),
		Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	})); err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if _, ok := svc.HostedOffer(ctx, "offer-1"); !ok {
		t.Fatal("the fresh offer is missing")
	}
	now = fixedTime.Add(2 * time.Minute)
	if _, ok := svc.HostedOffer(ctx, "offer-1"); ok {
		t.Fatal("an expired offer must not resolve")
	}
}

func TestAuthorizationCodeOfferNeedsAPublicUrl(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	client := dpgclient.New(dpgclient.Options{BaseURL: f.URL(), HTTP: f.Client(), Retries: -1})
	svc, err := service.New(service.Options{Certify: inji.NewCertify(client, ""), Store: store.Memory()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
	}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

func TestGetIssuerMetadataReturnsTheCatalogue(t *testing.T) {
	svc, _ := newService(t, both)
	resp, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	if resp.Msg.GetIssuer() != "https://inji-certify.example.org" {
		t.Fatalf("issuer = %q", resp.Msg.GetIssuer())
	}
	if len(resp.Msg.GetConfigurations()) != 2 {
		t.Fatalf("configurations = %d", len(resp.Msg.GetConfigurations()))
	}
	first := resp.Msg.GetConfigurations()[0]
	if first.GetId() != "FarmerCredential" || first.GetFormat() != commonv1.Format_FORMAT_LDP_VC {
		t.Fatalf("configuration = %v", first)
	}
	if first.GetType() != "FarmerCredential" {
		t.Fatalf("type = %q", first.GetType())
	}
	if len(first.GetSdClaims()) == 0 || first.GetDisplay() == "" {
		t.Fatalf("configuration = %v", first)
	}
	second := resp.Msg.GetConfigurations()[1]
	if second.GetType() != "https://inji-certify.example.org/credentials/IdentityCredential" {
		t.Fatalf("an SD-JWT configuration uses its vct, got %q", second.GetType())
	}
}

func TestGetIssuerMetadataReportsAFailure(t *testing.T) {
	svc, f := newService(t, both)
	f.SetStatus("/v1/certify/issuance/.well-known/openid-credential-issuer", http.StatusNotFound)
	_, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	wantCode(t, err, connect.CodeNotFound)
}

func TestListCredentialTypesPagesTheCatalogue(t *testing.T) {
	svc, _ := newService(t, both)
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
	svc, f := newService(t, both)
	f.SetStatus("/v1/certify/issuance/.well-known/openid-credential-issuer", http.StatusBadGateway)
	_, err := svc.ListCredentialTypes(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestCapabilitiesCarryDpgInfo(t *testing.T) {
	svc, _ := newService(t, both)
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	info := resp.Msg.GetDpgInfo()
	if info.GetDisplayName() == "" || info.GetVersion() != "0.14.0" {
		t.Fatalf("dpg info = %v", info)
	}
	seen := map[string]string{}
	for _, c := range info.GetComponents() {
		if c.GetName() == "" || c.GetVersion() == "" || c.GetLicense() == "" {
			t.Errorf("component %v lacks a name, a version, or a licence", c)
		}
		for _, u := range []string{c.GetRepositoryUrl(), c.GetDocsUrl()} {
			if !strings.HasPrefix(u, "https://") {
				t.Errorf("component %s: %q is not an https URL", c.GetName(), u)
			}
		}
		if _, dup := seen[c.GetName()]; dup {
			t.Errorf("component %s appears twice", c.GetName())
		}
		seen[c.GetName()] = c.GetVersion()
	}
	want := map[string]string{
		"certify": "0.14.0", "esignet": "1.5.1", "mock-identity": "0.10.1",
		"verify-service": "0.16.0", "verify-ui": "0.16.0", "keycloak": "25.0",
	}
	for name, version := range want {
		if seen[name] != version {
			t.Errorf("component %s = %q, want %q", name, seen[name], version)
		}
	}
	if !hasStatusKind(resp.Msg.GetStatusMechanisms(), backendv1.StatusListBinding_KIND_BITSTRING) ||
		!hasStatusKind(resp.Msg.GetStatusMechanisms(), backendv1.StatusListBinding_KIND_TOKEN) {
		t.Errorf("status mechanisms = %v, want both list kinds", resp.Msg.GetStatusMechanisms())
	}
	if len(resp.Msg.GetDidMethods()) != 0 {
		t.Errorf("DID methods = %v, the adapter manages no issuer DID today", resp.Msg.GetDidMethods())
	}
}

func TestCapabilitiesOfAVerifierOnlyDeploymentNameNoIssuerComponent(t *testing.T) {
	svc, _ := newService(t, roles{verify: true})
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	names := map[string]bool{}
	for _, c := range resp.Msg.GetDpgInfo().GetComponents() {
		names[c.GetName()] = true
	}
	if names["certify"] || names["esignet"] || names["mock-identity"] {
		t.Errorf("a verifier only deployment lists issuer components: %v", names)
	}
	if !names["verify-service"] || !names["keycloak"] {
		t.Errorf("the verifier components are missing: %v", names)
	}
	if len(resp.Msg.GetStatusMechanisms()) != 0 {
		t.Errorf("a verifier only deployment embeds no status: %v", resp.Msg.GetStatusMechanisms())
	}
}

// TestCapabilitiesListOnlyImplementedFeatures maps every feature that
// has an RPC behind it onto that RPC and calls it against the fake. The
// answer lists a feature when and only when the RPC works. A listed
// feature whose RPC answers Unimplemented is a lie the pages would show
// (ADR-034 decision 5).
func TestCapabilitiesListOnlyImplementedFeatures(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	resp, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	revoke := func() error {
		_, err := svc.Revoke(ctx, connect.NewRequest(&backendv1.RevokeRequest{}))
		return err
	}
	table := []struct {
		feature backendv1.Feature
		call    func() error
		// exact reports that the RPC works when and only when the
		// feature is listed. Suspension shares its RPC with revocation,
		// and a batch that loops over single issuances is not native.
		exact bool
	}{
		{backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API, func() error {
			_, err := svc.RegisterCredentialConfiguration(ctx,
				connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
					Configuration: &backendv1.CredentialConfiguration{
						Id: "probe", Format: commonv1.Format_FORMAT_LDP_VC, Type: "Probe",
					},
				}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_REVOCATION, revoke, true},
		{backendv1.Feature_FEATURE_SUSPENSION, revoke, false},
		{backendv1.Feature_FEATURE_VERIFY_UPLOAD, func() error {
			_, err := svc.VerifyCredential(ctx, connect.NewRequest(&backendv1.VerifyCredentialRequest{}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_ISSUED_LEDGER, func() error {
			_, err := svc.ListIssuedCredentials(ctx, connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_ISSUANCE_STATUS, func() error {
			_, err := svc.GetIssuanceStatus(ctx, connect.NewRequest(&backendv1.GetIssuanceStatusRequest{}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_BULK_NATIVE, func() error {
			_, err := svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{}))
			return err
		}, false},
		{backendv1.Feature_FEATURE_MULTI_TENANCY, func() error {
			_, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS, func() error {
			_, err := svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_WEBHOOKS, func() error {
			_, err := svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{}))
			return err
		}, true},
	}
	listed := map[backendv1.Feature]bool{}
	for _, f := range resp.Msg.GetFeatures() {
		listed[f] = true
	}
	known := map[backendv1.Feature]bool{}
	for _, row := range table {
		known[row.feature] = true
		works := connect.CodeOf(row.call()) != connect.CodeUnimplemented
		if listed[row.feature] && !works {
			t.Errorf("the feature %v is listed but its RPC answers Unimplemented", row.feature)
		}
		if row.exact && works && !listed[row.feature] {
			t.Errorf("the RPC of the feature %v works but the answer does not list it", row.feature)
		}
	}
	for f := range listed {
		if !known[f] {
			t.Errorf("the feature %v has no RPC behind it yet, so the answer must not list it", f)
		}
	}
}

func hasStatusKind(list []backendv1.StatusListBinding_Kind, want backendv1.StatusListBinding_Kind) bool {
	for _, k := range list {
		if k == want {
			return true
		}
	}
	return false
}

// TestTenantServiceUnimplementedWithoutFeature is ADR-037 decision 2:
// the adapter serves no DPG tenancy yet, so every tenant RPC answers
// Unimplemented with a reason, and the capability answer lists no
// tenancy feature. The admin pages then offer no tenancy on this stack.
func TestTenantServiceUnimplementedWithoutFeature(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	calls := []func() error{
		func() error {
			_, err := svc.CreateTenant(ctx, connect.NewRequest(&backendv1.CreateTenantRequest{Name: "Ministry"}))
			return err
		},
		func() error {
			_, err := svc.GetTenant(ctx, connect.NewRequest(&backendv1.GetTenantRequest{Id: "t-1"}))
			return err
		},
		func() error {
			_, err := svc.ListTenants(ctx, connect.NewRequest(&backendv1.ListTenantsRequest{}))
			return err
		},
		func() error {
			_, err := svc.DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{Id: "t-1"}))
			return err
		},
		func() error {
			_, err := svc.ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{TenantId: "t-1"}))
			return err
		},
		func() error {
			_, err := svc.CreateClientCredential(ctx, connect.NewRequest(&backendv1.CreateClientCredentialRequest{TenantId: "t-1", Name: "ci"}))
			return err
		},
		func() error {
			_, err := svc.DeleteClientCredential(ctx, connect.NewRequest(&backendv1.DeleteClientCredentialRequest{TenantId: "t-1", Id: "c-1"}))
			return err
		},
	}
	for i, call := range calls {
		err := call()
		wantCode(t, err, connect.CodeUnimplemented)
		if !strings.Contains(err.Error(), "tenant") {
			t.Errorf("call %d: the message %q does not say why", i, err)
		}
	}
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range caps.Msg.GetFeatures() {
		if f == backendv1.Feature_FEATURE_MULTI_TENANCY || f == backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS {
			t.Errorf("the answer lists %v", f)
		}
	}
}

// TestWebhookServiceUnimplementedWithoutFeature is ADR-040 decision 2:
// the adapter sets no DPG webhook yet, so both notification RPCs answer
// Unimplemented with a reason, and the answer lists no webhooks. The
// admin notifications page then shows no webhook form for this stack.
func TestWebhookServiceUnimplementedWithoutFeature(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	_, err := svc.GetWebhook(ctx, connect.NewRequest(&backendv1.GetWebhookRequest{TenantId: "t-1"}))
	wantCode(t, err, connect.CodeUnimplemented)
	if !strings.Contains(err.Error(), "webhook") {
		t.Errorf("the message %q does not say why", err)
	}
	_, err = svc.SetWebhook(ctx, connect.NewRequest(&backendv1.SetWebhookRequest{TenantId: "t-1", Url: "https://hooks.example/vca"}))
	wantCode(t, err, connect.CodeUnimplemented)
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range caps.Msg.GetFeatures() {
		if f == backendv1.Feature_FEATURE_WEBHOOKS {
			t.Errorf("the answer lists %v", f)
		}
	}
}

// TestIssuerIdentityUnimplementedWithoutFeature is ADR-046 decision 1:
// the adapter does not manage the issuer identity through the stack yet,
// so the three identity RPCs answer Unimplemented with a reason, and the
// capability answer lists no identity feature. The identity page then
// offers no action on this stack.
func TestIssuerIdentityUnimplementedWithoutFeature(t *testing.T) {
	svc, _ := newService(t, both)
	ctx := context.Background()
	calls := []func() error{
		func() error {
			_, err := svc.GetIssuerIdentity(ctx, connect.NewRequest(&backendv1.GetIssuerIdentityRequest{}))
			return err
		},
		func() error {
			_, err := svc.ProvisionIssuerIdentity(ctx, connect.NewRequest(&backendv1.ProvisionIssuerIdentityRequest{Method: "did:web"}))
			return err
		},
		func() error {
			_, err := svc.ImportIssuerIdentity(ctx, connect.NewRequest(&backendv1.ImportIssuerIdentityRequest{
				Subject: &backendv1.ImportIssuerIdentityRequest_Did{Did: "did:web:issuer.example"},
			}))
			return err
		},
	}
	for i, call := range calls {
		err := call()
		wantCode(t, err, connect.CodeUnimplemented)
		if !strings.Contains(err.Error(), "identity") {
			t.Errorf("call %d: the message %q does not say why", i, err)
		}
	}
	caps, err := svc.GetCapabilities(ctx, connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range caps.Msg.GetFeatures() {
		switch f {
		case backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION, backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID,
			backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509:
			t.Errorf("the answer lists %v", f)
		}
	}
}
