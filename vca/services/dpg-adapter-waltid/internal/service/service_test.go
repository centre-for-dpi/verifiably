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
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

const testdata = "../../testdata"

// roles says which walt.id services the test wires.
type roles struct {
	issuer   bool
	verifier bool
	wallet   bool
}

// all wires every role.
var all = roles{issuer: true, verifier: true, wallet: true}

// newService starts the fake and returns the service under test.
func newService(t *testing.T, r roles) (*service.Service, *fake.Server) {
	t.Helper()
	f := fake.New(testdata)
	t.Cleanup(f.Close)
	client := func(on bool) *dpgclient.Client {
		if !on {
			return nil
		}
		return dpgclient.New(dpgclient.Options{
			BaseURL: f.URL(), HTTP: f.Client(), Retries: -1,
			Sleep: func(time.Duration) {},
		})
	}
	svc, err := service.New(service.Options{
		Client: waltid.New(waltid.Options{
			Issuer:          client(r.issuer),
			Verifier:        client(r.verifier),
			Wallet:          client(r.wallet),
			StandardVersion: "draft13",
		}),
		Store:      store.Memory(),
		DpgVersion: "0.18.2",
		Versions: map[string]string{
			"issuer-api": "0.18.2", "verifier-api": "0.18.2", "wallet-api": "0.18.2", "keycloak": "25.0",
		},
		VctBase:     "https://issuer.example.org",
		PageSizeMax: 1,
		Now:         func() time.Time { return time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	return svc, f
}

func TestNewChecksItsInput(t *testing.T) {
	if _, err := service.New(service.Options{Store: store.Memory()}); err == nil {
		t.Fatal("New accepted a missing client")
	}
	if _, err := service.New(service.Options{Client: waltid.New(waltid.Options{})}); err == nil {
		t.Fatal("New accepted a missing store")
	}
}

func TestReadyReportsAWiredService(t *testing.T) {
	svc, _ := newService(t, all)
	if !svc.Ready() {
		t.Fatal("the service is not ready")
	}
}

func TestGetCapabilitiesListsEveryWiredRole(t *testing.T) {
	svc, _ := newService(t, all)
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	msg := resp.Msg
	if msg.GetAdapter() != service.AdapterName || msg.GetDpgVersion() != "0.18.2" {
		t.Fatalf("adapter %q version %q", msg.GetAdapter(), msg.GetDpgVersion())
	}
	wantRoles := []commonv1.Role{
		commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER,
	}
	if len(msg.GetRoles()) != len(wantRoles) {
		t.Fatalf("roles = %v", msg.GetRoles())
	}
	for i, want := range wantRoles {
		if msg.GetRoles()[i] != want {
			t.Fatalf("role %d = %v, want %v", i, msg.GetRoles()[i], want)
		}
	}
	if !hasProtocol(msg.GetProtocols(), backendv1.Protocol_PROTOCOL_OID4VP_PEX) {
		t.Fatal("walt.id 0.18.2 speaks Presentation Exchange, which the answer must list")
	}
	if hasProtocol(msg.GetProtocols(), backendv1.Protocol_PROTOCOL_OID4VP_DCQL) {
		t.Fatal("walt.id 0.18.2 has no DCQL support, so the answer must not list it")
	}
	if hasChannel(msg.GetChannels(), backendv1.Channel_CHANNEL_PDF) {
		t.Fatal("walt.id has no PDF export, so the answer must not list the PDF channel")
	}
}

func TestGetCapabilitiesOfAVerifierOnlyDeployment(t *testing.T) {
	svc, _ := newService(t, roles{verifier: true})
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	if len(resp.Msg.GetRoles()) != 1 || resp.Msg.GetRoles()[0] != commonv1.Role_ROLE_VERIFIER {
		t.Fatalf("roles = %v", resp.Msg.GetRoles())
	}
	if len(resp.Msg.GetFormats()) != 0 || len(resp.Msg.GetChannels()) != 0 {
		t.Fatal("a verifier only deployment issues nothing")
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

func hasChannel(list []backendv1.Channel, want backendv1.Channel) bool {
	for _, c := range list {
		if c == want {
			return true
		}
	}
	return false
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

func TestEveryUnwiredRoleAnswersUnimplemented(t *testing.T) {
	svc, _ := newService(t, roles{})
	ctx := context.Background()
	calls := map[string]func() error{
		"RegisterCredentialConfiguration": func() error {
			_, err := svc.RegisterCredentialConfiguration(ctx,
				connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{}))
			return err
		},
		"CreateOffer": func() error {
			_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{}))
			return err
		},
		"GetIssuerMetadata": func() error {
			_, err := svc.GetIssuerMetadata(ctx, connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
			return err
		},
		"ListCredentialTypes": func() error {
			_, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
			return err
		},
		"Register": func() error {
			_, err := svc.Register(ctx, connect.NewRequest(&backendv1.RegisterRequest{}))
			return err
		},
		"ListCredentials": func() error {
			_, err := svc.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{}))
			return err
		},
		"AcceptOffer": func() error {
			_, err := svc.AcceptOffer(ctx, connect.NewRequest(&backendv1.AcceptOfferRequest{}))
			return err
		},
		"Present": func() error {
			_, err := svc.Present(ctx, connect.NewRequest(&backendv1.PresentRequest{}))
			return err
		},
		"DeleteCredential": func() error {
			_, err := svc.DeleteCredential(ctx, connect.NewRequest(&backendv1.DeleteCredentialRequest{}))
			return err
		},
		"CreateRequest": func() error {
			_, err := svc.CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{}))
			return err
		},
		"GetResult": func() error {
			_, err := svc.GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{}))
			return err
		},
	}
	for name, call := range calls {
		err := call()
		wantCode(t, err, connect.CodeUnimplemented)
		if strings.TrimSpace(err.Error()) == "" {
			t.Fatalf("%s: the error has no message", name)
		}
	}
}

func TestTheRpcsThatWaltidNeverSupportsAnswerUnimplemented(t *testing.T) {
	svc, _ := newService(t, all)
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

func TestRegisterCredentialConfigurationBorrowsAConfigurationOfTheSameFormat(t *testing.T) {
	svc, f := newService(t, all)
	resp, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{
				Id:     "farmer-2026",
				Format: commonv1.Format_FORMAT_JWT_VC_JSON,
				Type:   "FarmerCredential",
			},
		}))
	if err != nil {
		t.Fatalf("RegisterCredentialConfiguration: %v", err)
	}
	if resp.Msg.GetId() != "farmer-2026" {
		t.Fatalf("id = %q", resp.Msg.GetId())
	}
	// The offer must now use the borrowed walt.id configuration and the
	// type of the schema.
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "farmer-2026",
			Format:          commonv1.Format_FORMAT_JWT_VC_JSON,
			SubjectData:     `{"given_name":"Ada"}`,
		},
		Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
	})); err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/jwt/issue", &body); err != nil {
		t.Fatalf("read the issue request: %v", err)
	}
	if body["credentialConfigurationId"] != "UniversityDegree_jwt_vc_json" {
		t.Fatalf("configuration = %v, want the borrowed walt.id one", body["credentialConfigurationId"])
	}
	var credential map[string]any
	if err := json.Unmarshal([]byte(toJSON(t, body["credentialData"])), &credential); err != nil {
		t.Fatalf("read the credential data: %v", err)
	}
	types := mustAs[[]any](t, credential["type"])
	if len(types) != 2 || types[1] != "FarmerCredential" {
		t.Fatalf("types = %v, want the type of the schema", types)
	}
}

// toJSON turns a decoded value back into JSON text.
func toJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(raw)
}

func TestRegisterCredentialConfigurationChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	ctx := context.Background()
	_, err := svc.RegisterCredentialConfiguration(ctx,
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.RegisterCredentialConfiguration(ctx,
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{Id: "x", Format: commonv1.Format_FORMAT_LDP_VC_BBS},
		}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestRegisterCredentialConfigurationFailsWithoutAMatchingFormat(t *testing.T) {
	svc, _ := newService(t, all)
	_, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{
				Id: "x", Format: commonv1.Format_FORMAT_LDP_VC, Type: "Example",
			},
		}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

func TestCreateOfferUsesTheSdJwtPathAndSetsTheDisclosureMap(t *testing.T) {
	svc, f := newService(t, all)
	_, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{
			Configuration: &backendv1.CredentialConfiguration{
				Id:     "identity-2026",
				Format: commonv1.Format_FORMAT_VC_SD_JWT,
				Type:   "IdentityCredential",
			},
		}))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "identity-2026",
			SubjectData:     `{"given_name":"Ada","age_over_18":true}`,
			Status: &backendv1.StatusListBinding{
				Kind:       backendv1.StatusListBinding_KIND_TOKEN,
				Index:      42,
				PublishUrl: "https://status.example.org/token/1",
			},
			Validity: &commonv1.ValidityWindow{
				ValidFrom:  timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
				ValidUntil: timestamppb.New(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
		Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
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
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/sdjwt/issue", &body); err != nil {
		t.Fatalf("the SD-JWT issue path was not called: %v", err)
	}
	if body["authenticationMethod"] != "PRE_AUTHORIZED" {
		t.Fatalf("authentication method = %v", body["authenticationMethod"])
	}
	if body["vct"] != "https://issuer.example.org/credentials/identity-2026" {
		t.Fatalf("vct = %v", body["vct"])
	}
	sd := mustAs[map[string]any](t, body["selectiveDisclosure"])
	fields := mustAs[map[string]any](t, sd["fields"])
	if len(fields) != 2 {
		t.Fatalf("the disclosure map has %d fields, want one per claim", len(fields))
	}
	credential := mustAs[map[string]any](t, body["credentialData"])
	if credential["given_name"] != "Ada" {
		t.Fatalf("the SD-JWT claims must sit at the payload root, got %v", credential)
	}
	status := mustAs[map[string]any](t, credential["status"])
	list := mustAs[map[string]any](t, status["status_list"])
	if list == nil || list["uri"] != "https://status.example.org/token/1" {
		t.Fatalf("status = %v", status)
	}
	if credential["nbf"] == nil || credential["exp"] == nil {
		t.Fatalf("the validity window is missing: %v", credential)
	}
}

func TestCreateOfferPutsABitstringStatusEntryInTheVcdmBody(t *testing.T) {
	svc, f := newService(t, all)
	_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "UniversityDegree_jwt_vc_json",
			SubjectData:     `{"degree":"Mathematics"}`,
			Subject:         &commonv1.Subject{Did: "did:key:zHolder"},
			Status: &backendv1.StatusListBinding{
				Kind:       backendv1.StatusListBinding_KIND_BITSTRING,
				Index:      7,
				PublishUrl: "https://status.example.org/bitstring/1",
			},
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/jwt/issue", &body); err != nil {
		t.Fatalf("read the issue request: %v", err)
	}
	credential := mustAs[map[string]any](t, body["credentialData"])
	subject := mustAs[map[string]any](t, credential["credentialSubject"])
	if subject["id"] != "did:key:zHolder" {
		t.Fatalf("the subject DID is missing: %v", subject)
	}
	status := mustAs[map[string]any](t, credential["credentialStatus"])
	if status["type"] != "BitstringStatusListEntry" {
		t.Fatalf("status type = %v", status["type"])
	}
	if _, ok := status["statusListIndex"].(string); !ok {
		t.Fatalf("statusListIndex = %#v, a verifier rejects a number here", status["statusListIndex"])
	}
}

func TestCreateOfferSendsAWholeCredentialBodyAsItIs(t *testing.T) {
	svc, f := newService(t, all)
	_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "UniversityDegree_jwt_vc_json",
			CredentialData:  `{"type":["VerifiableCredential","Delegation"],"termsOfUse":{"id":"x"}}`,
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/jwt/issue", &body); err != nil {
		t.Fatalf("read the issue request: %v", err)
	}
	credential := mustAs[map[string]any](t, body["credentialData"])
	if credential["termsOfUse"] == nil {
		t.Fatalf("the caller body was not kept: %v", credential)
	}
}

func TestCreateOfferUsesTheMdocPath(t *testing.T) {
	svc, f := newService(t, all)
	_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "org.iso.18013.5.1.mDL",
			SubjectData:     `{"family_name":"Lovelace"}`,
		},
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/mdoc/issue", &body); err != nil {
		t.Fatalf("the mdoc issue path was not called: %v", err)
	}
	data := mustAs[map[string]any](t, body["mdocData"])
	claims := mustAs[map[string]any](t, data["org.iso.18013.5.1"])
	if claims["family_name"] != "Lovelace" {
		t.Fatalf("the mdoc namespace is wrong: %v", data)
	}
}

func TestCreateOfferChecksItsInput(t *testing.T) {
	svc, _ := newService(t, all)
	ctx := context.Background()
	_, err := svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "x"}, Channel: backendv1.Channel_CHANNEL_PDF,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "unknown-configuration"},
	}))
	wantCode(t, err, connect.CodeNotFound)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "UniversityDegree_jwt_vc_json", SubjectData: "not json",
		},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = svc.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{
			ConfigurationId: "UniversityDegree_jwt_vc_json", CredentialData: "{",
		},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateOfferReportsAFailureOfWaltid(t *testing.T) {
	svc, f := newService(t, all)
	f.SetStatus("/openid4vc/jwt/issue", http.StatusBadRequest)
	_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "UniversityDegree_jwt_vc_json"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus("/openid4vc/jwt/issue", http.StatusInternalServerError)
	_, err = svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "UniversityDegree_jwt_vc_json"},
	}))
	wantCode(t, err, connect.CodeUnavailable)
	f.SetStatus("/draft13/.well-known/openid-credential-issuer", http.StatusServiceUnavailable)
	_, err = svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: &backendv1.IssueSpec{ConfigurationId: "UniversityDegree_jwt_vc_json"},
	}))
	wantCode(t, err, connect.CodeUnavailable)
}

func TestGetIssuerMetadataReturnsTheCatalogue(t *testing.T) {
	svc, _ := newService(t, all)
	resp, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	if resp.Msg.GetIssuer() != "https://walt-issuer.example.org" {
		t.Fatalf("issuer = %q", resp.Msg.GetIssuer())
	}
	if !strings.HasPrefix(resp.Msg.GetIssuerDid(), "did:key:") {
		t.Fatalf("issuer DID = %q", resp.Msg.GetIssuerDid())
	}
	if len(resp.Msg.GetConfigurations()) != 3 {
		t.Fatalf("configurations = %d, want 3", len(resp.Msg.GetConfigurations()))
	}
	if !strings.Contains(resp.Msg.GetMetadataJson(), "credential_configurations_supported") {
		t.Fatal("the metadata document is missing")
	}
}

func TestGetIssuerMetadataWorksWithoutAnOnboardedKey(t *testing.T) {
	svc, f := newService(t, all)
	f.SetStatus("/onboard/issuer", http.StatusInternalServerError)
	resp, err := svc.GetIssuerMetadata(context.Background(),
		connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatalf("GetIssuerMetadata: %v", err)
	}
	if resp.Msg.GetIssuerDid() != "" {
		t.Fatalf("issuer DID = %q, want an empty value", resp.Msg.GetIssuerDid())
	}
}

func TestListCredentialTypesPagesTheCatalogue(t *testing.T) {
	svc, _ := newService(t, all)
	ctx := context.Background()
	first, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if len(first.Msg.GetConfigurations()) != 1 || first.Msg.GetPage().GetTotalSize() != 3 {
		t.Fatalf("page = %v", first.Msg)
	}
	token := first.Msg.GetPage().GetNextPageToken()
	if token == "" {
		t.Fatal("the first page has no next token")
	}
	last, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{
		Page: &commonv1.Pagination{PageSize: 10, PageToken: "2"},
	}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if last.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("the last page has a next token")
	}
	if token != "1" {
		t.Fatalf("next token = %q, want 1", token)
	}
	past, err := svc.ListCredentialTypes(ctx, connect.NewRequest(&backendv1.ListCredentialTypesRequest{
		Page: &commonv1.Pagination{PageToken: "99"},
	}))
	if err != nil {
		t.Fatalf("ListCredentialTypes: %v", err)
	}
	if len(past.Msg.GetConfigurations()) != 0 {
		t.Fatal("a token past the end must return no entry")
	}
}

func TestListCredentialTypesReportsAFailure(t *testing.T) {
	svc, f := newService(t, all)
	f.SetStatus("/draft13/.well-known/openid-credential-issuer", http.StatusBadGateway)
	_, err := svc.ListCredentialTypes(context.Background(),
		connect.NewRequest(&backendv1.ListCredentialTypesRequest{}))
	wantCode(t, err, connect.CodeUnavailable)
}

// readFixture returns one recorded answer of the testdata directory.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, name)) //nolint:gosec // G304: the path is a test directory
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return raw
}

func TestCapabilitiesCarryDpgInfo(t *testing.T) {
	svc, _ := newService(t, all)
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	info := resp.Msg.GetDpgInfo()
	if info.GetDisplayName() == "" || info.GetVersion() != "0.18.2" {
		t.Fatalf("dpg info = %v", info)
	}
	if len(info.GetComponents()) < 4 {
		t.Fatalf("components = %v, want the three APIs and the identity provider", info.GetComponents())
	}
	seen := map[string]bool{}
	for _, c := range info.GetComponents() {
		if c.GetName() == "" || c.GetVersion() == "" || c.GetLicense() == "" {
			t.Errorf("component %v lacks a name, a version, or a licence", c)
		}
		for _, u := range []string{c.GetRepositoryUrl(), c.GetDocsUrl()} {
			if !strings.HasPrefix(u, "https://") {
				t.Errorf("component %s: %q is not an https URL", c.GetName(), u)
			}
		}
		if seen[c.GetName()] {
			t.Errorf("component %s appears twice", c.GetName())
		}
		seen[c.GetName()] = true
	}
	for _, name := range []string{"issuer-api", "verifier-api", "wallet-api", "keycloak"} {
		if !seen[name] {
			t.Errorf("the component %s is missing", name)
		}
	}
	for _, c := range info.GetComponents() {
		if c.GetName() == "keycloak" && c.GetVersion() != "25.0" {
			t.Errorf("keycloak version = %q, want the configured 25.0", c.GetVersion())
		}
	}
	if !hasStatusKind(resp.Msg.GetStatusMechanisms(), backendv1.StatusListBinding_KIND_BITSTRING) ||
		!hasStatusKind(resp.Msg.GetStatusMechanisms(), backendv1.StatusListBinding_KIND_TOKEN) {
		t.Errorf("status mechanisms = %v, want both list kinds", resp.Msg.GetStatusMechanisms())
	}
	if len(resp.Msg.GetDidMethods()) != 1 || resp.Msg.GetDidMethods()[0] != "did:key" {
		t.Errorf("DID methods = %v, want the onboarded did:key", resp.Msg.GetDidMethods())
	}
}

func TestCapabilitiesOfAVerifierOnlyDeploymentNameNoIssuerComponent(t *testing.T) {
	svc, _ := newService(t, roles{verifier: true})
	resp, err := svc.GetCapabilities(context.Background(),
		connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	for _, c := range resp.Msg.GetDpgInfo().GetComponents() {
		if c.GetName() == "issuer-api" || c.GetName() == "wallet-api" {
			t.Errorf("a verifier only deployment lists %s", c.GetName())
		}
	}
	if len(resp.Msg.GetFeatures()) != 0 || len(resp.Msg.GetStatusMechanisms()) != 0 || len(resp.Msg.GetDidMethods()) != 0 {
		t.Errorf("a verifier only deployment lists issuer features: %v", resp.Msg)
	}
}

// TestCapabilitiesListOnlyImplementedFeatures maps every feature that
// has an RPC behind it onto that RPC and calls it against the fake. The
// answer lists a feature when and only when the RPC works. A listed
// feature whose RPC answers Unimplemented is a lie the pages would show
// (ADR-034 decision 5).
func TestCapabilitiesListOnlyImplementedFeatures(t *testing.T) {
	svc, _ := newService(t, all)
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
						Id: "probe", Format: commonv1.Format_FORMAT_JWT_VC_JSON, Type: "Probe",
					},
				}))
			return err
		}, true},
		{backendv1.Feature_FEATURE_REVOCATION, revoke, true},
		{backendv1.Feature_FEATURE_SUSPENSION, revoke, false},
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
	svc, _ := newService(t, all)
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
	svc, _ := newService(t, all)
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
