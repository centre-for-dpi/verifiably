// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// withPresentation turns presentation during issuance on.
func withPresentation(o *serviceOptions) {
	o.PresentationDuringIssuance = true
	o.IARIdentityClaims = []string{"vcaSubject", "nationalId"}
}

// setRequirement stores the credential to present.
func setRequirement(t *testing.T, svc *service.Service) *backendv1.SetPresentationRequirementResponse {
	t.Helper()
	resp, err := svc.SetPresentationRequirement(context.Background(), connect.NewRequest(&backendv1.SetPresentationRequirementRequest{
		CredentialType: "NationalIdentityCredential", Format: commonv1.Format_FORMAT_LDP_VC,
		RequiredClaims: []string{"vcaSubject"}, Purpose: "Show your national identity credential.",
	}))
	if err != nil {
		t.Fatalf("SetPresentationRequirement: %v", err)
	}
	return resp.Msg
}

// presentationSpec is farmerSpec for the holder who presents the value
// NID-1001 of the identity claim.
func presentationSpec() *backendv1.IssueSpec {
	spec := farmerSpec()
	spec.PresentationSubject = &backendv1.PresentationSubject{Claim: "vcaSubject", Value: "NID-1001"}
	return spec
}

// postForm posts a form and decodes the JSON answer.
func postForm(t *testing.T, client *http.Client, address string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := client.PostForm(address, form) //nolint:noctx // a test call to the fake
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s answered %s", address, raw)
	}
	return resp.StatusCode, out
}

// TestOfferRequiresPresentation builds an authorization code offer whose
// authorization server is the interactive server of Certify. A wallet
// that follows it gets the presentation request of the stack, presents,
// receives a code, and trades it for an access token.
func TestOfferRequiresPresentation(t *testing.T) {
	svc, f := newServiceWith(t, both, withPresentation)
	setRequirement(t, svc)
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: presentationSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, RequirePresentation: true,
	}))
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	if resp.Msg.GetChannel() != backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE {
		t.Fatalf("channel = %v, a presentation needs the authorization code flow", resp.Msg.GetChannel())
	}
	document, ok := svc.HostedOffer(context.Background(), resp.Msg.GetOfferId())
	if !ok {
		t.Fatal("the adapter does not host the offer")
	}
	var offer struct {
		IDs    []string `json:"credential_configuration_ids"`
		Grants struct {
			Code struct {
				Server string `json:"authorization_server"`
				State  string `json:"issuer_state"`
			} `json:"authorization_code"`
		} `json:"grants"`
	}
	if jerr := json.Unmarshal([]byte(document), &offer); jerr != nil {
		t.Fatal(jerr)
	}
	server := f.URL() + "/v1/certify"
	if offer.Grants.Code.Server != server || offer.Grants.Code.State == "" || !slices.Equal(offer.IDs, []string{"FarmerCredential"}) {
		t.Fatalf("offer = %s", document)
	}

	// The wallet side, as the wallet portal runs it.
	client := f.Client()
	meta, err := client.Get(server + "/.well-known/oauth-authorization-server") //nolint:noctx // a test call to the fake
	if err != nil {
		t.Fatal(err)
	}
	var as struct {
		Interactive string `json:"interactive_authorization_endpoint"`
		Token       string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(meta.Body).Decode(&as); err != nil {
		t.Fatal(err)
	}
	if cerr := meta.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	verifier := "a-verifier-of-forty-three-characters-000000"
	sum := sha256.Sum256([]byte(verifier))
	status, first := postForm(t, client, as.Interactive, url.Values{
		"response_type": {"code"}, "client_id": {"vca-wallet"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "interaction_types_supported": {"openid4vp_presentation"},
		"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"FarmerCredential"}]`},
	})
	if status != http.StatusOK || first["status"] != "require_interaction" || first["auth_session"] != fake.AuthSession {
		t.Fatalf("first answer %d %v", status, first)
	}
	request := mustAs[map[string]any](t, first["openid4vp_request"])
	if request["response_mode"] != "iar-post" || request["response_uri"] != as.Interactive {
		t.Fatalf("request = %v", request)
	}
	_, refused := postForm(t, client, as.Interactive, url.Values{"auth_session": {fake.AuthSession}, "openid4vp_response": {`{}`}})
	if refused["status"] != "error" {
		t.Fatalf("an answer without a vp_token = %v", refused)
	}
	_, second := postForm(t, client, as.Interactive, url.Values{
		"auth_session": {fake.AuthSession}, "openid4vp_response": {`{"vp_token":"eyJ.a.b","presentation_submission":{}}`},
	})
	code := anyval.As[string](second["code"])
	if second["status"] != "ok" || !strings.HasPrefix(code, "iar_auth_") {
		t.Fatalf("second answer %v", second)
	}
	status, bad := postForm(t, client, as.Token, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {"wrong"}})
	if status != http.StatusBadRequest || bad["error"] != "invalid_grant" {
		t.Fatalf("a wrong verifier = %d %v", status, bad)
	}
	_, token := postForm(t, client, as.Token, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}})
	if token["access_token"] == nil || token["c_nonce"] == nil {
		t.Fatalf("token = %v", token)
	}
	status, _ = postForm(t, client, as.Interactive, url.Values{"response_type": {"token"}})
	if status != http.StatusBadRequest {
		t.Fatalf("a broken first request = %d", status)
	}
}

// TestOfferRequiresPresentationNeedsTheStack refuses the option without
// the setting and when Certify names no interactive endpoint.
func TestOfferRequiresPresentationNeedsTheStack(t *testing.T) {
	req := func() *connect.Request[backendv1.CreateOfferRequest] {
		return connect.NewRequest(&backendv1.CreateOfferRequest{Spec: presentationSpec(), RequirePresentation: true})
	}
	off, _ := newService(t, both)
	_, err := off.CreateOffer(context.Background(), req())
	wantCode(t, err, connect.CodeFailedPrecondition)

	on, f := newServiceWith(t, both, withPresentation)
	setRequirement(t, on)
	_, err = on.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: presentationSpec(), RequirePresentation: true, Channel: backendv1.Channel_CHANNEL_PDF,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus(fake.ASMetadataPath, http.StatusNotFound)
	_, err = on.CreateOffer(context.Background(), req())
	wantCode(t, err, connect.CodeFailedPrecondition)

	noURL, _ := newServiceWith(t, both, func(o *service.Options) {
		withPresentation(o)
		o.PublicURL = ""
	})
	setRequirement(t, noURL)
	_, err = noURL.CreateOffer(context.Background(), req())
	wantCode(t, err, connect.CodeFailedPrecondition)
}

// TestPresentationOfferWritesTheSubjectRow: the row of an offer with a
// presentation during issuance has the value of the identity claim as
// its subject, which Certify takes from the presented credential
// (ADR-051 decision 5).
func TestPresentationOfferWritesTheSubjectRow(t *testing.T) {
	var dir string
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) {
		withPresentation(o)
		dir = o.Claims.Dir
	})
	setRequirement(t, svc)
	if _, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: presentationSpec(), RequirePresentation: true,
	})); err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	row, ok, err := claims.Writer{Dir: dir}.Find("NID-1001")
	if err != nil || !ok || row.Map([]string{"fullName"})["fullName"] != "Ada Lovelace" || row.ConfigID != "FarmerCredential" {
		t.Fatalf("row = %+v %v %v", row, ok, err)
	}
}

// TestPresentationOfferNeedsASubjectClaim: the offer names the holder by
// one of the identity claims of the stack, and the requirement exists.
func TestPresentationOfferNeedsASubjectClaim(t *testing.T) {
	svc, _ := newServiceWith(t, both, withPresentation)
	offer := func(spec *backendv1.IssueSpec) error {
		_, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: spec, RequirePresentation: true,
		}))
		return err
	}
	err := offer(presentationSpec())
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "configure the credential to present first") {
		t.Errorf("err = %v", err)
	}
	setRequirement(t, svc)
	for _, subject := range []*backendv1.PresentationSubject{
		nil,
		{Claim: "vcaSubject", Value: "  "},
		{Claim: "email", Value: "a@b.example"},
	} {
		spec := farmerSpec()
		spec.PresentationSubject = subject
		err := offer(spec)
		wantCode(t, err, connect.CodeInvalidArgument)
		if !strings.Contains(err.Error(), "vcaSubject, nationalId") {
			t.Errorf("err = %v", err)
		}
	}
}

// TestSetPresentationRequirement builds the definition Certify reads,
// and a clear removes it.
func TestSetPresentationRequirement(t *testing.T) {
	svc, _ := newServiceWith(t, both, withPresentation)
	got := setRequirement(t, svc)
	if !slices.Equal(got.GetIdentityClaims(), []string{"vcaSubject", "nationalId"}) {
		t.Errorf("identity claims = %v", got.GetIdentityClaims())
	}
	var doc struct {
		Definition struct {
			ID          string `json:"id"`
			Purpose     string `json:"purpose"`
			Descriptors []struct {
				Format      map[string]map[string][]string `json:"format"`
				Constraints struct {
					Fields []struct {
						Path   []string       `json:"path"`
						Filter map[string]any `json:"filter"`
					} `json:"fields"`
				} `json:"constraints"`
			} `json:"input_descriptors"`
		} `json:"presentation_definition"`
	}
	if err := json.Unmarshal([]byte(got.GetDefinitionJson()), &doc); err != nil {
		t.Fatal(err)
	}
	d := doc.Definition
	if !strings.HasPrefix(d.ID, "vca-") || d.Purpose != "Show your national identity credential." || len(d.Descriptors) != 1 {
		t.Fatalf("definition = %s", got.GetDefinitionJson())
	}
	fields := d.Descriptors[0].Constraints.Fields
	if len(fields) != 2 || fields[0].Path[0] != "$.type" || fields[0].Filter["pattern"] != "NationalIdentityCredential" ||
		fields[1].Path[0] != "$.credentialSubject.vcaSubject" {
		t.Errorf("fields = %+v", fields)
	}
	if !slices.Contains(d.Descriptors[0].Format["ldp_vc"]["proof_type"], "Ed25519Signature2020") {
		t.Errorf("format = %v", d.Descriptors[0].Format)
	}
	stored, ok := svc.PresentationDefinition(context.Background())
	if !ok || string(stored) != got.GetDefinitionJson() {
		t.Errorf("stored = %s", stored)
	}
	// An SD-JWT VC reads the vct and the top level claims.
	sd, err := svc.SetPresentationRequirement(context.Background(), connect.NewRequest(&backendv1.SetPresentationRequirementRequest{
		CredentialType: "https://id.gov.example/national", Format: commonv1.Format_FORMAT_VC_SD_JWT, RequiredClaims: []string{"nationalId", " "},
	}))
	if err != nil || !strings.Contains(sd.Msg.GetDefinitionJson(), `"$.vct"`) || !strings.Contains(sd.Msg.GetDefinitionJson(), `"$.nationalId"`) ||
		!strings.Contains(sd.Msg.GetDefinitionJson(), `"vc+sd-jwt"`) {
		t.Errorf("sd-jwt = %v %v", sd, err)
	}
	for _, bad := range []*backendv1.SetPresentationRequirementRequest{
		{Format: commonv1.Format_FORMAT_LDP_VC},
		{CredentialType: "X", Format: commonv1.Format_FORMAT_MSO_MDOC},
		{CredentialType: "X", RequiredClaims: []string{"a.b"}},
	} {
		_, errErr := svc.SetPresentationRequirement(context.Background(), connect.NewRequest(bad))
		wantCode(t, errErr, connect.CodeInvalidArgument)
	}
	cleared, err := svc.SetPresentationRequirement(context.Background(), connect.NewRequest(&backendv1.SetPresentationRequirementRequest{Clear: true}))
	if err != nil || cleared.Msg.GetDefinitionJson() != "" {
		t.Fatalf("clear = %v %v", cleared, err)
	}
	if _, ok := svc.PresentationDefinition(context.Background()); ok {
		t.Error("the definition stays after a clear")
	}
	off, _ := newService(t, both)
	_, err = off.SetPresentationRequirement(context.Background(), connect.NewRequest(&backendv1.SetPresentationRequirementRequest{CredentialType: "X"}))
	wantCode(t, err, connect.CodeFailedPrecondition)
}

// TestPresentationFeatureListed lists the feature only with the setting
// and an Inji Certify URL.
func TestPresentationFeatureListed(t *testing.T) {
	has := func(svc *service.Service) bool {
		caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_PRESENTATION_DURING_ISSUANCE)
	}
	on, _ := newServiceWith(t, both, withPresentation)
	off, _ := newService(t, both)
	verifier, _ := newServiceWith(t, roles{verify: true}, withPresentation)
	if !has(on) || has(off) || has(verifier) {
		t.Fatalf("listed: on %v, off %v, verifier only %v", has(on), has(off), has(verifier))
	}
}

// TestOfferIssuerFollowsTheAuthorizationServer: Certify 0.14.0 checks
// every access token against one issuer, so the stack runs one Certify
// that is its own authorization server and one that takes eSignet
// tokens (P6-I0). An offer through eSignet names the Certify of
// VCA_INJI_OFFER_ISSUER. An offer with a presentation during issuance
// names the Certify whose interactive server gives the code: the one of
// the metadata, whatever VCA_INJI_OFFER_ISSUER says.
func TestOfferIssuerFollowsTheAuthorizationServer(t *testing.T) {
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) {
		withPresentation(o)
		o.OfferIssuer = "http://inji-certify-nginx:8091"
	})
	setRequirement(t, svc)
	issuerOf := func(requirePresentation bool) string {
		t.Helper()
		resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: presentationSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE, RequirePresentation: requirePresentation,
		}))
		if err != nil {
			t.Fatalf("CreateOffer: %v", err)
		}
		document, ok := svc.HostedOffer(context.Background(), resp.Msg.GetOfferId())
		if !ok {
			t.Fatal("the adapter does not host the offer")
		}
		var offer struct {
			Issuer string `json:"credential_issuer"`
		}
		if err := json.Unmarshal([]byte(document), &offer); err != nil {
			t.Fatal(err)
		}
		return offer.Issuer
	}
	if got := issuerOf(false); got != "http://inji-certify-nginx:8091" {
		t.Errorf("the eSignet offer names %q", got)
	}
	if got := issuerOf(true); got != "https://inji-certify.example.org" {
		t.Errorf("the presentation offer names %q, want the credential issuer of the Certify metadata", got)
	}
}
