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
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// withPresentation turns presentation during issuance on.
func withPresentation(o *serviceOptions) { o.PresentationDuringIssuance = true }

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
	resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, RequirePresentation: true,
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
		return connect.NewRequest(&backendv1.CreateOfferRequest{Spec: farmerSpec(), RequirePresentation: true})
	}
	off, _ := newService(t, both)
	_, err := off.CreateOffer(context.Background(), req())
	wantCode(t, err, connect.CodeFailedPrecondition)

	on, f := newServiceWith(t, both, withPresentation)
	_, err = on.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: farmerSpec(), RequirePresentation: true, Channel: backendv1.Channel_CHANNEL_PDF,
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
	f.SetStatus(fake.ASMetadataPath, http.StatusNotFound)
	_, err = on.CreateOffer(context.Background(), req())
	wantCode(t, err, connect.CodeFailedPrecondition)

	noURL, _ := newServiceWith(t, both, func(o *service.Options) {
		withPresentation(o)
		o.PublicURL = ""
	})
	_, err = noURL.CreateOffer(context.Background(), req())
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
	issuerOf := func(requirePresentation bool) string {
		t.Helper()
		resp, err := svc.CreateOffer(context.Background(), connect.NewRequest(&backendv1.CreateOfferRequest{
			Spec: farmerSpec(), Channel: backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE, RequirePresentation: requirePresentation,
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
