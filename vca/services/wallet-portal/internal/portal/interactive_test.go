// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestWalletPagesAnswerPresentationDuringIssuance claims an offer whose
// issuer asks for a presentation first: the claim goes to the consent
// screen, which says so, and sharing the credential brings the new one.
func TestWalletPagesAnswerPresentationDuringIssuance(t *testing.T) {
	const server = "https://certify.example/v1/certify"
	holder := &recordingHolder{fakeHolder: fakeHolder{credential: credential(t)}}
	h := setupShell(t, func(o *serviceOptions) {
		o.Holder = holder
		o.RequestHosts = []string{"issuer-inji.vca.example"}
		o.Fetch = func(context.Context, string) ([]byte, error) {
			return []byte(`{"credential_issuer":"https://certify.example","credential_configuration_ids":["FarmerCredential"],` +
				`"grants":{"authorization_code":{"issuer_state":"st","authorization_server":"` + server + `"}}}`), nil
		}
		o.Servers = func(context.Context, string) (issuers.Endpoints, error) {
			return issuers.Endpoints{Token: server + "/oauth/token", Interactive: server + "/oauth/iar"}, nil
		}
		o.Post = func(_ context.Context, address string, form url.Values) ([]byte, error) {
			switch {
			case strings.HasSuffix(address, "/token"):
				return []byte(`{"access_token":"at-iar"}`), nil
			case form.Get("auth_session") != "":
				return []byte(`{"status":"ok","code":"iar_auth_1"}`), nil
			}
			return json.Marshal(map[string]any{"status": "require_interaction", "type": "openid4vp_presentation", "auth_session": "s",
				"openid4vp_request": map[string]any{"response_mode": "iar-post", "client_id": "did:web:verify.example", "nonce": "n",
					"response_uri": server + "/oauth/iar", "presentation_definition": map[string]any{"id": "d", "input_descriptors": []any{
						map[string]any{"id": "licence", "constraints": map[string]any{"fields": []any{
							map[string]any{"path": []string{"$.vct"}, "filter": map[string]any{"const": "DriverLicence"}},
							map[string]any{"path": []string{"$.given_name"}}}}}}}}})
		}
	}, holderDeployment())
	offer := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape("https://issuer-inji.vca.example/offers/o1")
	rec := h.post(t, "/wallet/claim/offer", url.Values{"offer": {offer}})
	next := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(next, "/wallet/present?id=") || holder.offer != "" {
		t.Fatalf("status = %d location = %q", rec.Code, next)
	}
	page := h.get(t, strings.TrimSuffix(next, "#request"))
	body := page.Body.String()
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "The issuer asks you to show a credential before it gives you the new one.") ||
		!strings.Contains(body, "Request from Agency A") {
		t.Fatalf("consent screen = %s", body)
	}
	id, err := url.Parse(next)
	if err != nil {
		t.Fatal(err)
	}
	done := h.post(t, "/wallet/present", url.Values{"id": {id.Query().Get("id")}, "card.licence": {"c1"}, "claim.licence": {"given_name"}})
	out := done.Body.String()
	a11ytest.AssertPage(t, out)
	if !strings.Contains(out, "Credential received") || holder.grant != "at-iar" || holder.offer != offer {
		t.Fatalf("outcome = %d %s, grant %q", done.Code, out, holder.grant)
	}
}
