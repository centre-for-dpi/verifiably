// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/disclosure"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// plainClaimFixture returns an SD-JWT whose payload carries the claim
// identityQR in the clear, beside two disclosures. A Certify template
// that left the code out of sdClaim issued such a credential.
func plainClaimFixture(t *testing.T) string {
	t.Helper()
	payload := map[string]any{
		"vct": "DriverLicence", "iss": "did:web:issuer.example",
		"given_name": "Ada", "birth_date": "1990-01-01", "identityQR": "NCF-CODE",
	}
	concealed, discs, err := sdjwt.Conceal(payload, []string{"given_name", "birth_date"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(concealed)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
	for _, d := range discs {
		token += "~" + d.Encoded
	}
	return token + "~"
}

// TestConsentEqualsDisclosure reproduces the presentation of an SD-JWT
// with a claim outside any disclosure (proof run, Inji steps 085 to
// 087). The verifier asks for one claim. The consent screen must list
// every claim the verifier receives, and the history must name exactly
// the claims that left the wallet.
func TestConsentEqualsDisclosure(t *testing.T) {
	var seen url.Values
	svc := build(t, func(o *service.Options) {
		o.Fetch = fetchRequest
		o.Post = func(_ context.Context, _ string, form url.Values) ([]byte, error) {
			seen = form
			return []byte(`{}`), nil
		}
	})
	held, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: plainClaimFixture(t)}))
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	disclosed := map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{}
	for _, entry := range start.Msg.GetRequested() {
		paths := &walletportalv1.PresentConfirmRequest_ClaimPaths{}
		for _, c := range entry.GetClaims() {
			listed = append(listed, c.GetPath())
			// The holder ticks what the screen offers; a claim that
			// always goes stays ticked and locked.
			paths.Paths = append(paths.Paths, c.GetPath())
			if c.GetPath() == "identityQR" && (!c.GetAlwaysSent() || !c.GetMandatory() || c.GetValue() != "NCF-CODE") {
				t.Errorf("identityQR is listed as %+v, want always sent, locked, with its value", c)
			}
		}
		disclosed[entry.GetQueryId()] = paths
	}
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: start.Msg.GetPresentationId(),
		SelectedCards:  map[string]string{"licence": held.Msg.GetDetected().GetOfferId()},
		Disclosed:      disclosed,
	}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := vc.Parse([]byte(seen.Get("vp_token")))
	if err != nil {
		t.Fatal(err)
	}
	var received []string
	for name := range got.Claims {
		received = append(received, name)
	}
	sort.Strings(received)
	sort.Strings(listed)
	if !slices.Equal(listed, received) {
		t.Fatalf("the consent screen listed %v, the verifier received %v", listed, received)
	}
	recorded := slices.Clone(confirm.Msg.GetRecord().GetClaims())
	sort.Strings(recorded)
	if !slices.Equal(recorded, received) {
		t.Fatalf("the history names %v, the verifier received %v", recorded, received)
	}
}

// TestConsentOfAStackWalletThatSendsCredentialsWhole lists the whole
// credential as always sent when the stack wallet takes no choice of
// claims (FEATURE_WALLET_WHOLE_CREDENTIAL).
func TestConsentOfAStackWalletThatSendsCredentialsWhole(t *testing.T) {
	svc := build(t, func(o *service.Options) {
		o.Holder = &fakeHolder{credential: credential(t), accepted: true}
		o.Fetch = fetchRequest
		o.WholeCredential = func(context.Context) bool { return true }
	})
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	claims := start.Msg.GetRequested()[0].GetClaims()
	last := claims[len(claims)-1]
	if last.GetPath() != disclosure.Whole || !last.GetAlwaysSent() || !claims[0].GetMandatory() {
		t.Fatalf("claims = %+v, want the whole credential last and each claim locked", claims)
	}
}

// TestConsentOfAWholeQueryWithNoClaim lists each claim of the stack
// credential when the query names none, as the stack wallet sends them
// all (FEATURE_WALLET_WHOLE_QUERY).
func TestConsentOfAWholeQueryWithNoClaim(t *testing.T) {
	svc := build(t, func(o *service.Options) {
		o.Holder = &fakeHolder{credential: credential(t), accepted: true}
		o.WholeQuery = func(context.Context) bool { return true }
		o.Fetch = func(context.Context, string) ([]byte, error) {
			return []byte(`{"client_id":"https://verifier.example","nonce":"n","response_uri":"https://verifier.example/p",` +
				`"dcql_query":{"credentials":[{"id":"licence","format":"dc+sd-jwt","meta":{"vct_values":["DriverLicence"]}}]}}`), nil
		}
	})
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range start.Msg.GetRequested()[0].GetClaims() {
		if !c.GetAlwaysSent() {
			t.Errorf("%s is not marked always sent", c.GetPath())
		}
		names = append(names, c.GetPath())
	}
	if strings.Join(names, ",") != "birth_date,given_name" {
		t.Fatalf("claims = %v, want each claim of the credential", names)
	}
}
