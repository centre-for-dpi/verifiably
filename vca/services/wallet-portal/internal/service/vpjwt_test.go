// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// TestBrowserStoreSignsAVPJWTForJwtVcJson is ADR-083 decision 5: the
// browser store binds a jwt_vc_json credential that names the browser
// key. The portal hands the browser the signing input of a VP JWT, the
// browser signs it, and the verifier gets a VP JWT whose holder binding
// core/policy accepts with the audience and the nonce of the request.
func TestBrowserStoreSignsAVPJWTForJwtVcJson(t *testing.T) {
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	stack := newClaimStack(t)
	stack.offer = `{"credential_issuer":"` + claimIssuer + `","credential_configuration_ids":["licence_jwt"],` +
		`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code-1","tx_code":{"length":4}}}}`
	stack.metadata = `{"credential_issuer":"` + claimIssuer + `","credential_endpoint":"` + claimEndpoint + `",` +
		`"credential_configurations_supported":{"licence_jwt":{"format":"jwt_vc_json","credential_definition":{"type":["VerifiableCredential","DriverLicence"]}}}}`
	stack.issue = func(jwk map[string]any) string {
		signed, serr := jose.Sign(issuer, "issuer-key", "JWT", map[string]any{
			"iss": claimIssuer, "sub": "urn:holder", "cnf": map[string]any{"jwk": jwk},
			"vc": map[string]any{"type": []string{"VerifiableCredential", "DriverLicence"}, "credentialSubject": map[string]any{"given_name": "Wanjiku"}},
		})
		if serr != nil {
			t.Fatal(serr)
		}
		return signed
	}
	stack.request = jwtRequest(t)
	svc := browserStore(t, stack)
	browser := newBrowserHolder(t)
	step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput)); ferr != nil {
		t.Fatal(ferr)
	}
	req := consent(t, svc)
	input, err := svc.BindingInput(ctx(), req)
	if err != nil || input == "" {
		t.Fatalf("BindingInput = %q, %v; a jwt_vc_json credential bound to the browser key needs a VP JWT", input, err)
	}
	// A VP JWT that the browser did not sign is refused.
	req.KeyBinding = input + "." + newBrowserHolder(t).sign(t, input)
	if _, cerr := svc.PresentConfirm(ctx(), connect.NewRequest(req)); connect.CodeOf(cerr) != connect.CodeInvalidArgument {
		t.Fatalf("a VP JWT of another key: %v", cerr)
	}
	req = consent(t, svc)
	req.KeyBinding = input + "." + browser.sign(t, input)
	if _, cerr := svc.PresentConfirm(ctx(), connect.NewRequest(req)); cerr != nil {
		t.Fatalf("PresentConfirm: %v", cerr)
	}
	token := stack.posted.Get("vp_token")
	payload, err := jose.PeekPayload(token)
	if err != nil || payload["vp"] == nil {
		t.Fatalf("the answer %q is no VP JWT: %v", token, err)
	}
	vp, ok := payload["vp"].(map[string]any)
	if !ok {
		t.Fatalf("vp = %v", payload["vp"])
	}
	creds := vc.AsStringSlice(vp["verifiableCredential"])
	parsed, err := vc.Parse([]byte(creds[0]))
	if err != nil {
		t.Fatal(err)
	}
	p := policy.Presentation{Carrier: policy.CarrierOID4VP, Envelopes: []string{token},
		Credentials: []policy.Credential{{Format: vc.FormatJWT, Token: creds[0], VC: parsed}}}
	pc := policy.Context{Now: time.Now(), Audience: "https://verifier.example", Nonce: "n-1"}
	for _, check := range policy.Checks() {
		if check.Name != policy.NameKeyBinding && check.Name != policy.NameAudience && check.Name != policy.NameNonce {
			continue
		}
		for _, r := range check.Run(context.Background(), p, pc) {
			if r.Result != policy.Pass {
				t.Errorf("%s: %s (%s)", r.Name, r.Result, r.Detail)
			}
		}
	}
}

// jwtRequest asks for the given name of a jwt_vc_json driver licence.
func jwtRequest(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"client_id": "https://verifier.example", "nonce": "n-1", "state": "s-1",
		"response_uri": "https://verifier.example/direct_post",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "licence", "format": "jwt_vc_json",
			"meta":   map[string]any{"type_values": [][]string{{"VerifiableCredential", "DriverLicence"}}},
			"claims": []any{map[string]any{"path": []string{"credentialSubject", "given_name"}}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
