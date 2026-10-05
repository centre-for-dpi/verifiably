// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"encoding/base64"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
)

// TestBrowserStoreClaimsJwtVcJsonAndMdoc claims a credential of each
// format a stack issues besides SD-JWT into the browser store. The
// credential request names the format of the configuration with its
// type or its doctype, the browser signs the proof, and the store holds
// the credential under its format.
func TestBrowserStoreClaimsJwtVcJsonAndMdoc(t *testing.T) {
	issuer, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	// An IssuerSigned structure starts with a CBOR map of two entries.
	mdoc := base64.RawURLEncoding.EncodeToString([]byte{0xa2, 0x6a, 'n', 'a', 'm', 'e', 'S', 'p', 'a', 'c', 'e', 's', 0xa0,
		0x6a, 'i', 's', 's', 'u', 'e', 'r', 'A', 'u', 't', 'h', 0x80})
	for _, c := range []struct {
		config, cfg string
		issue       func(jwk map[string]any) string
		want        commonv1.Format
		field       string
	}{
		{
			config: "licence_jwt", cfg: `{"format":"jwt_vc_json","credential_definition":{"type":["VerifiableCredential","DriverLicence"]}}`,
			issue: func(jwk map[string]any) string {
				signed, serr := jose.Sign(issuer, "issuer-key", "JWT", map[string]any{
					"iss": claimIssuer, "sub": "did:jwk:holder", "cnf": map[string]any{"jwk": jwk},
					"vc": map[string]any{"type": []string{"VerifiableCredential", "DriverLicence"}, "credentialSubject": map[string]any{"given_name": "Wanjiku"}},
				})
				if serr != nil {
					t.Fatal(serr)
				}
				return signed
			},
			want: commonv1.Format_FORMAT_JWT_VC_JSON, field: "credential_definition",
		},
		{
			config: "licence_mdoc", cfg: `{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"}`,
			issue: func(map[string]any) string { return mdoc },
			want:  commonv1.Format_FORMAT_MSO_MDOC, field: "doctype",
		},
	} {
		stack := newClaimStack(t)
		stack.offer = `{"credential_issuer":"` + claimIssuer + `","credential_configuration_ids":["` + c.config + `"],` +
			`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code-1","tx_code":{"length":4}}}}`
		stack.metadata = `{"credential_issuer":"` + claimIssuer + `","credential_endpoint":"` + claimEndpoint + `",` +
			`"credential_configurations_supported":{"` + c.config + `":` + c.cfg + `}}`
		stack.issue = c.issue
		svc := browserStore(t, stack)
		browser := newBrowserHolder(t)
		step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
		if err != nil {
			t.Fatalf("%s: ClaimStart: %v", c.config, err)
		}
		got, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput))
		if err != nil {
			t.Fatalf("%s: ClaimFinish: %v", c.config, err)
		}
		req := stack.requests[0]
		if req["credential_configuration_id"] != c.config || req[c.field] == nil {
			t.Errorf("%s: the credential request %v names no %s", c.config, req, c.field)
		}
		held, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if got.Format != c.want || len(held.Msg.GetCards()) != 1 || !held.Msg.GetCards()[0].GetInBrowser() ||
			held.Msg.GetCards()[0].GetFormat() != c.want {
			t.Errorf("%s: claimed %s, held %v", c.config, got.Format, held.Msg.GetCards())
		}
	}
}
