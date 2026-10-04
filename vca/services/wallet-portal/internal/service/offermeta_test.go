// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// TestOfferNamesTheIssuerAndTheClaims reads the issuer metadata of an
// offer in each shape: the claim list of OID4VCI 1.0, the claim map of
// draft 13 with an mDoc namespace, and the credentialSubject of a W3C
// configuration. An unreadable document leaves the summary unread.
func TestOfferNamesTheIssuerAndTheClaims(t *testing.T) {
	offer := "openid-credential-offer://?credential_offer=" +
		`%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%2C%22credential_configuration_ids%22%3A%5B%22a%22%2C%22b%22%2C%22c%22%2C%22d%22%5D%7D`
	meta := `{"display":[{"name":"Licensing Office","locale":"en"}],"credential_configurations_supported":{` +
		`"a":{"display":[{"name":"Licence","locale":"en"}],"claims":[{"path":["given_name"],"display":[{"name":"Given name"}]},{"path":["address",0]}]},` +
		`"b":{"claims":{"org.iso.18013.5.1":{"family_name":{"display":[{"name":"Family name"}]},"age":{"mandatory":true}},"plain":{}}},` +
		`"c":{"credential_definition":{"credentialSubject":{"degree":{"display":[{"name":"Degree"}]}}}},` +
		`"x":{}}}`
	for name, tc := range map[string]struct {
		fetch      func(context.Context, string) ([]byte, error)
		read       bool
		issuerName string
		types      []string
		claims     []string
	}{
		"read": {
			fetch:      func(context.Context, string) ([]byte, error) { return []byte(meta), nil },
			read:       true,
			issuerName: "Agency A",
			types:      []string{"Licence", "b", "c"},
			claims:     []string{"Given name", "age", "Family name", "plain", "Degree"},
		},
		"unread": {
			fetch:      func(context.Context, string) ([]byte, error) { return nil, errors.New("down") },
			issuerName: "Agency A",
		},
	} {
		svc := build(t, func(o *service.Options) {
			o.RequestHosts = []string{"issuer.example"}
			o.Fetch = tc.fetch
		})
		resp, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: offer}))
		if err != nil {
			t.Fatal(err)
		}
		got := resp.Msg.GetDetected().GetOffer()
		var types []string
		for _, d := range got.GetDisplay() {
			types = append(types, d.GetName())
		}
		if got.GetMetadataRead() != tc.read || got.GetIssuerName() != tc.issuerName ||
			!slices.Equal(types, tc.types) || !slices.Equal(got.GetClaims(), tc.claims) {
			t.Errorf("%s: offer = %+v", name, got)
		}
	}
}
