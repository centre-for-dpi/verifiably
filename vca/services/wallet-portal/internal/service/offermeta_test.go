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

// TestOfferShowsThePublishedConfigurationOfAGenericEntry covers a stack
// whose issuer metadata lists one generic entry per wire format: the
// offer names the configuration of the schema registry, and the page
// shows its display and its claims. A hint of another format, or no
// hint, leaves the entry id.
func TestOfferShowsThePublishedConfigurationOfAGenericEntry(t *testing.T) {
	offer := "openid-credential-offer://?credential_offer=" +
		`%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%2C%22credential_configuration_ids%22%3A%5B%22vca_dc_sd_jwt%22%5D%7D`
	stack := `{"credential_configurations_supported":{"vca_dc_sd_jwt":{"format":"dc+sd-jwt"}}}`
	published := `{"format":"dc+sd-jwt","display":[{"name":"Proof of residence","locale":"en"}],` +
		`"claims":[{"path":["fullName"],"display":[{"name":"Full name"}]},{"path":["city"],"display":[{"name":"City"}]}]}`
	for name, tc := range map[string]struct {
		hint, published string
		types, claims   []string
	}{
		"hint":         {hint: "ProofOfResidence_dc%2Bsd-jwt", published: published, types: []string{"Proof of residence"}, claims: []string{"Full name", "City"}},
		"other format": {hint: "ProofOfResidence_dc%2Bsd-jwt", published: `{"format":"jwt_vc_json","display":[{"name":"Other"}]}`, types: []string{"vca_dc_sd_jwt"}},
		"unknown":      {hint: "Nothing", types: []string{"vca_dc_sd_jwt"}},
		"no hint":      {published: published, types: []string{"vca_dc_sd_jwt"}},
	} {
		text := offer
		if tc.hint != "" {
			text += "&vca_configuration=" + tc.hint
		}
		svc := build(t, func(o *service.Options) {
			o.RequestHosts = []string{"issuer.example"}
			o.Fetch = func(context.Context, string) ([]byte, error) { return []byte(stack), nil }
			o.Published = func(_ context.Context, id string) ([]byte, bool) {
				if id != "ProofOfResidence_dc+sd-jwt" || tc.published == "" {
					return nil, false
				}
				return []byte(tc.published), true
			}
		})
		resp, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: text}))
		if err != nil {
			t.Fatal(err)
		}
		got := resp.Msg.GetDetected().GetOffer()
		var types []string
		for _, d := range got.GetDisplay() {
			types = append(types, d.GetName())
		}
		if !slices.Equal(types, tc.types) || !slices.Equal(got.GetClaims(), tc.claims) {
			t.Errorf("%s: types %v claims %v, want %v and %v", name, types, got.GetClaims(), tc.types, tc.claims)
		}
	}
}

// TestOfferReadsTheCredentialMetadataOfAConfiguration covers the issuer
// metadata of a stack that nests the display and the claims of each
// configuration under credential_metadata (OID4VCI 1.0 section 12.2.4).
func TestOfferReadsTheCredentialMetadataOfAConfiguration(t *testing.T) {
	offer := "openid-credential-offer://?credential_offer=" +
		`%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%2C%22credential_configuration_ids%22%3A%5B%22ProofOfResidence-sdjwt%22%5D%7D`
	meta := `{"credential_configurations_supported":{"ProofOfResidence-sdjwt":{"format":"dc+sd-jwt",` +
		`"credential_metadata":{"display":[{"name":"Proof of residence","locale":"en"}],` +
		`"claims":[{"path":["fullName"],"display":[{"name":"Full name","locale":"en"}]},{"path":["city"]}]}}}}`
	svc := build(t, func(o *service.Options) {
		o.RequestHosts = []string{"issuer.example"}
		o.Fetch = func(context.Context, string) ([]byte, error) { return []byte(meta), nil }
	})
	resp, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: offer}))
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Msg.GetDetected().GetOffer()
	if len(got.GetDisplay()) != 1 || got.GetDisplay()[0].GetName() != "Proof of residence" ||
		!slices.Equal(got.GetClaims(), []string{"Full name", "city"}) {
		t.Fatalf("offer = %+v", got)
	}
}
