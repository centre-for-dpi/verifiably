// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
)

// boardOfferings are the rows of board Holder-Discover: one issuer on
// the trust list with both ways to claim, one with the code only, and
// one not on the list with the sign in only.
func boardOfferings() []*walletportalv1.Offering {
	return []*walletportalv1.Offering{
		{CredentialIssuer: "https://health.example", IssuerName: "Ministry of Health", Trust: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
			Schema: &schemav1.PublicSchema{Id: "nurse", Type: "NurseLicence", Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
				Display: []*schemav1.Display{{Name: "Nurse licence"}}},
			ClaimMethods: []walletportalv1.ClaimMethod{walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE, walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE}},
		{CredentialIssuer: "https://farm.example", IssuerName: "Ministry of Agriculture", Trust: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
			Schema:       &schemav1.PublicSchema{Id: "farmer", Type: "FarmerRegistration", Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}},
			ClaimMethods: []walletportalv1.ClaimMethod{walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE}},
		{CredentialIssuer: "https://county.example", IssuerName: "County Licensing Office", Trust: trustv1.TrustLookupResponse_OUTCOME_UNKNOWN,
			Schema:       &schemav1.PublicSchema{Id: "trade", Type: "TradeLicence", Formats: []commonv1.Format{commonv1.Format_FORMAT_MSO_MDOC}},
			ClaimMethods: []walletportalv1.ClaimMethod{walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE}},
	}
}

// TestDiscoverFollowsTheBoard checks the discover page of board
// Holder-Discover: the issuer and its trust, the credential, the format,
// how to claim, and a claim link per row.
func TestDiscoverFollowsTheBoard(t *testing.T) {
	h := setupShell(t, func(o *serviceOptions) {
		o.Catalogue = ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) { return boardOfferings(), nil })
	}, holderDeployment())
	rec := h.get(t, "/wallet/discover")
	body := rec.Body.String()
	for _, want := range []string{
		"Discover and claim", "Issuers on this deployment publish what they offer.",
		"Ministry of Health", "On the trust list", "Nurse licence", "SD-JWT VC", "Sign in at issuer · Code",
		"FarmerRegistration", "JSON-LD", ">Code<",
		"County Licensing Office", "Not on the list", "mdoc", ">Sign in at issuer<",
		`href="/wallet/discover?claim=1#claim"`, `href="/wallet/discover?claim=3#claim"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("discover misses %s\n%s", want, body)
		}
	}
}
