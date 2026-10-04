// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/consenttest"
)

// sdJwtHeld is the SD-JWT of wallet-credentials-sd-jwt.json. It carries
// residentSince in the clear and fullName and city in disclosures.
const sdJwtHeld = "urn:uuid:7a1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"

// TestStackWalletConsentEqualsDisclosure is the guard of ADR-081 for the
// walt.id wallet. walt.id appends the strings of the disclosure map to
// the document, so the adapter must send the encoded disclosures of the
// ticked claims, and residentSince travels with every answer.
func TestStackWalletConsentEqualsDisclosure(t *testing.T) {
	svc, f := newService(t, all)
	walletID := registerWallet(t, svc)
	f.SetHeld("wallet-credentials-sd-jwt.json")
	ask := func(claims ...string) *backendv1.PresentRequest {
		return &backendv1.PresentRequest{WalletId: walletID, RequestUri: "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier",
			CredentialIds: []string{sdJwtHeld}, DisclosedClaims: claims}
	}
	consenttest.Run(t, consenttest.Exchange{
		Present: func(ctx context.Context, req *backendv1.PresentRequest) (*backendv1.PresentResponse, error) {
			res, err := svc.Present(ctx, connect.NewRequest(req))
			if err != nil {
				return nil, err
			}
			return res.Msg, nil
		},
		Narrow: ask("fullName"),
		Full:   ask("fullName", "residentSince"),
		Sent:   f.Presented,
		Reset:  f.Forget,
	})
}
