// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/consenttest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/disclosure"
)

// TestStackWalletConsentEqualsDisclosure is the guard of ADR-081 for the
// Mimoto wallet. Mimoto takes the selected credentials and no choice of
// claims, so it sends each credential whole. The holder must consent to
// every claim of it.
func TestStackWalletConsentEqualsDisclosure(t *testing.T) {
	svc, f := newService(t, holder)
	wallet := openWallet(t, svc)
	ask := func(claims ...string) *backendv1.PresentRequest {
		return &backendv1.PresentRequest{WalletId: wallet, RequestUri: "https://verify.inji.example/v1/verify/vp-request/r1",
			CredentialIds: []string{"c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04"}, DisclosedClaims: claims}
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
		Full:   ask("fullName", disclosure.Whole),
		Sent: func() []string {
			if len(f.MimotoPresented()) == 0 {
				return nil
			}
			return []string{disclosure.Whole}
		},
		Reset: f.MimotoForget,
	})
}
