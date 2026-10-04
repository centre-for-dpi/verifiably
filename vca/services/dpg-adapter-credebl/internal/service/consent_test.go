// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/internal/consenttest"
)

// TestStackWalletConsentEqualsDisclosure is the guard of ADR-081 for the
// CREDEBL agent (proof run, CREDEBL steps 182 to 184). The holder
// consents to fullName. The stored SD-JWT carries contactEmail and
// residentSince outside any disclosure, so the agent sends both with
// every answer.
func TestStackWalletConsentEqualsDisclosure(t *testing.T) {
	svc, agent, _ := newHolder(t, nil)
	wallet := registerHolder(t, svc)
	agent.SetResolved(fake.Oid4vpResolvedPlainClaims)
	request := "openid4vp://?client_id=x509_san_dns%3Averifier.example.org&request_uri=https%3A%2F%2Fverifier.example.org%2Frequest%2F1"
	ask := func(claims ...string) *backendv1.PresentRequest {
		return &backendv1.PresentRequest{WalletId: wallet, RequestUri: request,
			CredentialIds: []string{"sd-jwt:" + fake.SdJwtRecord}, DisclosedClaims: claims}
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
		Full:   ask("fullName", "contactEmail", "residentSince"),
		Sent:   agent.Presented,
		Reset:  agent.Forget,
	})
}
