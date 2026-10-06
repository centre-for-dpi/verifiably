// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
)

// claim169Code signs a CWT with claim 169 as a COSE_Sign1 message with
// the key of the test issuer, as an issuer signs an identity QR code.
func (f fixture) claim169Code(t *testing.T) []byte {
	t.Helper()
	claims, err := cbor.Marshal(map[int64]any{
		1: "did:web:issuer", 6: testNow.Unix(), 169: map[int64]any{4: "Wanjiku Njeri", 9: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	alg, sign, err := token.KeySigner(f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int64]any{1: alg, 4: "issuer-key"})
	if err != nil {
		t.Fatal(err)
	}
	toSign, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, claims})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(toSign)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, claims, sig}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestToPresentationReadsAClaim169Code reads the code of an uploaded QR
// image. The ingestion service names no proto format for it, so the
// service detects it, and the view names the issuer and the claims.
func TestToPresentationReadsAClaim169Code(t *testing.T) {
	f := newFixture(t)
	got := ToPresentation(&ingestv1.RawPresentation{
		Carrier:     ingestv1.Carrier_CARRIER_IMAGE,
		Credentials: []*commonv1.Credential{{Payload: f.claim169Code(t)}},
	})
	c := got.Credentials[0]
	if c.Format != vc.FormatClaim169 || c.VC.Issuer != "did:web:issuer" || c.VC.Claims["Full Name"] != "Wanjiku Njeri" || c.Token == "" {
		t.Fatalf("credential = %+v", c)
	}
}

// TestEvaluateAClaim169Code checks a Claim 169 code with the key of its
// issuer. The signature passes, the issuer is trusted, and the verdict
// is valid.
func TestEvaluateAClaim169Code(t *testing.T) {
	f := newFixture(t)
	resp, err := f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: &ingestv1.RawPresentation{
			Carrier:      ingestv1.Carrier_CARRIER_QR_CLAIM169,
			DetectedType: ingestv1.DetectedType_DETECTED_TYPE_CWT_CLAIM169,
			Credentials:  []*commonv1.Credential{{Payload: f.claim169Code(t)}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]policyv1.Outcome{}
	for _, c := range resp.Msg.GetChecks() {
		if c.GetCredentialIndex() == 0 {
			outcomes[c.GetName()] = c.GetOutcome()
		}
	}
	if outcomes[policy.NameSignature] != policyv1.Outcome_OUTCOME_PASS || outcomes[policy.NameTrustChain] != policyv1.Outcome_OUTCOME_PASS {
		t.Fatalf("checks = %v", resp.Msg.GetChecks())
	}
	if resp.Msg.GetVerdict() != policyv1.EvaluateResponse_VERDICT_VALID {
		t.Fatalf("verdict = %s: %v", resp.Msg.GetVerdict(), resp.Msg.GetChecks())
	}
}
