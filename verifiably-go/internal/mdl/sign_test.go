package mdl

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"github.com/verifiably/verifiably-go/internal/mdl/pki"
	"github.com/verifiably/verifiably-go/internal/signer"
)

// testSigner builds a real IACA→DSC chain and a signer over the DSC key.
func testSigner(t *testing.T) signer.Signer {
	t.Helper()
	iacaKey, iaca, err := pki.GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	dscKey, dsc, err := pki.GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	s, err := signer.NewSoftwareSigner(dscKey, []*x509.Certificate{dsc, iaca})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func TestValidateValidityInfoRejectsValidUntilBeyondExpiryDate(t *testing.T) {
	issue := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := ValidityInfo{
		Signed:     TDate(issue),
		ValidFrom:  TDate(issue),
		ValidUntil: TDate(expiry.Add(24 * time.Hour)), // one day too far
	}
	if err := ValidateValidityInfo(v, issue, expiry); err == nil {
		t.Fatal("expected error: validUntil must not exceed expiry_date")
	}
}

func TestValidateValidityInfoRejectsValidFromBeforeIssueDate(t *testing.T) {
	issue := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := ValidityInfo{
		Signed:     TDate(issue),
		ValidFrom:  TDate(issue.Add(-24 * time.Hour)),
		ValidUntil: TDate(expiry),
	}
	if err := ValidateValidityInfo(v, issue, expiry); err == nil {
		t.Fatal("expected error: validFrom must not precede issue_date")
	}
}

func TestValidateValidityInfoAcceptsValidWindow(t *testing.T) {
	issue := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := ValidityInfo{
		Signed:     TDate(issue),
		ValidFrom:  TDate(issue),
		ValidUntil: TDate(expiry),
	}
	if err := ValidateValidityInfo(v, issue, expiry); err != nil {
		t.Fatalf("expected valid window to be accepted: %v", err)
	}
}

func TestBuildMSORequiresDeviceKey(t *testing.T) {
	// Without deviceKey the credential is clonable, so this must be an error
	// rather than an omitted field.
	if _, err := BuildMSO(map[uint][]byte{0: {1, 2, 3}}, nil, ValidityInfo{}); err == nil {
		t.Fatal("expected error when deviceKey is absent")
	}
}

func TestSignMSOProducesVerifiableCOSESign1WithX5Chain(t *testing.T) {
	s := testSigner(t)
	now := time.Now().UTC()
	deviceKey := cbor.RawMessage{0xa0} // empty map: a placeholder COSE_Key

	mso, err := BuildMSO(
		map[uint][]byte{0: make([]byte, 32)},
		deviceKey,
		ValidityInfo{
			Signed:     TDate(now),
			ValidFrom:  TDate(now),
			ValidUntil: TDate(now.Add(24 * time.Hour)),
		},
	)
	if err != nil {
		t.Fatalf("build MSO: %v", err)
	}

	issuerAuth, err := SignMSO(context.Background(), s, mso)
	if err != nil {
		t.Fatalf("sign MSO: %v", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(issuerAuth); err != nil {
		t.Fatalf("IssuerAuth must be a COSE_Sign1: %v", err)
	}

	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		t.Fatalf("protected header must carry alg: %v", err)
	}
	if alg != cose.AlgorithmES256 {
		t.Errorf("expected ES256, got %v", alg)
	}

	// Header label 33 is x5chain. A verifier needs the full chain to build a
	// path to the trust anchor.
	x5chain, ok := msg.Headers.Unprotected[int64(33)]
	if !ok {
		if x5chain, ok = msg.Headers.Protected[int64(33)]; !ok {
			t.Fatal("IssuerAuth must carry an x5chain header (label 33)")
		}
	}
	chain, ok := x5chain.([]any)
	if !ok {
		t.Fatalf("x5chain must be an array for multi-certificate chains, got %T", x5chain)
	}
	if len(chain) != 2 {
		t.Errorf("expected DSC and IACA in the chain, got %d entries", len(chain))
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, s.CertificateChain()[0].PublicKey)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		t.Errorf("signature must verify against the DSC public key: %v", err)
	}
}
