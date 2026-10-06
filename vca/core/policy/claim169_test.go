// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"crypto"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// claim169Kid is the key id of the code: the DID URL of the issuer key.
const claim169Kid = "did:web:certify.example#key-0"

// claim169Cred signs a CWT with claim 169 as a COSE_Sign1 message with
// key, and reads it as the ingestion service hands it over.
func claim169Cred(t *testing.T, key crypto.PrivateKey) Credential {
	t.Helper()
	claims, err := cbor.Marshal(map[int64]any{
		1: "did:web:certify.example", 6: testNow.Unix(),
		169: map[int64]any{4: "Wanjiku Njeri", 8: "1987-04-12", 9: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	alg, sign, err := token.KeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int64]any{1: alg, 4: claim169Kid})
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
	raw, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, claims, sig}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := vc.Parse(raw)
	if err != nil {
		t.Fatalf("vc.Parse: %v", err)
	}
	return Credential{Format: vc.DetectFormat(raw), Token: string(raw), VC: parsed}
}

// claim169Keys answers with the public key of key under the kid of the
// code, for the issuer of the code only.
func claim169Keys(t *testing.T, key crypto.PrivateKey, kid string) KeyResolver {
	t.Helper()
	k, err := jose.PublicJWK(key, kid)
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, issuer, gotKid string) (jose.JWKS, error) {
		if issuer != "did:web:certify.example" || gotKid != claim169Kid {
			t.Errorf("the resolver got the issuer %q and the kid %q", issuer, gotKid)
		}
		return jose.JWKS{Keys: []jose.JWK{k}}, nil
	}
}

// TestSignatureVerifiesAClaim169Code checks the COSE signature of a Claim
// 169 code with the key the issuer publishes, found by the same resolver
// as a JWT: the iss claim and the kid of the protected header.
func TestSignatureVerifiesAClaim169Code(t *testing.T) {
	for _, alg := range []jose.Algorithm{jose.EdDSA, jose.ES256} {
		key, err := jose.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		c := claim169Cred(t, key)
		if c.Format != vc.FormatClaim169 || c.VC.Issuer != "did:web:certify.example" {
			t.Fatalf("%s: the code reads as %q from %q", alg, c.Format, c.VC.Issuer)
		}
		pc := base()
		pc.Keys = claim169Keys(t, key, claim169Kid)
		got := only(t, signature(context.Background(), pres(c), pc))
		wantOutcome(t, got, Pass)
		if got.Evidence["alg"] != string(alg) || got.Evidence["kid"] != claim169Kid || got.Evidence["format"] != "claim169" {
			t.Fatalf("%s: evidence = %v", alg, got.Evidence)
		}

		// Another key of the same kid does not verify it.
		other, err := jose.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		pc.Keys = claim169Keys(t, other, claim169Kid)
		wantOutcome(t, only(t, signature(context.Background(), pres(c), pc)), Fail)

		// A key set without the kid gives an error, as for a JWT.
		pc.Keys = func(context.Context, string, string) (jose.JWKS, error) {
			k, kerr := jose.PublicJWK(key, "another-key")
			if kerr != nil {
				t.Fatal(kerr)
			}
			return jose.JWKS{Keys: []jose.JWK{k}}, nil
		}
		wantOutcome(t, only(t, signature(context.Background(), pres(c), pc)), Error)
	}
}

// TestSignatureOfABrokenClaim169Code fails a code whose bytes no longer
// read as a signed CWT.
func TestSignatureOfABrokenClaim169Code(t *testing.T) {
	broken := Credential{Format: vc.FormatClaim169, Token: "not a code"}
	pc := base()
	pc.Keys = func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, nil }
	got := only(t, signature(context.Background(), pres(broken), pc))
	wantOutcome(t, got, Fail)

	// Without a key resolver the check cannot run.
	key, err := jose.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, only(t, signature(context.Background(), pres(claim169Cred(t, key)), base())), Error)
}

// TestEvaluateAClaim169Code runs every mandatory check on a Claim 169
// code: the signature passes, the trust check reads the issuer of the
// iss claim, and the status check finds no status list.
func TestEvaluateAClaim169Code(t *testing.T) {
	key, err := jose.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	pc := base()
	pc.Keys = claim169Keys(t, key, claim169Kid)
	pc.Trust = func(_ context.Context, issuer, _ string) (Trust, error) {
		return Trust{Trusted: issuer == "did:web:certify.example", DisplayName: "Certify"}, nil
	}
	set := Set{Settings: []Setting{{Name: NameStatus, Blocking: true}, {Name: NameTrustChain, Blocking: true}}}
	report := Evaluate(context.Background(), Presentation{Carrier: CarrierClaim169, Credentials: []Credential{claim169Cred(t, key)}}, pc, set)
	outcomes := map[string]Outcome{}
	for _, r := range report.Results {
		if r.CredentialIndex == 0 {
			outcomes[r.Name] = r.Result
		}
	}
	if outcomes[NameSignature] != Pass || outcomes[NameTrustChain] != Pass || outcomes[NameStatus] != Skip {
		t.Fatalf("outcomes = %v", outcomes)
	}
	if report.Verdict != Valid {
		t.Fatalf("verdict = %v, results %+v", report.Verdict, report.Results)
	}
}
