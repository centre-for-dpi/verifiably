// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// holderDID returns the did:jwk of the holder key of b.
func holderDID(t *testing.T, b builder) string {
	t.Helper()
	pub, err := jose.PublicJWK(b.holderKey, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := did.FromJWK(m)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// boundJWT returns a jwt_vc_json credential whose subject is the holder.
func boundJWT(t *testing.T, b builder, subject string) Credential {
	t.Helper()
	return b.jwtCred(t, map[string]any{
		"iss": "did:web:issuer", "sub": subject,
		"vc": map[string]any{"type": []string{"VerifiableCredential", "ResidenceCredential"},
			"credentialSubject": map[string]any{"id": subject, "city": "Demo City"}},
	})
}

// vpJWT signs a VP JWT that carries tokens with key.
func vpJWT(t *testing.T, key any, iss, aud, nonce string, iat time.Time, tokens ...string) string {
	t.Helper()
	list := make([]any, 0, len(tokens))
	for _, tok := range tokens {
		list = append(list, tok)
	}
	signed, err := jose.Sign(key, iss+"#0", "JWT", map[string]any{
		"iss": iss, "aud": aud, "nonce": nonce, "iat": iat.Unix(),
		"vp": map[string]any{"type": []string{"VerifiablePresentation"}, "verifiableCredential": list},
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// unboundMdoc returns an IssuerSigned mDoc, as the browser store sends it.
func unboundMdoc(t *testing.T, deviceSigned bool) Credential {
	t.Helper()
	signed := map[string]any{"nameSpaces": map[string]any{"ns": []any{}}, "issuerAuth": []any{}}
	var doc any = signed
	if deviceSigned {
		doc = map[string]any{"version": "1.0", "documents": []any{map[string]any{
			"docType": "x", "issuerSigned": signed, "deviceSigned": map[string]any{"nameSpaces": cbor.Tag{Number: 24, Content: []byte{0xa0}}},
		}}}
	}
	raw, err := cbor.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return Credential{Format: vc.FormatMdoc, Token: string(raw)}
}

// TestPolicyRequiresHolderBinding is ADR-083: an OID4VP answer in a
// format that can carry holder binding must carry it, unless the policy
// set turns the rule off. The verdict reads Not valid with the reason.
func TestPolicyRequiresHolderBinding(t *testing.T) {
	b := newBuilder(t)
	holder := holderDID(t, b)
	for name, c := range map[string]Credential{
		"jwt_vc_json without a VP JWT":        boundJWT(t, b, holder),
		"mso_mdoc without a device signature": unboundMdoc(t, false),
		"dc+sd-jwt with no holder key":        b.sdjwtCred(t, sdjwtOptions{noHolder: true}),
	} {
		p := Presentation{Carrier: CarrierOID4VP, Credentials: []Credential{c}}
		got := only(t, keyBinding(context.Background(), p, base()))
		if got.Result != Fail || got.Detail != NoHolderBinding {
			t.Errorf("%s: %s (%s), want FAIL with %q", name, got.Result, got.Detail, NoHolderBinding)
		}
		report := Evaluate(context.Background(), p, base(), Set{})
		if report.Verdict != Invalid {
			t.Errorf("%s: verdict %s, want INVALID", name, report.Verdict)
		}
		off := map[string]string{ParamRequireHolderBinding: "false"}
		if r := only(t, keyBinding(context.Background(), p, with(base(), off))); r.Result != Skip {
			t.Errorf("%s: with the rule off: %s (%s), want SKIP", name, r.Result, r.Detail)
		}
		// A pasted or scanned credential is no presentation, so it binds
		// nothing.
		pasted := Presentation{Carrier: "json", Credentials: []Credential{c}}
		if r := only(t, keyBinding(context.Background(), pasted, base())); r.Result != Skip {
			t.Errorf("%s: pasted: %s (%s), want SKIP", name, r.Result, r.Detail)
		}
		// A stack verifier that accepted the answer checked the binding.
		stack := Presentation{Carrier: CarrierOID4VP, Holder: &vc.HolderBinding{Confirmed: true}, Credentials: []Credential{c}}
		if r := only(t, keyBinding(context.Background(), stack, base())); r.Result != Skip || r.Detail != StackCheckedBinding {
			t.Errorf("%s: stack: %s (%s), want SKIP", name, r.Result, r.Detail)
		}
	}
	// An mDoc with a device signature is bound; VCA leaves that check to
	// the stack verifier.
	p := Presentation{Carrier: CarrierOID4VP, Credentials: []Credential{unboundMdoc(t, true)}}
	if r := only(t, keyBinding(context.Background(), p, base())); r.Result != Skip || r.Detail != mdocDeviceSkip {
		t.Errorf("device signed mDoc: %s (%s)", r.Result, r.Detail)
	}
}

// TestPolicyChecksTheVPJWTOfAJwtVcJson verifies the VP JWT a holder
// signs around a jwt_vc_json credential: the key of the subject DID or
// of cnf.jwk signs it, it carries the credential, and the audience and
// nonce checks read it.
func TestPolicyChecksTheVPJWTOfAJwtVcJson(t *testing.T) {
	b := newBuilder(t)
	holder := holderDID(t, b)
	c := boundJWT(t, b, holder)
	good := vpJWT(t, b.holderKey, holder, "verifier", "n1", testNow.Add(-time.Minute), c.Token)
	p := Presentation{Carrier: CarrierOID4VP, Envelopes: []string{good}, Credentials: []Credential{c}}
	pc := base()
	pc.Audience, pc.Nonce = "verifier", "n1"
	wantOutcome(t, only(t, keyBinding(context.Background(), p, pc)), Pass)
	wantOutcome(t, only(t, audience(context.Background(), p, pc)), Pass)
	wantOutcome(t, only(t, nonce(context.Background(), p, pc)), Pass)
	if r := Evaluate(context.Background(), p, with(pc, nil), Set{ID: "default"}); r.Verdict == Invalid {
		t.Fatalf("a bound answer is invalid: %+v", r.Results)
	}

	other := newBuilder(t)
	stranger := holderDID(t, other)
	for name, tc := range map[string]struct {
		cred     Credential
		envelope string
		detail   string
	}{
		"another signer":       {c, vpJWT(t, other.holderKey, holder, "verifier", "n1", testNow, c.Token), "the presentation signature is not valid"},
		"another holder":       {c, vpJWT(t, b.holderKey, stranger, "verifier", "n1", testNow, c.Token), "the presentation names another holder"},
		"dated in the future":  {c, vpJWT(t, b.holderKey, holder, "verifier", "n1", testNow.Add(time.Hour), c.Token), "the presentation is dated in the future"},
		"no holder key":        {b.jwtCred(t, map[string]any{"iss": "did:web:issuer", "vc": map[string]any{}}), "", "the credential names no holder key"},
		"a holder of did:web":  {boundJWT(t, b, "did:web:holder.example"), "", "the credential names no holder key"},
		"a VP of another cred": {c, vpJWT(t, b.holderKey, holder, "verifier", "n1", testNow, "other"), NoHolderBinding},
	} {
		envelope := tc.envelope
		if envelope == "" {
			envelope = vpJWT(t, b.holderKey, holder, "verifier", "n1", testNow, tc.cred.Token)
		}
		answer := Presentation{Carrier: CarrierOID4VP, Envelopes: []string{envelope, "not-a-jwt"}, Credentials: []Credential{tc.cred}}
		got := only(t, keyBinding(context.Background(), answer, base()))
		if got.Result != Fail || got.Detail != tc.detail {
			t.Errorf("%s: %s (%s), want FAIL with %q", name, got.Result, got.Detail, tc.detail)
		}
	}
	// cnf.jwk names the key when the subject is no DID of a key.
	cnf, err := jose.PublicJWK(b.holderKey, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(cnf)
	if err != nil {
		t.Fatal(err)
	}
	withCnf := b.jwtCred(t, map[string]any{"iss": "did:web:issuer", "sub": "urn:holder", "cnf": map[string]any{"jwk": m}, "vc": map[string]any{}})
	vp := vpJWT(t, b.holderKey, "urn:holder", "verifier", "n1", testNow, withCnf.Token)
	p = Presentation{Carrier: CarrierOID4VP, Envelopes: []string{vp}, Credentials: []Credential{withCnf}}
	wantOutcome(t, only(t, keyBinding(context.Background(), p, base())), Pass)
}

// TestVPJWTClaimShapes covers an audience list, a JWT credential with no
// VP JWT, and a credential token that does not parse.
func TestVPJWTClaimShapes(t *testing.T) {
	b := newBuilder(t)
	holder := holderDID(t, b)
	c := boundJWT(t, b, holder)
	signed, err := jose.Sign(b.holderKey, holder+"#0", "JWT", map[string]any{
		"iss": holder, "aud": []string{"other", "verifier"}, "iat": testNow.Unix(),
		"vp": map[string]any{"verifiableCredential": []string{c.Token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := Presentation{Carrier: CarrierOID4VP, Envelopes: []string{signed}, Credentials: []Credential{c}}
	pc := base()
	pc.Audience = "verifier"
	wantOutcome(t, only(t, audience(context.Background(), p, pc)), Pass)
	if _, ok := kbClaim(c, Presentation{}, "aud", "verifier"); ok {
		t.Fatal("a JWT credential with no VP JWT gave a claim")
	}
	broken := Credential{Format: vc.FormatJWT, Token: "broken"}
	p = Presentation{Carrier: CarrierOID4VP, Envelopes: []string{vpJWT(t, b.holderKey, holder, "v", "n", testNow, "broken")}, Credentials: []Credential{broken}}
	if r := only(t, keyBinding(context.Background(), p, base())); r.Result != Fail || r.Detail != "the credential names no holder key" {
		t.Fatalf("broken token: %s (%s)", r.Result, r.Detail)
	}
}
