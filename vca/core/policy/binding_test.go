// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

func TestAudienceNotExpected(t *testing.T) {
	wantOutcome(t, only(t, audience(context.Background(), Presentation{}, base())), Skip)
}

func TestAudienceFromKeyBinding(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true, aud: "verifier", nonce: "n1"})
	pc := base()
	pc.Audience = "verifier"
	wantOutcome(t, only(t, audience(context.Background(), pres(c), pc)), Pass)
	pc.Audience = "other"
	got := only(t, audience(context.Background(), pres(c), pc))
	wantOutcome(t, got, Fail)
	if got.Evidence["presented"] != "verifier" {
		t.Fatalf("want the presented audience as evidence, got %v", got.Evidence)
	}
}

func TestAudienceFromCarrier(t *testing.T) {
	pc := base()
	pc.Audience = "verifier"
	p := Presentation{Audience: "verifier", Credentials: []Credential{objectCred(vc.FormatJSONLD, nil)}}
	got := only(t, audience(context.Background(), p, pc))
	wantOutcome(t, got, Pass)
	if got.CredentialIndex != WholePresentation {
		t.Fatalf("want the whole presentation index, got %d", got.CredentialIndex)
	}
	wantOutcome(t, only(t, audience(context.Background(), Presentation{}, pc)), Skip)
}

func TestNonceChecks(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true, nonce: "n1"})
	pc := base()
	pc.Nonce = "n1"
	wantOutcome(t, only(t, nonce(context.Background(), pres(c), pc)), Pass)
	pc.Nonce = "n2"
	wantOutcome(t, only(t, nonce(context.Background(), pres(c), pc)), Fail)
	pc.Nonce = "n1"
	wantOutcome(t, only(t, nonce(context.Background(), Presentation{Nonce: "n1"}, pc)), Pass)
}

func TestKBClaimShapes(t *testing.T) {
	b := newBuilder(t)
	if _, ok := kbClaim(objectCred(vc.FormatJSONLD, nil), "aud"); ok {
		t.Fatal("want no claim from a JSON-LD credential")
	}
	if _, ok := kbClaim(Credential{Format: vc.FormatSDJWT, Token: "bad~"}, "aud"); ok {
		t.Fatal("want no claim from a broken token")
	}
	if _, ok := kbClaim(b.sdjwtCred(t, sdjwtOptions{}), "aud"); ok {
		t.Fatal("want no claim without key binding")
	}
	c := signKB(t, b, b.sdjwtCred(t, sdjwtOptions{keyBinding: true}), map[string]any{"aud": 7})
	if _, ok := kbClaim(c, "aud"); ok {
		t.Fatal("want no claim when the value is not text")
	}
	plain := b.sdjwtCred(t, sdjwtOptions{})
	parsed, err := sdjwt.Parse(plain.Token)
	if err != nil {
		t.Fatal(err)
	}
	parsed.KeyBindingJWT = "x.y.z"
	bad := Credential{Format: vc.FormatSDJWT, Token: sdjwt.Serialize(parsed)}
	if _, ok := kbClaim(bad, "aud"); ok {
		t.Fatal("want no claim when the key binding JWT does not parse")
	}
}
