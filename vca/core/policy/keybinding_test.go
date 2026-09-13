// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

func TestKeyBindingNoCredentials(t *testing.T) {
	wantOutcome(t, only(t, keyBinding(context.Background(), Presentation{}, base())), Skip)
}

func TestKeyBindingNotSDJWT(t *testing.T) {
	got := only(t, keyBinding(context.Background(), pres(objectCred(vc.FormatJSONLD, nil)), base()))
	wantOutcome(t, got, Skip)
}

func TestKeyBindingValid(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true, aud: "verifier", nonce: "n1"})
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Pass)
}

func TestKeyBindingMissing(t *testing.T) {
	b := newBuilder(t)
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(b.sdjwtCred(t, sdjwtOptions{})), base())), Fail)
}

func TestKeyBindingNoHolderKey(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{noHolder: true})
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Skip)
}

func TestKeyBindingBadToken(t *testing.T) {
	c := Credential{Format: vc.FormatSDJWT, Token: "not-a-token~"}
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Fail)
}

func TestKeyBindingBadDisclosure(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true})
	parts := strings.Split(c.Token, "~")
	parts[1] = "WyJzYWx0IiwiZXh0cmEiLCJ2YWx1ZSJd"
	c.Token = strings.Join(parts, "~")
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Fail)
}

func TestKeyBindingWrongSignature(t *testing.T) {
	b, other := newBuilder(t), newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true})
	pres1, err := sdjwt.Parse(c.Token)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := sdjwt.KeyBinding(pres1, other.holderKey, sdjwt.DefaultAlg, "", "", testNow)
	if err != nil {
		t.Fatal(err)
	}
	pres1.KeyBindingJWT = kb
	c.Token = sdjwt.Serialize(pres1)
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Fail)
}

func TestKeyBindingWrongType(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true})
	p, err := sdjwt.Parse(c.Token)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jose.Sign(b.holderKey, "", "JWT", map[string]any{"iat": testNow.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	p.KeyBindingJWT = tok
	c.Token = sdjwt.Serialize(p)
	got := only(t, keyBinding(context.Background(), pres(c), base()))
	wantOutcome(t, got, Fail)
	if got.Evidence["typ"] != "JWT" {
		t.Fatalf("want the type as evidence, got %v", got.Evidence)
	}
}

// signKB replaces the key binding JWT of c with one that carries claims.
func signKB(t *testing.T, b builder, c Credential, claims any) Credential {
	t.Helper()
	p, err := sdjwt.Parse(c.Token)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jose.Sign(b.holderKey, "", sdjwt.TypeKB, claims)
	if err != nil {
		t.Fatal(err)
	}
	p.KeyBindingJWT = tok
	c.Token = sdjwt.Serialize(p)
	return c
}

func TestKeyBindingDigestAndTime(t *testing.T) {
	b := newBuilder(t)
	c := b.sdjwtCred(t, sdjwtOptions{keyBinding: true})
	p, err := sdjwt.Parse(c.Token)
	if err != nil {
		t.Fatal(err)
	}
	good, err := sdjwt.Digest(sdjwt.DefaultAlg, sdjwt.Serialize(sdjwt.Presentation{
		IssuerJWT: p.IssuerJWT, Disclosures: p.Disclosures,
	}))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{"wrong digest", map[string]any{"sd_hash": "other", "iat": testNow.Unix()}},
		{"no iat", map[string]any{"sd_hash": good}},
		{"future iat", map[string]any{"sd_hash": good, "iat": testNow.Add(time.Hour).Unix()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := only(t, keyBinding(context.Background(), pres(signKB(t, b, c, tc.claims)), base()))
			wantOutcome(t, got, Fail)
		})
	}
}

func TestCheckDigestUnknownAlg(t *testing.T) {
	got := checkDigest(sdjwt.Presentation{IssuerJWT: "a.b.c"},
		map[string]any{"_sd_alg": "sha-999"}, map[string]any{})
	if got != "the credential names an unknown digest algorithm" {
		t.Fatalf("want the unknown algorithm detail, got %q", got)
	}
}

func TestHolderKeyShapes(t *testing.T) {
	if _, ok := holderKey(map[string]any{}); ok {
		t.Fatal("want no key without cnf")
	}
	if _, ok := holderKey(map[string]any{"cnf": map[string]any{}}); ok {
		t.Fatal("want no key without cnf.jwk")
	}
	if _, ok := holderKey(map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "oops"}}}); ok {
		t.Fatal("want no key for a broken jwk")
	}
}

func TestKeyBindingBadIssuerPayload(t *testing.T) {
	c := Credential{Format: vc.FormatSDJWT, Token: "a.b.c~"}
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Fail)
}

func TestKeyBindingWithoutCnf(t *testing.T) {
	b := newBuilder(t)
	c := signKB(t, b, b.sdjwtCred(t, sdjwtOptions{noHolder: true}), map[string]any{"iat": testNow.Unix()})
	got := only(t, keyBinding(context.Background(), pres(c), base()))
	wantOutcome(t, got, Fail)
	if got.Detail != "the credential names no holder key" {
		t.Fatalf("want the holder key detail, got %q", got.Detail)
	}
}

func TestKeyBindingPayloadNotAnObject(t *testing.T) {
	b := newBuilder(t)
	c := signKB(t, b, b.sdjwtCred(t, sdjwtOptions{}), "text")
	wantOutcome(t, only(t, keyBinding(context.Background(), pres(c), base())), Fail)
}
