// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

func TestSignatureNoCredentials(t *testing.T) {
	got := only(t, signature(context.Background(), Presentation{}, base()))
	wantOutcome(t, got, Skip)
	if got.CredentialIndex != WholePresentation {
		t.Fatalf("want whole presentation index, got %d", got.CredentialIndex)
	}
}

func TestSignatureValid(t *testing.T) {
	b := newBuilder(t)
	pc := base()
	pc.Keys = b.keys(t)
	for _, c := range []Credential{
		b.sdjwtCred(t, sdjwtOptions{}),
		b.jwtCred(t, map[string]any{"iss": "did:web:issuer"}),
	} {
		wantOutcome(t, only(t, signature(context.Background(), pres(c), pc)), Pass)
	}
}

func TestSignatureSkippedFormats(t *testing.T) {
	cases := []struct {
		format vc.Format
		want   string
	}{
		{vc.FormatJSONLD, notImplementedLDP},
		{vc.FormatMdoc, notImplementedMdoc},
		{vc.FormatJSON, "the credential carries no signed token"},
	}
	for _, tc := range cases {
		got := only(t, signature(context.Background(), pres(objectCred(tc.format, map[string]any{})), base()))
		wantOutcome(t, got, Skip)
		if got.Detail != tc.want {
			t.Fatalf("want %q, got %q", tc.want, got.Detail)
		}
	}
}

func TestSignatureBadToken(t *testing.T) {
	b := newBuilder(t)
	pc := base()
	pc.Keys = b.keys(t)
	sd := Credential{Format: vc.FormatSDJWT, Token: "not-a-token~"}
	wantOutcome(t, only(t, signature(context.Background(), pres(sd), pc)), Fail)
	jwt := Credential{Format: vc.FormatJWT, Token: "a.b"}
	wantOutcome(t, only(t, signature(context.Background(), pres(jwt), pc)), Fail)
}

func TestSignatureNoResolver(t *testing.T) {
	b := newBuilder(t)
	got := only(t, signature(context.Background(), pres(b.jwtCred(t, nil)), base()))
	wantOutcome(t, got, Error)
}

func TestSignatureResolverFails(t *testing.T) {
	b := newBuilder(t)
	pc := base()
	pc.Keys = func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, errors.New("offline") }
	wantOutcome(t, only(t, signature(context.Background(), pres(b.jwtCred(t, nil)), pc)), Error)
}

func TestSignatureNoMatchingKey(t *testing.T) {
	b := newBuilder(t)
	pc := base()
	pc.Keys = func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, nil }
	wantOutcome(t, only(t, signature(context.Background(), pres(b.jwtCred(t, nil)), pc)), Error)
}

func TestSignatureWrongKey(t *testing.T) {
	b, other := newBuilder(t), newBuilder(t)
	pc := base()
	set := other.jwks(t)
	pc.Keys = func(context.Context, string, string) (jose.JWKS, error) { return set, nil }
	wantOutcome(t, only(t, signature(context.Background(), pres(b.jwtCred(t, nil)), pc)), Fail)
}
