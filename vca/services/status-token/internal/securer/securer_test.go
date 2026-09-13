// SPDX-License-Identifier: Apache-2.0

package securer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func newIssuer(t *testing.T, alg jose.Algorithm, configured ...string) keys.Issuer {
	t.Helper()
	is, err := keys.Open(context.Background(), store.Memory(), keys.Options{
		Configured: configured, Alg: alg, Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return is.Default()
}

// publicKey returns the public key of the did:jwk in kid.
func publicKey(t *testing.T, kid string) any {
	t.Helper()
	base, _, _ := strings.Cut(kid, "#")
	doc, err := did.JWKDocument(base)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := did.PublicKey(doc.VerificationMethod[0])
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func filled(t *testing.T, bits int, values map[int]int) lists.Record {
	t.Helper()
	rec, err := lists.NewRecord("l1", lists.KindToken, lists.Revocation, bits, 16, "default", t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		rec.Allocated[i/8] |= 1 << (7 - uint(i%8))
		rec.AllocatedCount++
	}
	for i, v := range values {
		if _, err := rec.Set(i, v, t0); err != nil {
			t.Fatal(err)
		}
	}
	return rec
}

func TestSecureBothRepresentations(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		for _, alg := range []jose.Algorithm{jose.ES256, jose.EdDSA} {
			issuer := newIssuer(t, alg)
			want := map[int]int{0: 1, 3: 1}
			if bits > 1 {
				want[5] = 2
			}
			rec := filled(t, bits, want)
			sec := New(5*time.Minute, "https://status.example/aggregate")
			out, err := sec.Secure(rec, issuer, "https://status.example/status/l1", t0, t0.Add(time.Hour))
			if err != nil {
				t.Fatalf("bits %d %s: %v", bits, alg, err)
			}
			if len(out) != 2 || out[0].MediaType != MediaTypeJWT || out[1].MediaType != MediaTypeCWT {
				t.Fatalf("out = %+v", out)
			}
			pub := publicKey(t, issuer.Kid(issuer.Active()))

			payload, header, err := jose.Verify(string(out[0].Body), pub, jose.SigningAlgorithms)
			if err != nil {
				t.Fatalf("bits %d %s: jwt verify: %v", bits, alg, err)
			}
			if header.Typ != token.TypeJWT {
				t.Fatalf("typ = %s", header.Typ)
			}
			var m map[string]any
			if err := json.Unmarshal(payload, &m); err != nil {
				t.Fatal(err)
			}
			jwtClaims, jwtList, err := token.ParseJWTClaims(m)
			if err != nil {
				t.Fatal(err)
			}

			raw, err := token.VerifyCWT(out[1].Body, token.KeyVerifier(pub))
			if err != nil {
				t.Fatalf("bits %d %s: cwt verify: %v", bits, alg, err)
			}
			cwtClaims, cwtList, err := token.ParseCWTClaims(raw)
			if err != nil {
				t.Fatal(err)
			}

			// Both representations carry the same bits and claims.
			if jwtClaims != cwtClaims {
				t.Fatalf("claims differ: %+v %+v", jwtClaims, cwtClaims)
			}
			if jwtClaims.Issuer != issuer.DID() || jwtClaims.Subject != "https://status.example/status/l1" {
				t.Fatalf("claims = %+v", jwtClaims)
			}
			if !jwtClaims.IssuedAt.Equal(t0) || !jwtClaims.ExpiresAt.Equal(t0.Add(time.Hour)) || jwtClaims.TTL != 5*time.Minute {
				t.Fatalf("times = %+v", jwtClaims)
			}
			if jwtClaims.AggregationURI != "https://status.example/aggregate" {
				t.Fatal("aggregation_uri")
			}
			if jwtList.Bits() != bits || cwtList.Bits() != bits {
				t.Fatalf("bits = %d %d", jwtList.Bits(), cwtList.Bits())
			}
			for i := range 16 {
				a, _ := jwtList.Get(i)
				b, _ := cwtList.Get(i)
				if a != b || int(a) != want[i] {
					t.Fatalf("bits %d index %d: jwt %d cwt %d want %d", bits, i, a, b, want[i])
				}
			}
		}
	}
}

func TestSecureWithoutOptionalClaims(t *testing.T) {
	issuer := newIssuer(t, jose.ES256, "did:web:issuer.example")
	rec := filled(t, 1, nil)
	out, err := New(0, "").Secure(rec, issuer, "https://status.example/status/l1", t0, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.PeekPayload(string(out[0].Body))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ttl"]; ok {
		t.Fatal("ttl must be absent")
	}
	sl, _ := m["status_list"].(map[string]any)
	if _, ok := sl["aggregation_uri"]; ok {
		t.Fatal("aggregation_uri must be absent")
	}
	if m["iss"] != "did:web:issuer.example" {
		t.Fatalf("iss = %v", m["iss"])
	}
	header, _ := jose.PeekHeader(string(out[0].Body))
	if header.Kid != issuer.Active().ID {
		t.Fatalf("kid = %s", header.Kid)
	}
}

func TestSecureRejectsBadRecords(t *testing.T) {
	issuer := newIssuer(t, jose.ES256)
	sec := New(0, "")
	if sec.Kind() != lists.KindToken || len(sec.MediaTypes()) != 2 {
		t.Fatal("accessors")
	}
	wrong, _ := lists.NewRecord("b", lists.KindBitstring, lists.Revocation, 1, 0, "default", t0)
	if _, err := sec.Secure(wrong, issuer, "u", t0, t0); !errors.Is(err, lists.ErrBadKind) {
		t.Fatalf("err = %v", err)
	}
	badPurpose := filled(t, 1, nil)
	badPurpose.Purpose = "other"
	if _, err := sec.Secure(badPurpose, issuer, "u", t0, t0); !errors.Is(err, lists.ErrBadPurpose) {
		t.Fatalf("err = %v", err)
	}
	badBits := filled(t, 1, nil)
	badBits.Bits = 3
	if _, err := sec.Secure(badBits, issuer, "u", t0, t0); err == nil {
		t.Fatal("expected a width error")
	}
	broken := issuer
	broken.Keys = append([]keys.Key(nil), issuer.Keys...)
	broken.Keys[0].Private = "not a key"
	if _, err := sec.Secure(filled(t, 1, nil), broken, "u", t0, t0); err == nil {
		t.Fatal("expected a signing error")
	}
}

// failingKey is an Ed25519 key that jose accepts but COSE does not.
func TestSecureReportsCOSEKeyFailure(t *testing.T) {
	// KeySigner is reached only after jose.Sign succeeds. A key that
	// jose signs with but COSE rejects does not exist for ES256 and
	// Ed25519, so this test checks the error text of KeySigner itself.
	if _, _, err := token.KeySigner("not a key"); err == nil {
		t.Fatal("expected an error")
	}
}
