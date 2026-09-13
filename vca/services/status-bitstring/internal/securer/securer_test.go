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
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
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

func newRecord(t *testing.T, purpose lists.Purpose) lists.Record {
	t.Helper()
	rec, err := lists.NewRecord("list1", lists.KindBitstring, purpose, 1, bitstring.MinSize, "default", t0)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestNewSelectsMethod(t *testing.T) {
	for _, name := range []string{"", MethodJOSE, " JOSE "} {
		s, err := New(name)
		if err != nil || s.Kind() != lists.KindBitstring {
			t.Fatalf("%q: %v", name, err)
		}
		if len(s.MediaTypes()) != 1 || s.MediaTypes()[0] != MediaType {
			t.Fatalf("%q: media types %v", name, s.MediaTypes())
		}
	}
	_, err := New(MethodDataIntegrity)
	if !errors.Is(err, ErrNotImplemented) || !strings.Contains(err.Error(), "docs/status-bitstring.md") {
		t.Fatalf("err = %v", err)
	}
	if _, err := New("ed25519signature2020"); err == nil || errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v", err)
	}
	if len(Methods()) != 2 {
		t.Fatal("Methods")
	}
}

func TestSecureAndVerify(t *testing.T) {
	for _, alg := range []jose.Algorithm{jose.ES256, jose.EdDSA} {
		issuer := newIssuer(t, alg)
		rec := newRecord(t, lists.Revocation)
		idx := 94567
		if _, err := rec.Allocate(nil); err != nil {
			t.Fatal(err)
		}
		rec.Allocated[idx/8] |= 1 << (7 - uint(idx%8))
		rec.AllocatedCount++
		if _, err := rec.Set(idx, 1, t0); err != nil {
			t.Fatal(err)
		}
		out, err := JOSE{}.Secure(rec, issuer, "https://status.example/status/list1", t0, t0.Add(24*time.Hour))
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if len(out) != 1 || out[0].MediaType != MediaType {
			t.Fatalf("%s: out = %+v", alg, out)
		}
		token := string(out[0].Body)
		header, err := jose.PeekHeader(token)
		if err != nil {
			t.Fatal(err)
		}
		if header.Typ != Type || header.Alg != string(alg) {
			t.Fatalf("%s: header = %+v", alg, header)
		}
		if header.Kid != issuer.Kid(issuer.Active()) {
			t.Fatalf("%s: kid = %s", alg, header.Kid)
		}
		// The kid names a did:jwk verification method that resolves.
		base, _, _ := strings.Cut(header.Kid, "#")
		doc, err := did.JWKDocument(base)
		if err != nil || len(doc.VerificationMethod) != 1 {
			t.Fatalf("%s: did:jwk does not resolve: %v", alg, err)
		}
		pub, err := did.PublicKey(doc.VerificationMethod[0])
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := jose.Verify(token, pub, jose.SigningAlgorithms)
		if err != nil {
			t.Fatalf("%s: verify: %v", alg, err)
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		purpose, list, err := bitstring.ParseCredential(claims)
		if err != nil {
			t.Fatal(err)
		}
		if purpose != bitstring.Revocation || list.Size() != bitstring.MinSize {
			t.Fatalf("%s: purpose %s size %d", alg, purpose, list.Size())
		}
		if v, _ := list.Get(idx); !v {
			t.Fatalf("%s: index %d must be set", alg, idx)
		}
		if claims["issuer"] != issuer.DID() || !strings.HasPrefix(issuer.DID(), "did:jwk:") {
			t.Fatalf("%s: issuer = %v", alg, claims["issuer"])
		}
		if claims["validUntil"] != t0.Add(24*time.Hour).Format(time.RFC3339) {
			t.Fatalf("%s: validUntil = %v", alg, claims["validUntil"])
		}
		types, _ := claims["type"].([]any)
		if len(types) != 2 || types[1] != bitstring.TypeCredential {
			t.Fatalf("%s: type = %v", alg, claims["type"])
		}
	}
}

func TestSecureUsesConfiguredDID(t *testing.T) {
	issuer := newIssuer(t, jose.ES256, "did:web:issuer.example")
	rec := newRecord(t, lists.Suspension)
	out, err := JOSE{}.Secure(rec, issuer, "https://status.example/status/list1", t0, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jose.PeekPayload(string(out[0].Body))
	if err != nil {
		t.Fatal(err)
	}
	if claims["issuer"] != "did:web:issuer.example" {
		t.Fatalf("issuer = %v", claims["issuer"])
	}
	header, _ := jose.PeekHeader(string(out[0].Body))
	if header.Kid != issuer.Active().ID {
		t.Fatalf("kid = %s", header.Kid)
	}
}

func TestCredentialRejectsBadRecords(t *testing.T) {
	small, _ := lists.NewRecord("s", lists.KindToken, lists.Revocation, 1, 8, "default", t0)
	if _, err := Credential(small, "did:x", "u", t0, t0); !errors.Is(err, lists.ErrBadKind) {
		t.Fatalf("err = %v", err)
	}
	rec := newRecord(t, lists.Revocation)
	rec.Purpose = "other"
	if _, err := Credential(rec, "did:x", "u", t0, t0); !errors.Is(err, lists.ErrBadPurpose) {
		t.Fatalf("err = %v", err)
	}
	short := newRecord(t, lists.Revocation)
	short.Size = 8
	if _, err := Credential(short, "did:x", "u", t0, t0); err == nil || !strings.Contains(err.Error(), "131072") {
		t.Fatalf("err = %v", err)
	}
	issuer := newIssuer(t, jose.ES256)
	if _, err := (JOSE{}).Secure(short, issuer, "u", t0, t0); err == nil {
		t.Fatal("Secure must report the record error")
	}
}

func TestSecureReportsSigningFailure(t *testing.T) {
	issuer := newIssuer(t, jose.ES256)
	issuer.Keys[0].Private = "not a key"
	rec := newRecord(t, lists.Revocation)
	if _, err := (JOSE{}).Secure(rec, issuer, "u", t0, t0); err == nil || !strings.Contains(err.Error(), "securer:") {
		t.Fatalf("err = %v", err)
	}
}

func TestDataIntegrityIsNotImplemented(t *testing.T) {
	var s lists.Securer = DataIntegrity{}
	if s.Kind() != lists.KindBitstring || s.MediaTypes()[0] != "application/vc" {
		t.Fatal("accessors")
	}
	var empty keys.Issuer
	_, err := s.Secure(lists.Record{}, empty, "", t0, t0)
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v", err)
	}
}
