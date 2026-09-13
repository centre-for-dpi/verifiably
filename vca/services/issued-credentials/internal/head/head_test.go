// SPDX-License-Identifier: Apache-2.0

package head_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/head"
)

func newSigner(t *testing.T, period time.Duration) *head.Signer {
	t.Helper()
	key, err := head.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	s, err := head.NewSigner(head.Options{Key: key, Issuer: "issuer.example", Period: period})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func TestSignAndVerify(t *testing.T) {
	s := newSigner(t, 0)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	tip := head.Tip{RecordID: "a", Hash: "abcd", Length: 3}
	got, err := s.Sign(tip, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got.KeyID != s.KeyID() || got.JWS == "" || !got.SignedAt.Equal(now) {
		t.Fatalf("head = %+v", got)
	}
	claims, err := head.Verify(got.JWS, s.JWKS())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := head.ClaimsOf("issuer.example", tip, now)
	if claims != want {
		t.Errorf("claims = %+v, want %+v", claims, want)
	}
	hdr, err := jose.PeekHeader(got.JWS)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if hdr.Typ != head.TokenType || hdr.Alg != string(jose.ES256) {
		t.Errorf("header = %+v", hdr)
	}
}

func TestSignReusesTheSignatureForOneDay(t *testing.T) {
	s := newSigner(t, head.Period)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	tip := head.Tip{RecordID: "a", Hash: "abcd", Length: 1}
	first, err := s.Sign(tip, start)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	same, err := s.Sign(tip, start.Add(6*time.Hour))
	if err != nil {
		t.Fatalf("sign again: %v", err)
	}
	if same.JWS != first.JWS {
		t.Error("an unchanged tip inside the period keeps its signature")
	}
	later, err := s.Sign(tip, start.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("sign after the period: %v", err)
	}
	if later.JWS == first.JWS {
		t.Error("the signer signs again after the period")
	}
	moved, err := s.Sign(head.Tip{RecordID: "b", Hash: "beef", Length: 2}, start.Add(26*time.Hour))
	if err != nil {
		t.Fatalf("sign a new tip: %v", err)
	}
	if moved.JWS == later.JWS {
		t.Error("a new tip needs a new signature")
	}
	if s.Last().JWS != moved.JWS {
		t.Error("Last must return the newest signature")
	}
}

func TestLastIsEmptyBeforeTheFirstSignature(t *testing.T) {
	s := newSigner(t, 0)
	if !s.Last().IsZero() {
		t.Error("a new signer has no signature")
	}
}

func TestNewSignerRejectsBadKeys(t *testing.T) {
	if _, err := head.NewSigner(head.Options{}); !errors.Is(err, head.ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	if _, err := head.NewSigner(head.Options{Key: ed}); !errors.Is(err, head.ErrKeyType) {
		t.Errorf("err = %v, want ErrKeyType", err)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	key, err := head.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, err := head.EncodePEM(key)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := head.ParsePEM(append([]byte("# a comment\n"), data...))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := head.NewSigner(head.Options{Key: back}); err != nil {
		t.Fatalf("new signer: %v", err)
	}
}

func TestParsePEMRejectsBadInput(t *testing.T) {
	if _, err := head.ParsePEM([]byte("no blocks here")); !errors.Is(err, head.ErrNoPEM) {
		t.Errorf("err = %v, want ErrNoPEM", err)
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")})
	if _, err := head.ParsePEM(bad); err == nil {
		t.Error("want a parse error")
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	other := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("skipped")})
	other = append(other, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	if _, err := head.ParsePEM(other); !errors.Is(err, head.ErrKeyType) {
		t.Errorf("err = %v, want ErrKeyType", err)
	}
}

func TestEncodePEMRejectsANonKey(t *testing.T) {
	if _, err := head.EncodePEM("not a key"); err == nil {
		t.Error("want an encode error")
	}
}

func TestVerifyRejectsAWrongKey(t *testing.T) {
	s := newSigner(t, 0)
	other := newSigner(t, 0)
	signed, err := s.Sign(head.Tip{RecordID: "a", Hash: "ab", Length: 1}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := head.Verify(signed.JWS, other.JWKS()); err == nil {
		t.Error("a head signed with another key must not verify")
	}
	if _, err := head.Verify("not.a.jws", s.JWKS()); err == nil {
		t.Error("want a parse error")
	}
}

func TestVerifyRejectsClaimsThatAreNotAnObject(t *testing.T) {
	key, err := head.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	s, err := head.NewSigner(head.Options{Key: key})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	token, err := jose.Sign(key, s.KeyID(), head.TokenType, []string{"not", "an", "object"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := head.Verify(token, s.JWKS()); err == nil {
		t.Error("want a decode error")
	}
}
