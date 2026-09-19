// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestCWTClaimsRoundTrip(t *testing.T) {
	l := mustNew(t, 2, 12)
	if err := l.Set(1, Suspended); err != nil {
		t.Fatalf("l.Set: %v", err)
	}
	raw := CWTClaims(sampleClaims(), l)
	c, got, err := ParseCWTClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c != sampleClaims() {
		t.Fatalf("claims = %+v", c)
	}
	if mustGet(t, got, 1) != Suspended {
		t.Fatal("index 1 must be Suspended")
	}
	// Minimal claims.
	minRaw := CWTClaims(Claims{Subject: "s", IssuedAt: time.Unix(5, 0)}, l)
	var m map[int64]any
	if err := cbor.Unmarshal(minRaw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m[cwtExp]; ok {
		t.Fatal("exp must be omitted")
	}
	if _, ok := m[cwtTTL]; ok {
		t.Fatal("ttl must be omitted")
	}
	if _, _, err := ParseCWTClaims(minRaw); err != nil {
		t.Fatal(err)
	}
}

func TestParseCWTClaimsErrors(t *testing.T) {
	enc := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatalf("cbor.Marshal: %v", err)
		}
		return b
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"not cbor map", []byte{0xff}},
		{"no sub", enc(map[int64]any{})},
		{"no iat", enc(map[int64]any{cwtSub: "s"})},
		{"no status_list", enc(map[int64]any{cwtSub: "s", cwtIat: 1})},
		{"bad list", enc(map[int64]any{cwtSub: "s", cwtIat: 1, cwtStatusList: map[string]any{"bits": 1, "lst": []byte("x")}})},
		{"negative iat", enc(map[int64]any{cwtSub: "s", cwtIat: -5, cwtStatusList: map[string]any{"bits": 1, "lst": mustNew(t, 1, 8).Compress()}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseCWTClaims(tc.raw)
			if tc.name == "negative iat" {
				if err != nil {
					t.Fatalf("negative int must decode: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSignVerifyCWT(t *testing.T) {
	ec, ecErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if ecErr != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", ecErr)
	}
	_, ed, edErr := ed25519.GenerateKey(rand.Reader)
	if edErr != nil {
		t.Fatalf("ed25519.GenerateKey: %v", edErr)
	}
	payload := CWTClaims(sampleClaims(), mustNew(t, 1, 8))
	for name, key := range map[string]any{"es256": ec, "eddsa": ed} {
		t.Run(name, func(t *testing.T) {
			alg, sign, err := KeySigner(key)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := SignCWT(payload, alg, []byte("kid-1"), sign)
			if err != nil {
				t.Fatal(err)
			}
			var pub any
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				pub = &k.PublicKey
			case ed25519.PrivateKey:
				pub = k.Public()
			}
			var seenKid []byte
			verify := func(alg int64, kid, data, sig []byte) error {
				seenKid = kid
				return KeyVerifier(pub)(alg, kid, data, sig)
			}
			got, err := VerifyCWT(msg, verify)
			if err != nil {
				t.Fatalf("VerifyCWT: %v", err)
			}
			if string(got) != string(payload) || string(seenKid) != "kid-1" {
				t.Fatalf("payload or kid mismatch: kid=%q", seenKid)
			}
			// Tamper with the payload byte inside the message.
			bad := append([]byte{}, msg...)
			bad[len(bad)-1] ^= 0x01
			if _, err := VerifyCWT(bad, verify); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("tampered: %v", err)
			}
		})
	}
	// No kid.
	alg, sign, err := KeySigner(ec)
	if err != nil {
		t.Fatalf("KeySigner: %v", err)
	}
	msg, err := SignCWT(payload, alg, nil, sign)
	if err != nil {
		t.Fatalf("SignCWT: %v", err)
	}
	if _, err := VerifyCWT(msg, func(_ int64, kid, _, _ []byte) error {
		if kid != nil {
			t.Fatal("kid must be nil")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Signer failure.
	if _, err := SignCWT(payload, alg, nil, func([]byte) ([]byte, error) { return nil, errors.New("hsm down") }); err == nil {
		t.Fatal("signer error must propagate")
	}
}

func TestKeySignerErrors(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	if _, _, err := KeySigner(p384); err == nil {
		t.Fatal("P-384 must fail")
	}
	if _, _, err := KeySigner("nope"); err == nil {
		t.Fatal("string must fail")
	}
}

func TestKeyVerifierErrors(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	data := []byte("data")
	if err := KeyVerifier(&ec.PublicKey)(COSEAlgEdDSA, nil, data, make([]byte, 64)); err == nil {
		t.Fatal("wrong alg for EC must fail")
	}
	if err := KeyVerifier(&ec.PublicKey)(COSEAlgES256, nil, data, make([]byte, 64)); err == nil {
		t.Fatal("zero signature must fail")
	}
	if err := KeyVerifier(edPub)(COSEAlgEdDSA, nil, data, make([]byte, 64)); err == nil {
		t.Fatal("bad EdDSA signature must fail")
	}
	if err := KeyVerifier("nope")(COSEAlgES256, nil, data, nil); err == nil {
		t.Fatal("unsupported key must fail")
	}
}

func TestVerifyCWTStructureErrors(t *testing.T) {
	enc := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatalf("cbor.Marshal: %v", err)
		}
		return b
	}
	ok := func(int64, []byte, []byte, []byte) error { return nil }
	goodHdr := enc(map[int64]any{coseAlg: COSEAlgES256, coseTyp: TypeCWT})
	cases := []struct {
		name string
		msg  []byte
	}{
		{"not cbor", []byte{0xff}},
		{"not a tag", enc([]any{})},
		{"wrong tag", enc(cbor.Tag{Number: 17, Content: []any{}})},
		{"bad structure", enc(cbor.Tag{Number: 18, Content: "x"})},
		{"bad protected", enc(cbor.Tag{Number: 18, Content: []any{[]byte{0xff}, map[any]any{}, []byte{}, []byte{}}})},
		{"wrong typ", enc(cbor.Tag{Number: 18, Content: []any{enc(map[int64]any{coseAlg: -7}), map[any]any{}, []byte{}, []byte{}}})},
		{"no alg", enc(cbor.Tag{Number: 18, Content: []any{enc(map[int64]any{coseTyp: TypeCWT}), map[any]any{}, []byte{}, []byte{}}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyCWT(tc.msg, ok); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	good := enc(cbor.Tag{Number: 18, Content: []any{goodHdr, map[any]any{}, []byte("p"), []byte("s")}})
	if p, err := VerifyCWT(good, ok); err != nil || string(p) != "p" {
		t.Fatalf("good = %q, %v", p, err)
	}
}

func FuzzParseCWT(f *testing.F) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	alg, sign, err := KeySigner(ec)
	if err != nil {
		f.Fatalf("KeySigner: %v", err)
	}
	payload := CWTClaims(sampleClaims(), mustNewF(f))
	msg, err := SignCWT(payload, alg, []byte("k"), sign)
	if err != nil {
		f.Fatalf("SignCWT: %v", err)
	}
	f.Add(msg)
	f.Add(payload)
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, _, err := ParseCWTClaims(data); err != nil && err.Error() == "" {
			t.Fatal("ParseCWTClaims must describe the failure")
		}
		if _, err := VerifyCWT(data, KeyVerifier(&ec.PublicKey)); err != nil && err.Error() == "" {
			t.Fatal("VerifyCWT must describe the failure")
		}
	})
}

func mustNewF(f *testing.F) *List {
	l, err := New(1, 8)
	if err != nil {
		f.Fatal(err)
	}
	return l
}

func TestValueHelpers(t *testing.T) {
	if _, ok := asInt(uint64(math.MaxUint64)); ok {
		t.Fatal("a uint64 above MaxInt64 must not convert")
	}
	if got := bytesOrNil([]byte("x"), errors.New("boom")); got != nil {
		t.Fatalf("bytesOrNil with error = %v", got)
	}
	if got := floatOf("not a number"); got != 0 {
		t.Fatalf("floatOf = %v", got)
	}
}
