// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// claim169Data is the claim 169 of an identity QR code: the integer keys
// of the 169 QR code specification.
func claim169Data() map[any]any {
	return map[any]any{
		uint64(4): "Wanjiku Njeri", uint64(8): "1987-04-12", uint64(9): uint64(2),
		uint64(12): "+254712345678", uint64(14): uint64(1), uint64(18): []any{uint64(1), uint64(6)},
		uint64(62): []any{map[any]any{uint64(0): []byte{1, 2}, uint64(1): uint64(0)}}, uint64(99): "extra",
		uint64(98): int64(-3), "text key": "skipped", uint64(math.MaxUint64): "skipped",
	}
}

// signClaim169 signs a CWT with claim 169 as a COSE_Sign1 message. The
// kid is a text string, as Certify writes the DID URL of its key.
func signClaim169(t *testing.T, key ed25519.PrivateKey, kid any, tagged bool, data map[any]any) []byte {
	t.Helper()
	claims, err := cbor.Marshal(map[int64]any{
		1: "did:web:certify.example", 2: "subject-1", 4: 1900000000, 5: 1700000000, 6: 1700000000, 169: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[int64]any{1: -8}
	if kid != nil {
		hdr[4] = kid
	}
	protected, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	toSign, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, claims})
	if err != nil {
		t.Fatal(err)
	}
	msg := []any{protected, map[any]any{}, claims, ed25519.Sign(key, toSign)}
	var out []byte
	if tagged {
		out, err = cbor.Marshal(cbor.Tag{Number: 18, Content: msg})
	} else {
		out, err = cbor.Marshal(msg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

// TestClaim169ReadsTheSignedCWT reads a Claim 169 code into the view: the
// issuer of the iss claim, the attributes by the names of the
// specification, the validity window, and the signed bytes the verifier
// checks with the key of the issuer.
func TestClaim169ReadsTheSignedCWT(t *testing.T) {
	pub, key := newEd25519(t)
	raw := signClaim169(t, key, "did:web:certify.example#key-0", true, claim169Data())
	for _, in := range [][]byte{raw, []byte(base64.RawURLEncoding.EncodeToString(raw)), signClaim169(t, key, "did:web:certify.example#key-0", false, claim169Data())} {
		if f := DetectFormat(in); f != FormatClaim169 {
			t.Fatalf("DetectFormat = %q, want %q", f, FormatClaim169)
		}
		c, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if c.Issuer != "did:web:certify.example" || c.SubjectID != "subject-1" || c.Format != string(FormatClaim169) {
			t.Fatalf("view = %+v", c)
		}
		want := map[string]string{
			"Full Name": "Wanjiku Njeri", "Date of Birth": "1987-04-12", "Gender": "Female",
			"Phone Number": "+254712345678", "Marital Status": "Unmarried", "Best Quality Fingers": "[1,6]", "99": "extra",
			"98": "-3",
		}
		for k, v := range want {
			if c.Claims[k] != v {
				t.Fatalf("claim %q = %q, want %q (claims %v)", k, c.Claims[k], v, c.Claims)
			}
		}
		if _, ok := c.Claims["Face"]; ok || len(c.Claims) != len(want) {
			t.Fatalf("the claims hold a biometric or more: %v", c.Claims)
		}
		if c.PrimaryType() != Claim169Type {
			t.Fatalf("type = %q", c.PrimaryType())
		}
		from, until := c.TemporalBounds()
		if from.Unix() != 1700000000 || until.Unix() != 1900000000 {
			t.Fatalf("window = %v %v", from, until)
		}
		s, err := Claim169Signature(in)
		if err != nil {
			t.Fatalf("Claim169Signature: %v", err)
		}
		if s.Algorithm != -8 || s.KeyID != "did:web:certify.example#key-0" || !ed25519.Verify(pub, s.ToBeSigned, s.Signature) {
			t.Fatalf("signature parts = %+v", s)
		}
	}
	// A binary kid reads as text too.
	s, err := Claim169Signature(signClaim169(t, key, []byte("key-1"), true, claim169Data()))
	if err != nil || s.KeyID != "key-1" {
		t.Fatalf("binary kid: %+v %v", s, err)
	}
}

// TestClaim169Refusals keeps other CBOR out of the format.
func TestClaim169Refusals(t *testing.T) {
	_, key := newEd25519(t)
	other := map[int64]any{1: "did:web:x", 65533: map[string]any{"bits": 1}}
	payload, err := cbor.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int64]any{1: -8})
	if err != nil {
		t.Fatal(err)
	}
	statusList, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, payload, []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	notCWT, err := cbor.Marshal([]any{protected, map[any]any{}, []byte("text"), []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	badHeader, err := cbor.Marshal([]any{[]byte{0xff}, map[any]any{}, payload, []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	wrongTag, err := cbor.Marshal(cbor.Tag{Number: 98, Content: []any{protected, map[any]any{}, payload, []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	notMap, err := cbor.Marshal(map[int64]any{1: "did:web:x", 169: "text"})
	if err != nil {
		t.Fatal(err)
	}
	dataNotMap, err := cbor.Marshal([]any{protected, map[any]any{}, notMap, []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"status list": statusList, "payload not CBOR": notCWT, "header not CBOR": badHeader,
		"other tag": wrongTag, "claim 169 not a map": dataNotMap, "short": {0x84}, "empty": nil, "short tag": {0xd2},
		"not base64": []byte("!!!"),
	} {
		if DetectFormat(in) == FormatClaim169 {
			t.Errorf("%s: detected as Claim 169", name)
		}
		if _, err := FromClaim169(in); err == nil {
			t.Errorf("%s: FromClaim169 read it", name)
		}
		if _, err := Claim169Signature(in); err == nil {
			t.Errorf("%s: Claim169Signature read it", name)
		}
	}
	if _, err := FromClaim169(signClaim169(t, key, nil, true, claim169Data())); err != nil {
		t.Fatalf("a code without a kid: %v", err)
	}
}
