// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
)

func TestDecodeClaim169(t *testing.T) {
	text := claim169QR(t, map[any]any{
		"vcVer": "v1", "name": "Asha", "id": []byte{1, 2},
		"address": map[any]any{"city": "Nairobi"}, "roles": []any{"driver"}, 7: "numeric key",
	}, true)
	cwt, steps, err := ingest.DecodeClaim169(text)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"base45", "zlib", "cose_sign1", "cwt"}; strings.Join(steps, ",") != strings.Join(want, ",") {
		t.Errorf("steps = %v", steps)
	}
	if cwt.Issuer != "did:web:issuer.test" || cwt.Subject != "subject-1" || cwt.Audience != "verifier" {
		t.Errorf("claims = %+v", cwt)
	}
	if cwt.IssuedAt.IsZero() || cwt.NotBefore.IsZero() || cwt.ExpiresAt.IsZero() {
		t.Errorf("times = %+v", cwt)
	}
	if cwt.Data["name"] != "Asha" {
		t.Errorf("claim 169 = %v", cwt.Data)
	}
	if cwt.Data["7"] != "numeric key" {
		t.Errorf("a numeric key becomes text, got %v", cwt.Data)
	}
	if cwt.Data["id"] != "\x01\x02" {
		t.Errorf("a byte string becomes text, got %q", cwt.Data["id"])
	}
	address, ok := cwt.Data["address"].(map[string]any)
	if !ok || address["city"] != "Nairobi" {
		t.Errorf("nested map = %v", cwt.Data["address"])
	}
	if roles, ok := cwt.Data["roles"].([]any); !ok || roles[0] != "driver" {
		t.Errorf("list = %v", cwt.Data["roles"])
	}
	if cwt.Sign1.Algorithm != -7 || string(cwt.Sign1.KeyID) != "key-1" {
		t.Errorf("COSE header = %+v", cwt.Sign1)
	}
	if len(cwt.Sign1.SigStructure) == 0 || string(cwt.Sign1.Signature) != "signature" {
		t.Errorf("COSE signature = %+v", cwt.Sign1)
	}
	body, err := cwt.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"name":"Asha"`) {
		t.Errorf("JSON = %s", body)
	}
}

func TestDecodeClaim169Untagged(t *testing.T) {
	if _, _, err := ingest.DecodeClaim169(claim169QR(t, map[any]any{"a": "b"}, false)); err != nil {
		t.Fatalf("an untagged COSE_Sign1 must decode: %v", err)
	}
}

func TestDecodeClaim169WithPrefix(t *testing.T) {
	text := "HC1:" + claim169QR(t, map[any]any{"a": "b"}, true)
	if _, _, err := ingest.DecodeClaim169(text); err != nil {
		t.Fatalf("a scheme prefix must decode: %v", err)
	}
}

func TestDecodeClaim169Errors(t *testing.T) {
	if _, _, err := ingest.DecodeClaim169("   "); err == nil {
		t.Error("empty text wants an error")
	}
	if _, _, err := ingest.DecodeClaim169("prefix:"); err == nil {
		t.Error("an empty body wants an error")
	}
	if _, _, err := ingest.DecodeClaim169("not base45!!"); err == nil {
		t.Error("text outside the alphabet wants an error")
	}
	if _, _, err := ingest.DecodeClaim169(pixelpass.EncodeBase45([]byte("plain"))); err == nil {
		t.Error("bytes that are not zlib want an error")
	}
	if _, _, err := ingest.DecodeClaim169(pixelpass.EncodeBase45(deflate(t, []byte("not cbor")))); err == nil {
		t.Error("bytes that are not COSE want an error")
	}
	claims, err := cbor.Marshal(map[int64]any{1: "iss"})
	if err != nil {
		t.Fatal(err)
	}
	text := pixelpass.EncodeBase45(deflate(t, sign1(t, claims, true)))
	_, _, err = ingest.DecodeClaim169(text)
	if !errors.Is(err, ingest.ErrNotClaim169) {
		t.Errorf("a CWT without claim 169 wants ErrNotClaim169, got %v", err)
	}
}

func TestParseSign1Errors(t *testing.T) {
	wrongTag, wrongTagErr := cbor.Marshal(cbor.Tag{Number: 17, Content: []any{[]byte{}, map[any]any{}, []byte("p"), []byte("s")}})
	if wrongTagErr != nil {
		t.Fatal(wrongTagErr)
	}
	if _, err := ingest.ParseSign1(wrongTag); err == nil {
		t.Error("a tag other than 18 wants an error")
	}
	badHeader, badHeaderErr := cbor.Marshal([]any{[]byte("not cbor at all"), map[any]any{}, []byte("p"), []byte("s")})
	if badHeaderErr != nil {
		t.Fatal(badHeaderErr)
	}
	if _, err := ingest.ParseSign1(badHeader); err == nil {
		t.Error("a broken protected header wants an error")
	}
	empty, err := cbor.Marshal([]any{[]byte{}, map[any]any{}, []byte("p"), []byte("s")})
	if err != nil {
		t.Fatal(err)
	}
	s, err := ingest.ParseSign1(empty)
	if err != nil {
		t.Fatalf("an empty protected header must decode: %v", err)
	}
	if s.Algorithm != 0 || s.KeyID != nil {
		t.Errorf("an empty header has no algorithm, got %+v", s)
	}
}

func TestParseCWTErrors(t *testing.T) {
	if _, err := ingest.ParseCWT([]byte("not cbor")); err == nil {
		t.Error("bytes that are not CBOR want an error")
	}
	notMap, notMapErr := cbor.Marshal(map[int64]any{169: "text"})
	if notMapErr != nil {
		t.Fatal(notMapErr)
	}
	if _, err := ingest.ParseCWT(notMap); err == nil {
		t.Error("a claim 169 that is not a map wants an error")
	}
	floats, err := cbor.Marshal(map[int64]any{6: 1700000000.0, 169: map[any]any{"a": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	cwt, err := ingest.ParseCWT(floats)
	if err != nil {
		t.Fatal(err)
	}
	if cwt.IssuedAt.IsZero() {
		t.Error("a floating point date must decode")
	}
}

func TestInflateLimits(t *testing.T) {
	if _, err := ingest.Inflate([]byte("not zlib")); err == nil {
		t.Error("bytes that are not zlib want an error")
	}
	broken := deflate(t, []byte("hello"))
	if _, err := ingest.Inflate(broken[:len(broken)-3]); err == nil {
		t.Error("a truncated stream wants an error")
	}
	big := deflate(t, make([]byte, ingest.MaxInflatedBytes+16))
	if _, err := ingest.Inflate(big); err == nil {
		t.Error("an oversized payload wants an error")
	}
}
