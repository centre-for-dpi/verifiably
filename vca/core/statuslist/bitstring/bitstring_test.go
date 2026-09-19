// SPDX-License-Identifier: Apache-2.0

package bitstring

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewClampsToMinSize(t *testing.T) {
	if got := New(64).Size(); got != MinSize {
		t.Fatalf("Size = %d, want %d", got, MinSize)
	}
	if got := New(MinSize * 2).Size(); got != MinSize*2 {
		t.Fatalf("Size = %d", got)
	}
	if got := len(New(0).Bytes()); got != MinSize/8 {
		t.Fatalf("bytes = %d", got)
	}
}

// mustGet returns bit i of l. It stops the test when Get fails.
func mustGet(t *testing.T, l *List, i int) bool {
	t.Helper()
	v, err := l.Get(i)
	if err != nil {
		t.Fatalf("Get(%d): %v", i, err)
	}
	return v
}

func TestMultibaseError(t *testing.T) {
	if got := multibase([]byte("x"), errors.New("boom")); got != "" {
		t.Fatalf("multibase with error = %q", got)
	}
}

// Regression: legacy TestBitstringSetGet.
func TestSetGet(t *testing.T) {
	b := New(0)
	if mustGet(t, b, 0) {
		t.Fatal("fresh bit must be 0")
	}
	if err := b.Set(0, true); err != nil {
		t.Fatal(err)
	}
	if !mustGet(t, b, 0) {
		t.Fatal("Set then Get should be true")
	}
	if err := b.Set(0, false); err != nil {
		t.Fatal(err)
	}
	if mustGet(t, b, 0) {
		t.Fatal("after clearing, Get should be false")
	}
	for _, i := range []int{-1, MinSize} {
		if err := b.Set(i, true); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("Set(%d) = %v", i, err)
		}
		if _, err := b.Get(i); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("Get(%d) = %v", i, err)
		}
	}
}

// Regression: legacy TestBitstringMSBFirst pins the W3C bit order.
func TestMSBFirst(t *testing.T) {
	cases := []struct {
		bit      int
		byteIdx  int
		wantByte byte
	}{{0, 0, 0x80}, {7, 0, 0x01}, {8, 1, 0x80}}
	for _, tc := range cases {
		b := New(0)
		if err := b.Set(tc.bit, true); err != nil {
			t.Fatal(err)
		}
		if got := b.Bytes()[tc.byteIdx]; got != tc.wantByte {
			t.Fatalf("bit %d: byte %d = 0x%x, want 0x%x", tc.bit, tc.byteIdx, got, tc.wantByte)
		}
	}
}

// Regression: legacy TestGzipRoundTrip, with the multibase prefix.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	a := New(0)
	for i := 0; i < 256; i += 17 {
		if err := a.Set(i, true); err != nil {
			t.Fatalf("a.Set: %v", err)
		}
	}
	enc := a.Encode()
	if !strings.HasPrefix(enc, "u") {
		t.Fatalf("missing multibase prefix: %q", enc[:4])
	}
	b, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if b.Size() != a.Size() {
		t.Fatalf("size %d != %d", b.Size(), a.Size())
	}
	for i := 0; i < 256; i++ {
		x := mustGet(t, a, i)
		y := mustGet(t, b, i)
		if x != y {
			t.Fatalf("mismatch at bit %d", i)
		}
	}
}

// The specification example list (section 3.2) decodes to 131,072 zero bits.
func TestDecodeSpecExample(t *testing.T) {
	const spec = "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
	l, err := Decode(spec)
	if err != nil {
		t.Fatal(err)
	}
	if l.Size() != MinSize {
		t.Fatalf("size = %d", l.Size())
	}
	if !bytes.Equal(l.Bytes(), make([]byte, MinSize/8)) {
		t.Fatal("expected all zero list")
	}
}

func TestDecodeErrors(t *testing.T) {
	var bomb bytes.Buffer
	w := gzip.NewWriter(&bomb)
	_, errAssign := w.Write(make([]byte, MaxDecodedBytes+1))
	if errAssign != nil {
		t.Fatalf("w.Write: %v", errAssign)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("w.Close: %v", err)
	}
	cases := []struct{ name, in string }{
		{"empty", ""},
		{"no prefix", "H4sI"},
		{"bad base64", "u!!!"},
		{"not gzip", "u" + base64.RawURLEncoding.EncodeToString([]byte("plain"))},
		{"truncated gzip", "u" + base64.RawURLEncoding.EncodeToString(bomb.Bytes()[:40])},
		{"too large", "u" + base64.RawURLEncoding.EncodeToString(bomb.Bytes())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCredentialAndParse(t *testing.T) {
	l := New(0)
	if err := l.Set(5, true); err != nil {
		t.Fatalf("l.Set: %v", err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	vc := Credential("https://issuer.example/status/1", "did:web:issuer.example", Revocation, l, now)
	if vc["validFrom"] != "2026-01-02T03:04:05Z" || vc["issuer"] != "did:web:issuer.example" {
		t.Fatalf("vc = %v", vc)
	}
	cs, isObject := vc["credentialSubject"].(map[string]any)
	if !isObject {
		t.Fatal("credentialSubject must be an object")
	}
	if cs["id"] != "https://issuer.example/status/1#list" || cs["type"] != TypeList {
		t.Fatalf("credentialSubject = %v", cs)
	}
	purpose, got, err := ParseCredential(vc)
	if err != nil || purpose != Revocation {
		t.Fatalf("ParseCredential: %v %q", err, purpose)
	}
	if !mustGet(t, got, 5) {
		t.Fatal("bit 5 must survive the round trip")
	}
	// JWT claim set wrapper (VCDM 2.0 secured with JOSE).
	if _, _, err := ParseCredential(map[string]any{"iss": "x", "vc": vc}); err != nil {
		t.Fatalf("vc wrapper: %v", err)
	}
	bad := []struct {
		name string
		doc  map[string]any
	}{
		{"no subject", map[string]any{}},
		{"no encodedList", map[string]any{"credentialSubject": map[string]any{"statusPurpose": "revocation"}}},
		{"no purpose", map[string]any{"credentialSubject": map[string]any{"encodedList": "uAA"}}},
		{"bad list", map[string]any{"credentialSubject": map[string]any{"encodedList": "uAA", "statusPurpose": "revocation"}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseCredential(tc.doc); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEntryAndParseEntry(t *testing.T) {
	e := Entry("https://issuer.example/status/1", 94567, Suspension)
	if e["id"] != "https://issuer.example/status/1#94567" || e["statusListIndex"] != "94567" {
		t.Fatalf("entry = %v", e)
	}
	ref, err := ParseEntry(e)
	if err != nil || ref.Index != 94567 || ref.Purpose != Suspension || ref.ListURL != "https://issuer.example/status/1" {
		t.Fatalf("ParseEntry = %+v, %v", ref, err)
	}
	num := map[string]any{"type": TypeEntry, "statusListCredential": "u", "statusListIndex": float64(3)}
	ref, err = ParseEntry(num)
	if err != nil || ref.Index != 3 || ref.Purpose != Revocation {
		t.Fatalf("numeric index = %+v, %v", ref, err)
	}
	bad := []struct {
		name string
		cs   map[string]any
	}{
		{"wrong type", map[string]any{"type": "Other"}},
		{"no url", map[string]any{"type": TypeEntry}},
		{"bad string index", map[string]any{"type": TypeEntry, "statusListCredential": "u", "statusListIndex": "x"}},
		{"negative string index", map[string]any{"type": TypeEntry, "statusListCredential": "u", "statusListIndex": "-1"}},
		{"fraction index", map[string]any{"type": TypeEntry, "statusListCredential": "u", "statusListIndex": 1.5}},
		{"missing index", map[string]any{"type": TypeEntry, "statusListCredential": "u"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseEntry(tc.cs); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func FuzzParseDecode(f *testing.F) {
	f.Add(New(0).Encode())
	f.Add("uH4sI")
	f.Fuzz(func(t *testing.T, s string) {
		l, err := Decode(s)
		if err != nil {
			return
		}
		if _, err := Decode(l.Encode()); err != nil {
			t.Fatalf("re-encode of a decoded list must decode: %v", err)
		}
	})
}
