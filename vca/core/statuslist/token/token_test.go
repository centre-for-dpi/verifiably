// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func mustNew(t *testing.T, bits, size int) *List {
	t.Helper()
	l, err := New(bits, size)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNewErrors(t *testing.T) {
	if _, err := New(3, 10); err == nil {
		t.Fatal("bits=3 must fail")
	}
	if _, err := New(1, 0); err == nil {
		t.Fatal("size=0 must fail")
	}
	if _, err := FromBytes(5, nil); err == nil {
		t.Fatal("bits=5 must fail")
	}
	l, err := FromBytes(2, []byte{0xff})
	if err != nil || l.Size() != 4 || l.Bits() != 2 {
		t.Fatalf("FromBytes = %+v, %v", l, err)
	}
}

// Regression: legacy TestBitstringLSBFirst pins the IETF bit order.
func TestLSBFirst(t *testing.T) {
	cases := []struct {
		bit      int
		byteIdx  int
		wantByte byte
	}{{0, 0, 0x01}, {7, 0, 0x80}, {8, 1, 0x01}}
	for _, tc := range cases {
		l := mustNew(t, 1, 16)
		if err := l.Set(tc.bit, Invalid); err != nil {
			t.Fatal(err)
		}
		if got := l.Bytes()[tc.byteIdx]; got != tc.wantByte {
			t.Fatalf("bit %d: byte %d = 0x%x, want 0x%x", tc.bit, tc.byteIdx, got, tc.wantByte)
		}
	}
}

// Test vectors from draft-ietf-oauth-status-list section 4.1.
func TestSpecVectors(t *testing.T) {
	one := mustNew(t, 1, 16)
	for i, v := range []uint8{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1} {
		if err := one.Set(i, v); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(one.Bytes(), []byte{0xb9, 0xa3}) {
		t.Fatalf("bits=1 bytes = %x", one.Bytes())
	}
	dec, err := Decode(1, "eNrbuRgAAhcBXQ")
	if err != nil || !bytes.Equal(dec.Bytes(), []byte{0xb9, 0xa3}) {
		t.Fatalf("bits=1 vector decode: %x %v", dec.Bytes(), err)
	}

	two := mustNew(t, 2, 12)
	for i, v := range []uint8{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3} {
		if err := two.Set(i, v); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(two.Bytes(), []byte{0xc9, 0x44, 0xf9}) {
		t.Fatalf("bits=2 bytes = %x", two.Bytes())
	}
	if v, _ := two.Get(3); v != 3 {
		t.Fatalf("Get(3) = %d", v)
	}
}

func TestSetGetAllWidths(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		l := mustNew(t, bits, 20)
		maxV := uint8(1<<uint(bits) - 1)
		for i := 0; i < 20; i++ {
			if err := l.Set(i, uint8(i)&maxV); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 20; i++ {
			if v, err := l.Get(i); err != nil || v != uint8(i)&maxV {
				t.Fatalf("bits=%d Get(%d) = %d, %v", bits, i, v, err)
			}
		}
		if err := l.Set(0, maxV+1); bits != 8 && err == nil {
			t.Fatalf("bits=%d overflow must fail", bits)
		}
		if err := l.Set(20, 0); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("Set out of range = %v", err)
		}
		if _, err := l.Get(-1); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("Get out of range = %v", err)
		}
		// Regression: legacy TestZlibRoundTrip.
		back, err := Decode(bits, l.Encode())
		if err != nil || !bytes.Equal(back.Bytes(), l.Bytes()) {
			t.Fatalf("bits=%d round trip: %v", bits, err)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	var bomb bytes.Buffer
	w := zlib.NewWriter(&bomb)
	_, _ = w.Write(make([]byte, MaxDecodedBytes+1))
	_ = w.Close()
	b64 := base64.RawURLEncoding.EncodeToString
	cases := []struct {
		name string
		bits int
		in   string
	}{
		{"bad bits", 3, "eNrbuRgAAhcBXQ"},
		{"bad base64", 1, "!!!"},
		{"not zlib", 1, b64([]byte("plain"))},
		{"truncated", 1, b64(bomb.Bytes()[:30])},
		{"too large", 1, b64(bomb.Bytes())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.bits, tc.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func sampleClaims() Claims {
	return Claims{
		Issuer:         "https://issuer.example",
		Subject:        "https://issuer.example/status/1",
		IssuedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:      time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		TTL:            12 * time.Hour,
		AggregationURI: "https://issuer.example/status/all",
	}
}

func TestJWTClaimsRoundTrip(t *testing.T) {
	l := mustNew(t, 1, 16)
	_ = l.Set(3, Invalid)
	m := JWTClaims(sampleClaims(), l)
	if m["ttl"] != int64(43200) || m["exp"] == nil {
		t.Fatalf("claims = %v", m)
	}
	// Simulate a JSON round trip: numbers become float64.
	js := map[string]any{
		"iss": m["iss"], "sub": m["sub"], "iat": float64(m["iat"].(int64)),
		"exp": float64(m["exp"].(int64)), "ttl": float64(43200),
		"status_list": map[string]any{"bits": float64(1), "lst": m["status_list"].(map[string]any)["lst"],
			"aggregation_uri": "https://issuer.example/status/all"},
	}
	c, got, err := ParseJWTClaims(js)
	if err != nil {
		t.Fatal(err)
	}
	if c != sampleClaims() {
		t.Fatalf("claims = %+v", c)
	}
	if v, _ := got.Get(3); v != Invalid {
		t.Fatal("bit 3 must be Invalid")
	}
	// Minimal claims: no exp, ttl or aggregation_uri.
	min := JWTClaims(Claims{Subject: "s", IssuedAt: time.Unix(1, 0)}, l)
	if _, ok := min["exp"]; ok {
		t.Fatal("exp must be omitted")
	}
	if _, ok := min["status_list"].(map[string]any)["aggregation_uri"]; ok {
		t.Fatal("aggregation_uri must be omitted")
	}
	bad := []struct {
		name string
		m    map[string]any
	}{
		{"no sub", map[string]any{}},
		{"no iat", map[string]any{"sub": "s"}},
		{"no status_list", map[string]any{"sub": "s", "iat": float64(1)}},
		{"bad list", map[string]any{"sub": "s", "iat": float64(1), "status_list": map[string]any{"bits": float64(1), "lst": "!!"}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseJWTClaims(tc.m); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseRef(t *testing.T) {
	ref, err := ParseRef(map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": "https://l"}})
	if err != nil || ref != (Ref{URI: "https://l", Index: 7}) {
		t.Fatalf("ParseRef = %+v, %v", ref, err)
	}
	bad := []map[string]any{
		{},
		{"status_list": map[string]any{"idx": float64(1)}},
		{"status_list": map[string]any{"uri": "u"}},
		{"status_list": map[string]any{"uri": "u", "idx": float64(-1)}},
		{"status_list": map[string]any{"uri": "u", "idx": 1.5}},
	}
	for i, m := range bad {
		if _, err := ParseRef(m); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func FuzzParseDecode(f *testing.F) {
	f.Add(1, "eNrbuRgAAhcBXQ")
	f.Add(2, "eNo66fITEAAA__8D3wIH")
	f.Fuzz(func(t *testing.T, bits int, lst string) {
		l, err := Decode(bits, lst)
		if err != nil {
			return
		}
		if _, err := Decode(bits, l.Encode()); err != nil {
			t.Fatalf("re-encode must decode: %v", err)
		}
	})
}
