// SPDX-License-Identifier: Apache-2.0

package pixelpass

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"testing"
)

// Test vectors from RFC 9285 section 4.3 and 4.4.
func TestBase45Vectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AB", "BB8"}, {"Hello!!", "%69 VD92EX0"}, {"base-45", "UJCLQE7W581"}, {"ietf!", "QED8WEX0"}, {"", ""},
	}
	for _, tc := range cases {
		if got := EncodeBase45([]byte(tc.in)); got != tc.want {
			t.Fatalf("EncodeBase45(%q) = %q, want %q", tc.in, got, tc.want)
		}
		dec, err := DecodeBase45(tc.want)
		if err != nil || string(dec) != tc.in {
			t.Fatalf("DecodeBase45(%q) = %q, %v", tc.want, dec, err)
		}
	}
	// GGW is the RFC 9285 example of a group above 65535.
	bad := []string{"A", "AB8a", "GGW", "ZZ", "abc"}
	for _, s := range bad {
		if _, err := DecodeBase45(s); err == nil {
			t.Fatalf("%q must fail", s)
		}
	}
}

func TestEncodeDecodeJSON(t *testing.T) {
	vc := []byte(`{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"credentialSubject":{"id":"did:example:1","name":"Ana","age":30,"tags":["a","b"],"ok":true}}`)
	enc, encErr := Encode(vc)
	if encErr != nil {
		t.Fatal(encErr)
	}
	for _, c := range enc {
		if !bytes.ContainsRune([]byte(alphabet), c) {
			t.Fatalf("non base45 character %q", c)
		}
	}
	dec, decErr := Decode(" " + enc + " ")
	if decErr != nil {
		t.Fatal(decErr)
	}
	var want, got any
	if err := json.Unmarshal(vc, &want); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if err := json.Unmarshal(dec, &got); err != nil {
		t.Fatalf("decoded is not JSON: %s", dec)
	}
	wb, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !bytes.Equal(wb, gb) {
		t.Fatalf("round trip mismatch:\n%s\n%s", wb, gb)
	}
}

func TestEncodeDecodeRaw(t *testing.T) {
	raw := []byte("eyJhbGciOiJFUzI1NiJ9.e30.sig")
	enc, err := Encode(raw)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil || !bytes.Equal(dec, raw) {
		t.Fatalf("raw round trip = %q, %v", dec, err)
	}
	if _, err := Encode(nil); err == nil {
		t.Fatal("empty must fail")
	}
}

func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, errAssign := w.Write(b)
	if errAssign != nil {
		t.Fatalf("w.Write: %v", errAssign)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("w.Close: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeErrors(t *testing.T) {
	bomb := deflate(t, make([]byte, MaxDecodedBytes+1))
	nan := deflate(t, []byte{0xf9, 0x7e, 0x00}) // CBOR half float NaN
	cases := []struct{ name, in string }{
		{"bad base45", "abc"},
		{"not zlib", EncodeBase45([]byte("plain text"))},
		{"short", EncodeBase45([]byte{0x78})},
		{"bad zlib header", EncodeBase45([]byte{0x78, 0x00, 0x00})},
		{"corrupt zlib", EncodeBase45([]byte{0x78, 0x9c, 0xff, 0xff, 0xff})},
		{"truncated", EncodeBase45(bomb[:20])},
		{"too large", EncodeBase45(bomb)},
		{"cbor nan", EncodeBase45(nan)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func FuzzParseDecode(f *testing.F) {
	enc, err := Encode([]byte(`{"a":[1,2,{"b":null}]}`))
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}
	f.Add(enc)
	f.Add("%69 VD92EX0")
	f.Fuzz(func(t *testing.T, s string) {
		out, err := Decode(s)
		if err != nil {
			return
		}
		if len(out) == 0 {
			return
		}
		re, err := Encode(out)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if _, err := Decode(re); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
	})
}

// TestEncodeWritesCanonicalCBOR proves one JSON document always gives
// one QR text, with the CBOR map keys in the core deterministic order of
// RFC 8949 section 4.2.1: sorted by their encoded bytes, so a shorter
// key comes before a longer one. JSON numbers stay 64 bit floats, as
// before.
func TestEncodeWritesCanonicalCBOR(t *testing.T) {
	doc := []byte(`{"name":"Asha","id":"7","gender":"F","dob":"1990-01-01","address":{"zip":"00100","city":"Nairobi"},"a":1,"bb":2}`)
	want, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for range 50 {
		if got, again := Encode(doc); again != nil || got != want {
			t.Fatalf("the same document gave another text: %v", again)
		}
	}
	raw, err := DecodeBase45(want)
	if err != nil {
		t.Fatalf("DecodeBase45: %v", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	var inflated bytes.Buffer
	if _, err := inflated.ReadFrom(zr); err != nil {
		t.Fatalf("inflate: %v", err)
	}
	// The keys in canonical order: a, bb, id, dob, name, gender, address,
	// and inside the address zip before city.
	canonical := []byte{0xa7, 0x61, 'a', 0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0,
		0x62, 'b', 'b', 0xfb, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x62, 'i', 'd', 0x61, '7',
		0x63, 'd', 'o', 'b', 0x6a}
	canonical = append(canonical, "1990-01-01"...)
	canonical = append(canonical, 0x64, 'n', 'a', 'm', 'e', 0x64, 'A', 's', 'h', 'a',
		0x66, 'g', 'e', 'n', 'd', 'e', 'r', 0x61, 'F', 0x67, 'a', 'd', 'd', 'r', 'e', 's', 's',
		0xa2, 0x63, 'z', 'i', 'p', 0x65, '0', '0', '1', '0', '0', 0x64, 'c', 'i', 't', 'y', 0x67)
	canonical = append(canonical, "Nairobi"...)
	if !bytes.Equal(inflated.Bytes(), canonical) {
		t.Fatalf("CBOR = % x\nwant   % x", inflated.Bytes(), canonical)
	}
}
