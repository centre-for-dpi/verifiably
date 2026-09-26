// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"compress/zlib"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/render"
)

// canonical encodes CBOR in the core deterministic form of RFC 8949
// section 4.2.1: map keys sorted by their encoded bytes. The MOSIP QR
// code specification 1.1.0 expects it, and it makes one text per claims.
var canonical = anyval.Must(cbor.CoreDetEncOptions().EncMode())

// issuerDID is the issuer of the test codes.
const issuerDID = "did:web:certify.inji.example"

// issuedAt is claim 6 of the test codes.
const issuedAt = 1774958400

// identityText builds the text of a Claim 169 QR code with the claims:
// a COSE_Sign1 CWT, then zlib, then base45, as the QR code specification
// 1.1.0 describes it. The CBOR is canonical, so the same claims always
// give the same text. The signature is a placeholder; the render never
// checks it.
func identityText(t *testing.T, data map[any]any) string {
	t.Helper()
	protected, err := canonical.Marshal(map[int]any{1: -8, 4: []byte(issuerDID + "#key-0")})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := canonical.Marshal(map[int]any{1: issuerDID, 6: issuedAt, 169: data})
	if err != nil {
		t.Fatal(err)
	}
	return sign1Text(t, protected, claims)
}

// sign1Text wraps the protected header and the claims in a COSE_Sign1
// message, then deflates and base45 encodes it.
func sign1Text(t *testing.T, protected, claims []byte) string {
	t.Helper()
	msg, err := canonical.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[int]any{}, claims, []byte("signature")}})
	if err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return pixelpass.EncodeBase45(z.Bytes())
}

// keyOrder is the order of the keys in the four maps of a Claim 169
// code: the protected header, the CWT claims, claim 169, and the face
// biometric of claim 169.
type keyOrder struct {
	header, claims, identity, face []any
}

// canonicalOrder is the order of RFC 8949 section 4.2.1 for wanjiku:
// integers before text, and a shorter encoding before a longer one.
var canonicalOrder = keyOrder{
	header:   []any{1, 4},
	claims:   []any{1, 6, 169},
	identity: []any{4, 8, 9, 12, 14, 62, 99, "note"},
	face:     []any{0, 1},
}

// orderedText builds the Claim 169 code of wanjiku with the keys of each
// map in the order given. An encoder that writes a map in the iteration
// order of a Go map gives any of these texts for the same claims.
func orderedText(t *testing.T, o keyOrder) string {
	t.Helper()
	identity := map[any]any{}
	for k, v := range wanjiku {
		identity[k] = v
	}
	identity[62] = []any{orderedMap(t, o.face, map[any]any{0: []byte{1, 2}, 1: 0})}
	header := map[any]any{1: -8, 4: []byte(issuerDID + "#key-0")}
	claims := map[any]any{1: issuerDID, 6: issuedAt, 169: orderedMap(t, o.identity, identity)}
	return sign1Text(t, orderedMap(t, o.header, header), orderedMap(t, o.claims, claims))
}

// orderedMap encodes a CBOR map of fewer than 24 entries with its keys
// in the order given.
func orderedMap(t *testing.T, keys []any, values map[any]any) cbor.RawMessage {
	t.Helper()
	if len(keys) != len(values) || len(keys) >= 24 {
		t.Fatalf("%d keys for %d values", len(keys), len(values))
	}
	out := []byte{0xa0 | byte(len(keys))}
	for _, k := range keys {
		v, ok := values[k]
		if !ok {
			t.Fatalf("no value for the key %v", k)
		}
		for _, item := range []any{k, v} {
			enc, err := canonical.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, enc...)
		}
	}
	return out
}

// wanjiku is the identity of the tests.
var wanjiku = map[any]any{4: "Wanjiku Njeri", 8: "1987-04-12", 9: 2, 12: "+254712345678", 14: 2,
	62: []any{map[int]any{0: []byte{1, 2}, 1: 0}}, 99: "x", "note": "y"}

// TestIdentityTextIsCanonical proves the same claims always give the
// same text, with the keys of every map in the canonical order.
func TestIdentityTextIsCanonical(t *testing.T) {
	want := orderedText(t, canonicalOrder)
	for range 50 {
		if got := identityText(t, wanjiku); got != want {
			t.Fatal("the same claims gave another text")
		}
	}
}

// TestClaim169QrRendered puts the Claim 169 text of the stack in the QR
// code of the document as it is, and names the attributes it carries in
// the order of the QR code specification.
func TestClaim169QrRendered(t *testing.T) {
	text := identityText(t, wanjiku)
	payload, err := render.IdentityPayload("  " + text + "\n")
	if err != nil {
		t.Fatalf("IdentityPayload: %v", err)
	}
	if payload != text {
		t.Fatal("the identity payload must be the text of the stack, unchanged")
	}
	document, err := render.Render(render.Document{Title: "National ID", Claims: map[string]string{"fullName": "Wanjiku Njeri"}, QRPayload: payload})
	if err != nil || !bytes.Contains(document, []byte("/XObject")) {
		t.Fatalf("Render: %v", err)
	}
	attrs, err := render.IdentityAttributes(text)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range attrs {
		got = append(got, a.Name+"="+a.Value)
	}
	want := "Full Name=Wanjiku Njeri,Date of Birth=1987-04-12,Gender=Female,Phone Number=+254712345678," +
		"Marital Status=Married,Face=Included,Claim 99=x,note=y"
	if strings.Join(got, ",") != want {
		t.Fatalf("attributes = %s", strings.Join(got, ","))
	}
	for _, bad := range []string{"", "not base45!", pixelpass.EncodeBase45([]byte("plain"))} {
		if _, err := render.IdentityPayload(bad); err == nil {
			t.Errorf("IdentityPayload(%q) passed", bad)
		}
		if _, err := render.IdentityAttributes(bad); err == nil {
			t.Errorf("IdentityAttributes(%q) passed", bad)
		}
	}
}

// TestIngestReadsClaim169Qr reads the rendered document back with the
// decoder of the scanner: the PDF, its QR code, and the Claim 169 CWT.
// Each key order is one text an encoder that follows the iteration order
// of a Go map wrote for the same claims. Each of these gave a symbol
// that the scanner failed to read before the fix. The canonical order
// is one of them.
func TestIngestReadsClaim169Qr(t *testing.T) {
	cases := []struct {
		name  string
		order keyOrder
	}{
		{"canonical", canonicalOrder},
		{"face first", keyOrder{[]any{4, 1}, []any{6, 169, 1}, []any{62, 99, "note", 4, 8, 9, 12, 14}, []any{0, 1}}},
		{"note first", keyOrder{[]any{4, 1}, []any{6, 169, 1}, []any{"note", 4, 8, 9, 12, 14, 62, 99}, []any{0, 1}}},
		{"birth date first", keyOrder{[]any{4, 1}, []any{1, 6, 169}, []any{8, 9, 12, 14, 62, 99, "note", 4}, []any{1, 0}}},
		{"gender first", keyOrder{[]any{1, 4}, []any{169, 1, 6}, []any{9, 12, 14, 62, 99, "note", 4, 8}, []any{1, 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := orderedText(t, tc.order)
			document, err := render.Render(render.Document{Title: "National ID", Issuer: "Ministry of Interior",
				Claims: map[string]string{"fullName": "Wanjiku Njeri"}, QRPayload: text})
			if err != nil {
				t.Fatal(err)
			}
			res, err := ingest.Decode(document, ingest.Options{})
			if err != nil {
				t.Fatalf("the scanner cannot read the document: %v", err)
			}
			if res.Carrier != ingest.CarrierPDF || res.Detected != ingest.TypeCWTClaim169 {
				t.Fatalf("carrier %s, detected %s", res.Carrier, res.Detected)
			}
			if !bytes.Contains(res.Payload, []byte("Wanjiku Njeri")) {
				t.Fatalf("payload = %s", res.Payload)
			}
		})
	}
}
