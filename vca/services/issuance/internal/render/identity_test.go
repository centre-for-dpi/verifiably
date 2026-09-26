// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"compress/zlib"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/render"
)

// identityText builds the text of a Claim 169 QR code with the claims:
// a COSE_Sign1 CWT, then zlib, then base45, as the QR code specification
// 1.1.0 describes it. The signature is a placeholder; the render never
// checks it.
func identityText(t *testing.T, data map[any]any) string {
	t.Helper()
	protected, err := cbor.Marshal(map[int]any{1: -8, 4: []byte("did:web:certify.inji.example#key-0")})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := cbor.Marshal(map[int]any{1: "did:web:certify.inji.example", 6: 1774958400, 169: data})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[int]any{}, claims, []byte("signature")}})
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

// wanjiku is the identity of the tests.
var wanjiku = map[any]any{4: "Wanjiku Njeri", 8: "1987-04-12", 9: 2, 12: "+254712345678", 14: 2,
	62: []any{map[int]any{0: []byte{1, 2}, 1: 0}}, 99: "x", "note": "y"}

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
func TestIngestReadsClaim169Qr(t *testing.T) {
	text := identityText(t, wanjiku)
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
}
