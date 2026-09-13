// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// sdjwtToken is an SD-JWT VC with one disclosure and no key binding.
const sdjwtToken = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQifQ.c2ln~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkFzaGEiXQ~"

func TestDetect(t *testing.T) {
	cases := []struct {
		name      string
		data      []byte
		mediaType string
		want      ingest.Carrier
	}{
		{"pdf", []byte("%PDF-1.7\n"), "", ingest.CarrierPDF},
		{"png", []byte("\x89PNG\r\n\x1a\nrest"), "", ingest.CarrierImage},
		{"jpeg", []byte("\xff\xd8\xffrest"), "", ingest.CarrierImage},
		{"gif", []byte("GIF89arest"), "", ingest.CarrierImage},
		{"media type", []byte("binary bytes"), "image/webp", ingest.CarrierImage},
		{"xml", []byte("<root/>"), "", ingest.CarrierXML},
		{"json object", []byte(`{"a":1}`), "", ingest.CarrierJSON},
		{"json array", []byte(`["a"]`), "", ingest.CarrierJSON},
		{"request scheme", []byte("openid4vp://?request_uri=https%3A%2F%2Fa.test"), "", ingest.CarrierOID4VPRequest},
		{"request url", []byte("https://verifier.test/authorize?request_uri=https%3A%2F%2Fa.test"), "", ingest.CarrierOID4VPRequest},
		{"plain url", []byte("https://verifier.test/page"), "", ingest.CarrierQR},
		{"base45", []byte("NCFOXN%TS3DH"), "", ingest.CarrierClaim169},
		{"token", []byte(sdjwtToken), "", ingest.CarrierQR},
		{"empty", []byte("   "), "", ingest.CarrierUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ingest.Detect(c.data, c.mediaType); got != c.want {
				t.Errorf("Detect = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDecodeLimits(t *testing.T) {
	if _, err := ingest.Decode(nil, ingest.Options{}); err == nil {
		t.Error("empty input wants an error")
	}
	if _, err := ingest.Decode([]byte("12345"), ingest.Options{MaxBytes: 2}); err == nil {
		t.Error("input over the limit wants an error")
	}
	if _, err := ingest.Decode([]byte("   "), ingest.Options{}); err == nil {
		t.Error("input with no carrier wants an error")
	}
	if _, err := ingest.Decode([]byte("x"), ingest.Options{Carrier: "tape"}); err == nil {
		t.Error("an unknown carrier wants an error")
	}
}

func TestDecodeSDJWT(t *testing.T) {
	res, err := ingest.Decode([]byte(sdjwtToken), ingest.Options{Carrier: ingest.CarrierJSON})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != vc.FormatSDJWT || res.Detected != ingest.TypeCredential {
		t.Errorf("result = %+v", res)
	}
	if len(res.Credentials) != 1 {
		t.Errorf("credentials = %d", len(res.Credentials))
	}
	if res.InputHash == "" || res.Carrier != ingest.CarrierJSON {
		t.Errorf("envelope = %+v", res)
	}
	bound := sdjwtToken + jwt(t, map[string]any{"nonce": "n"})
	res, err = ingest.Decode([]byte(bound), ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePresentation || res.KeyBinding == "" {
		t.Errorf("a key binding JWT makes a presentation, got %+v", res)
	}
	if _, err := ingest.Decode([]byte("eyJhbGciOiJFUzI1NiJ9.e30.c2ln~!!~"), ingest.Options{Carrier: ingest.CarrierJSON}); err == nil {
		t.Error("a broken disclosure wants an error")
	}
}

func TestDecodeJWT(t *testing.T) {
	token := jwt(t, map[string]any{"vct": "https://example.test/pid"})
	res, err := ingest.Decode([]byte(token), ingest.Options{Carrier: ingest.CarrierQR})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != vc.FormatJWT || res.Detected != ingest.TypeCredential || len(res.Credentials) != 1 {
		t.Errorf("result = %+v", res)
	}
	vpToken := jwt(t, map[string]any{"vp": map[string]any{"verifiableCredential": []any{token, map[string]any{"id": "x"}, 7}}})
	res, err = ingest.Decode([]byte(vpToken), ingest.Options{Carrier: ingest.CarrierQR})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePresentation || len(res.Credentials) != 2 {
		t.Errorf("vp result = %+v", res)
	}
}

func TestDecodeJSONPresentation(t *testing.T) {
	doc := jsonText(t, map[string]any{
		"@context":             []string{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": map[string]any{"type": []string{"VerifiableCredential"}},
		"proof":                map[string]any{"jwt": "kb"},
	})
	res, err := ingest.Decode([]byte(doc), ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePresentation || res.KeyBinding != "kb" || len(res.Credentials) != 1 {
		t.Errorf("result = %+v", res)
	}
	credential := jsonText(t, map[string]any{"@context": []string{"x"}, "type": []string{"VerifiableCredential"}})
	res, err = ingest.Decode([]byte(credential), ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeCredential || res.Format != vc.FormatJSONLD {
		t.Errorf("credential result = %+v", res)
	}
	res, err = ingest.Decode([]byte(`{"a":`), ingest.Options{Carrier: ingest.CarrierJSON})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeUnknown {
		t.Errorf("broken JSON is not a credential, got %+v", res)
	}
}

func TestDecodeMdocAndUnknown(t *testing.T) {
	res, err := ingest.Decode([]byte{0xa1, 0x61, 0x61, 0x01}, ingest.Options{Carrier: ingest.CarrierQR})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != vc.FormatMdoc || len(res.Credentials) != 1 {
		t.Errorf("mdoc result = %+v", res)
	}
	res, err = ingest.Decode([]byte("just some text"), ingest.Options{Carrier: ingest.CarrierQR})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeUnknown {
		t.Errorf("unknown result = %+v", res)
	}
	if _, err := ingest.Decode([]byte(" "), ingest.Options{Carrier: ingest.CarrierQR}); err == nil {
		t.Error("blank text wants an error")
	}
}

func TestDecodeClaim169Carrier(t *testing.T) {
	text := claim169QR(t, map[any]any{"name": "Asha"}, true)
	res, err := ingest.Decode([]byte(text), ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Carrier != ingest.CarrierClaim169 || res.Detected != ingest.TypeCWTClaim169 {
		t.Errorf("result = %+v", res)
	}
	if !strings.Contains(string(res.Payload), "Asha") || len(res.Credentials) != 1 {
		t.Errorf("payload = %s", res.Payload)
	}
	if strings.Join(res.Steps, ",") != "base45,zlib,cose_sign1,cwt" {
		t.Errorf("steps = %v", res.Steps)
	}
}

func TestDecodePixelPassFallback(t *testing.T) {
	inner := jsonText(t, map[string]any{"@context": []string{"x"}, "type": []string{"VerifiableCredential"}})
	code, err := pixelpass.Encode([]byte(inner))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ingest.Decode([]byte(code), ingest.Options{Carrier: ingest.CarrierClaim169})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeCredential || res.Steps[0] != "base45" {
		t.Errorf("result = %+v", res)
	}
	plain, err := pixelpass.Encode([]byte("PLAIN TEXT"))
	if err != nil {
		t.Fatal(err)
	}
	res, err = ingest.Decode([]byte(plain), ingest.Options{Carrier: ingest.CarrierClaim169})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePixelPass {
		t.Errorf("a payload the decoder does not know is a legacy PixelPass code, got %+v", res)
	}
	if _, err := ingest.Decode([]byte("ABCDEFGHIJ"), ingest.Options{Carrier: ingest.CarrierClaim169}); err == nil {
		t.Error("text that is neither wants an error")
	}
	empty, err := pixelpass.Encode([]byte("\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.Decode([]byte(empty), ingest.Options{Carrier: ingest.CarrierClaim169}); err == nil {
		t.Error("an empty PixelPass payload wants an error")
	}
}

func TestDecodeRequest(t *testing.T) {
	res, err := ingest.Decode([]byte("openid4vp://authorize?client_id=verifier&nonce=n1&request_uri=https%3A%2F%2Fa.test%2Fr%2F1"), ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Carrier != ingest.CarrierOID4VPRequest || res.Detected != ingest.TypeRequest {
		t.Errorf("result = %+v", res)
	}
	if !strings.Contains(string(res.Payload), `"nonce":"n1"`) {
		t.Errorf("payload = %s", res.Payload)
	}
	if _, err := ingest.Decode([]byte("openid4vp://authorize"), ingest.Options{Carrier: ingest.CarrierOID4VPRequest}); err == nil {
		t.Error("a request without a parameter wants an error")
	}
	if _, err := ingest.Decode([]byte("openid4vp://%zz"), ingest.Options{Carrier: ingest.CarrierOID4VPRequest}); err == nil {
		t.Error("a URL that does not parse wants an error")
	}
}

func TestDecodeVPToken(t *testing.T) {
	token := jwt(t, map[string]any{"vct": "x"})
	res, err := ingest.Decode([]byte(token), ingest.Options{Carrier: ingest.CarrierOID4VPResponse})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePresentation || res.Steps[0] != "vp_token" {
		t.Errorf("single token result = %+v", res)
	}
	list := jsonText(t, []any{token, sdjwtToken, 7})
	res, err = ingest.Decode([]byte(list), ingest.Options{Carrier: ingest.CarrierOID4VPResponse})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != 2 {
		t.Errorf("array result = %+v", res)
	}
	byQuery := jsonText(t, map[string]any{"pid": []any{sdjwtToken}, "licence": token})
	res, err = ingest.Decode([]byte(byQuery), ingest.Options{Carrier: ingest.CarrierOID4VPResponse})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != 2 {
		t.Errorf("map result = %+v", res)
	}
	if _, err := ingest.Decode([]byte("  "), ingest.Options{Carrier: ingest.CarrierOID4VPResponse}); err == nil {
		t.Error("an empty vp_token wants an error")
	}
}

func TestDecodeVPTokenFallsBackToJSON(t *testing.T) {
	doc := jsonText(t, map[string]any{"type": []string{"VerifiablePresentation"}, "verifiableCredential": []any{}})
	res, err := ingest.Decode([]byte(doc), ingest.Options{Carrier: ingest.CarrierOID4VPResponse})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePresentation {
		t.Errorf("result = %+v", res)
	}
	numbers := jsonText(t, []any{1, 2})
	if _, err := ingest.Decode([]byte(numbers), ingest.Options{Carrier: ingest.CarrierOID4VPResponse}); err != nil {
		t.Fatalf("a list without tokens falls back to the JSON reader: %v", err)
	}
}

func TestDecodeImageCarrier(t *testing.T) {
	png := qrPNG(t, sdjwtToken)
	res, err := ingest.Decode(png, ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Carrier != ingest.CarrierImage || res.Steps[0] != "image" || res.Format != vc.FormatSDJWT {
		t.Errorf("result = %+v", res)
	}
	if _, err := ingest.Decode([]byte("\x89PNG\r\n\x1a\nbroken"), ingest.Options{}); err == nil {
		t.Error("a broken image wants an error")
	}
	blank := qrPNG(t, "x")
	_ = blank
	if _, err := ingest.DecodeImage(plainPNG(t)); err == nil {
		t.Error("an image without a QR code wants an error")
	}
}

func TestHash(t *testing.T) {
	if ingest.Hash([]byte("a")) == ingest.Hash([]byte("b")) {
		t.Error("different bytes give different hashes")
	}
	if len(ingest.Hash(nil)) != 64 {
		t.Error("the hash is 64 hex characters")
	}
}

func TestCarriersList(t *testing.T) {
	if len(ingest.Carriers) != 8 {
		t.Errorf("the package names 8 carriers, got %d", len(ingest.Carriers))
	}
}
