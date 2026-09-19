// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"math"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
)

func TestClaim169NotANumber(t *testing.T) {
	claims, err := cbor.Marshal(map[int64]any{169: map[any]any{"value": math.NaN()}})
	if err != nil {
		t.Fatal(err)
	}
	cwt, err := ingest.ParseCWT(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cwt.JSON(); err == nil {
		t.Error("a value that JSON cannot write wants an error")
	}
	text := pixelpass.EncodeBase45(deflate(t, sign1(t, claims, true)))
	if _, err := ingest.Decode([]byte(text), ingest.Options{Carrier: ingest.CarrierClaim169}); err == nil {
		t.Error("a claim 169 that JSON cannot write wants an error")
	}
}

func TestDecodeXMLCarrier(t *testing.T) {
	doc := "<root><vc>" + sampleSDJWT + "</vc></root>"
	res, err := ingest.Decode([]byte(doc), ingest.Options{XML: ingest.XMLConfig{Path: "root.vc"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Carrier != ingest.CarrierXML || res.Steps[0] != "xml" {
		t.Errorf("result = %+v", res)
	}
	if _, err := ingest.Decode([]byte(doc), ingest.Options{XML: ingest.XMLConfig{Path: "root.missing"}}); err == nil {
		t.Error("a path that matches nothing wants an error")
	}
}

func TestXMLNestedElement(t *testing.T) {
	doc := "<root><vc>before<inner>skip</inner>after</vc></root>"
	got, err := ingest.DecodeXML([]byte(doc), ingest.XMLConfig{Path: "root.vc"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "beforeafter" {
		t.Errorf("text = %q", got)
	}
	open := "<root><vc>text"
	if _, err := ingest.DecodeXML([]byte(open), ingest.XMLConfig{Path: "root.vc"}); err == nil {
		t.Error("an element without an end tag wants an error")
	}
}

func TestPDFWithoutEndObject(t *testing.T) {
	samples, width, height := grayImage(t, "NO ENDOBJ")
	stream := deflate(t, samples)
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%%PDF-1.7\n1 0 obj\n<< /Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray /Length %d >>\nstream\n", width, height, len(stream)))
	buf.Write(stream)
	buf.WriteString("\nendstream\n")
	text, err := ingest.DecodePDF(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if text != "NO ENDOBJ" {
		t.Errorf("text = %q", text)
	}
}

func TestPDFWithoutHeight(t *testing.T) {
	samples, width, _ := grayImage(t, "NO HEIGHT")
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /BitsPerComponent 8 /ColorSpace /DeviceGray", width)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, samples))); err == nil {
		t.Error("an image without a height wants an error")
	}
}

func TestPDFTruncatedStream(t *testing.T) {
	samples, width, height := grayImage(t, "TRUNCATED")
	stream := deflate(t, samples)
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray", width, height)
	// Cut the stream so the reader gets some bytes and then an error.
	short := stream[:len(stream)/2]
	body := pdfWithStream(dict, short)
	if _, err := ingest.ExtractPDFImages(body); err == nil {
		t.Error("a truncated image stream gives no usable image")
	}
}

func TestPDFPredictorWithoutColumns(t *testing.T) {
	samples, width, height := grayImage(t, "NO COLUMNS")
	rows := make([]byte, 0, (width+1)*height)
	for y := 0; y < height; y++ {
		rows = append(rows, 0)
		rows = append(rows, samples[y*width:(y+1)*width]...)
	}
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray "+
		"/DecodeParms << /Predictor 15 >>", width, height)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, rows))); err != nil {
		t.Fatalf("the width stands in for the columns: %v", err)
	}
}

func TestDecodeQRImageErrors(t *testing.T) {
	if _, err := ingest.DecodeQRImage(image.NewGray(image.Rect(0, 0, 0, 10))); err == nil {
		t.Error("an image with no width wants an error")
	}
	if _, err := ingest.DecodeQRImage(plainGray()); err == nil {
		t.Error("an image without a QR code wants an error")
	}
}

func TestDecodeTextClaim169(t *testing.T) {
	text := claim169QR(t, map[any]any{"name": "Asha"}, true)
	res, err := ingest.DecodeText(text)
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeCWTClaim169 {
		t.Errorf("result = %+v", res)
	}
}

func TestJWTWithoutJSONPayload(t *testing.T) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	token := head + "." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c2ln"
	if _, err := ingest.DecodeText(token); err == nil {
		t.Error("a payload that is not JSON wants an error")
	}
}

func TestPresentationWithoutCredentialMember(t *testing.T) {
	doc := jsonText(t, map[string]any{"type": []string{"VerifiablePresentation"}})
	res, err := ingest.DecodeText(doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypePresentation || len(res.Credentials) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestCredentialLimit(t *testing.T) {
	list := make([]any, 0, ingest.MaxCredentials+5)
	for i := 0; i < ingest.MaxCredentials+5; i++ {
		list = append(list, jwt(t, map[string]any{"n": i}))
	}
	doc := jsonText(t, map[string]any{"type": []string{"VerifiablePresentation"}, "verifiableCredential": list})
	res, err := ingest.DecodeText(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != ingest.MaxCredentials {
		t.Errorf("credentials = %d, want %d", len(res.Credentials), ingest.MaxCredentials)
	}
	tokens := jsonText(t, list)
	res, err = ingest.DecodeVPToken(tokens)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != ingest.MaxCredentials {
		t.Errorf("vp_token credentials = %d", len(res.Credentials))
	}
}

func TestVPTokenEdgeCases(t *testing.T) {
	// A list with one entry the text decoder refuses.
	res, err := ingest.DecodeVPToken(jsonText(t, []any{" ", sampleSDJWT}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Credentials) != 1 {
		t.Errorf("the decoder skips the entry it cannot read, got %+v", res)
	}
	// An object with no token falls back to the JSON reader.
	res, err = ingest.DecodeVPToken(jsonText(t, map[string]any{"pid": 7}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeCredential {
		t.Errorf("result = %+v", res)
	}
	// A list of tokens that decode to nothing falls back to the reader.
	res, err = ingest.DecodeVPToken(jsonText(t, []any{" "}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeUnknown {
		t.Errorf("result = %+v", res)
	}
}

func TestKeyBindingFromFirstToken(t *testing.T) {
	bound := sampleSDJWT + jwt(t, map[string]any{"nonce": "n"})
	res, err := ingest.DecodeVPToken(jsonText(t, []any{bound, sampleSDJWT}))
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyBinding == "" {
		t.Errorf("the key binding of the first token survives, got %+v", res)
	}
	if !strings.Contains(strings.Join(res.Steps, ","), "vp_token") {
		t.Errorf("steps = %v", res.Steps)
	}
}

func TestPDFWithoutLength(t *testing.T) {
	samples, width, height := grayImage(t, "NO LENGTH")
	stream := deflate(t, samples)
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%%PDF-1.7\n1 0 obj\n<< /Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray >>\nstream\n", width, height))
	buf.Write(stream)
	buf.WriteString("\nendstream\nendobj\n%%EOF\n")
	text, err := ingest.DecodePDF(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if text != "NO LENGTH" {
		t.Errorf("text = %q", text)
	}
}

func TestPDFPredictorBadColumns(t *testing.T) {
	dict := "/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 /BitsPerComponent 8 /ColorSpace /DeviceGray " +
		"/DecodeParms << /Predictor 15 /Columns 0 /Colors 0 >>"
	if _, err := ingest.ExtractPDFImages(pdfWithStream(dict, deflate(t, []byte{0, 1, 2, 3}))); err == nil {
		t.Error("a zero column predictor wants an error")
	}
}

func TestPDFStreamWithoutOutput(t *testing.T) {
	dict := "/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2"
	if _, err := ingest.ExtractPDFImages(pdfWithStream(dict, []byte{0x78, 0x9c, 0xff, 0xff, 0xff})); err == nil {
		t.Error("a zlib stream that gives no bytes wants an error")
	}
}

func TestDecodePDFWithoutImage(t *testing.T) {
	if _, err := ingest.Decode([]byte("%PDF-1.7\n%%EOF\n"), ingest.Options{}); err == nil {
		t.Error("a PDF without an image wants an error")
	}
}

func TestDecodeVPTokenBrokenToken(t *testing.T) {
	if _, err := ingest.DecodeVPToken("eyJhbGciOiJFUzI1NiJ9.e30.c2ln~!!~"); err == nil {
		t.Error("a broken token wants an error")
	}
	res, err := ingest.DecodeVPToken(`{"a":`)
	if err != nil {
		t.Fatal(err)
	}
	if res.Detected != ingest.TypeUnknown {
		t.Errorf("result = %+v", res)
	}
}

func TestXMLSyntaxError(t *testing.T) {
	if _, err := ingest.DecodeXML([]byte("<root><a ==></a></root>"), ingest.XMLConfig{Path: "root.a"}); err == nil {
		t.Error("a document with an attribute error wants an error")
	}
}
