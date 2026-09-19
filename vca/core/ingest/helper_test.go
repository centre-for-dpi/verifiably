// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/pixelpass"
	"github.com/fxamacker/cbor/v2"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// qrImage builds an image that holds the QR code of text.
func qrImage(t *testing.T, text string) image.Image {
	t.Helper()
	matrix, err := qrcode.NewQRCodeWriter().EncodeWithoutHint(text, gozxing.BarcodeFormat_QR_CODE, 240, 240)
	if err != nil {
		t.Fatalf("encode the QR code: %v", err)
	}
	img := image.NewGray(image.Rect(0, 0, matrix.GetWidth(), matrix.GetHeight()))
	for y := 0; y < matrix.GetHeight(); y++ {
		for x := 0; x < matrix.GetWidth(); x++ {
			value := uint8(0xff)
			if matrix.Get(x, y) {
				value = 0
			}
			img.SetGray(x, y, color.Gray{Y: value})
		}
	}
	return img
}

// qrPNG builds a PNG file that holds the QR code of text.
func qrPNG(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, qrImage(t, text)); err != nil {
		t.Fatalf("write the PNG: %v", err)
	}
	return buf.Bytes()
}

// deflate returns the zlib form of data.
func deflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

// sign1 wraps payload in an untagged or a tagged COSE_Sign1 message.
func sign1(t *testing.T, payload []byte, tagged bool) []byte {
	t.Helper()
	protected, err := cbor.Marshal(map[int64]any{1: -7, 4: []byte("key-1")})
	if err != nil {
		t.Fatalf("protected header: %v", err)
	}
	msg := []any{protected, map[any]any{}, payload, []byte("signature")}
	var out []byte
	if tagged {
		out, err = cbor.Marshal(cbor.Tag{Number: 18, Content: msg})
	} else {
		out, err = cbor.Marshal(msg)
	}
	if err != nil {
		t.Fatalf("COSE_Sign1: %v", err)
	}
	return out
}

// claim169QR builds the text of a MOSIP Claim 169 QR code.
func claim169QR(t *testing.T, data map[any]any, tagged bool) string {
	t.Helper()
	claims, err := cbor.Marshal(map[int64]any{
		1: "did:web:issuer.test", 2: "subject-1", 3: "verifier", 4: 1900000000, 5: 1700000000, 6: 1700000000,
		169: data,
	})
	if err != nil {
		t.Fatalf("CWT claims: %v", err)
	}
	return pixelpass.EncodeBase45(deflate(t, sign1(t, claims, tagged)))
}

// jsonText renders a value as compact JSON.
func jsonText(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("write JSON: %v", err)
	}
	return string(data)
}

// jwt builds an unsigned compact JWS with the payload.
func jwt(t *testing.T, payload any) string {
	t.Helper()
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(jsonText(t, payload)))
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

// plainPNG builds a white PNG with no QR code.
func plainPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 32, 32))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("write the PNG: %v", err)
	}
	return buf.Bytes()
}
