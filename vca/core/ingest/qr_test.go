// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"encoding/json"
	"image"
	"image/color"
	"os"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/qr"
)

// symbolImage draws a symbol at four pixels a module with the margin of
// four modules the standard asks for.
func symbolImage(code qr.Code) image.Image {
	const scale, quiet = 4, 4
	width := (code.Size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, width, width))
	for y := 0; y < width; y++ {
		for x := 0; x < width; x++ {
			v := uint8(0xff)
			if code.Module(x/scale-quiet, y/scale-quiet) {
				v = 0
			}
			img.SetGray(x, y, color.Gray{Y: v})
		}
	}
	return img
}

// TestDecodeQRImageReadsASymbolWithAFalseFinder reads the Claim 169
// codes of core/qr/testdata/false-finders.json under the masks that hold
// a finder shape in the data. A single pass of the finder stops at that
// shape and misses the lower left finder pattern. The scanner must still
// read the symbol, as a stack may print it that way.
func TestDecodeQRImageReadsASymbolWithAFalseFinder(t *testing.T) {
	raw, err := os.ReadFile("../qr/testdata/false-finders.json")
	if err != nil {
		t.Fatalf("read the cases: %v", err)
	}
	var cases []struct {
		Masks []int  `json:"masks"`
		Text  string `json:"text"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) == 0 {
		t.Fatalf("parse the cases: %v", err)
	}
	for i, c := range cases {
		for _, mask := range c.Masks {
			code, err := qr.EncodeMask([]byte(c.Text), 11, mask)
			if err != nil {
				t.Fatalf("case %d: EncodeMask %d: %v", i, mask, err)
			}
			got, err := ingest.DecodeQRImage(symbolImage(code))
			if err != nil || got != c.Text {
				t.Errorf("case %d, mask %d: the scanner cannot read the symbol: %v", i, mask, err)
				continue
			}
			if _, _, err := ingest.DecodeClaim169(got); err != nil {
				t.Errorf("case %d, mask %d: DecodeClaim169: %v", i, mask, err)
			}
		}
	}
}
