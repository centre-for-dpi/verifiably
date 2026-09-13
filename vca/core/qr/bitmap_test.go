// SPDX-License-Identifier: Apache-2.0

package qr

import "testing"

// pixelAt reports whether the pixel is dark.
func (b Bitmap) pixelAt(x, y int) bool {
	stride := (b.Width + 7) / 8
	return b.Pixels[y*stride+x/8]&(1<<uint(7-x%8)) == 0
}

func TestBitmapScalesEveryModule(t *testing.T) {
	code, err := Encode([]byte("bitmap"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const scale, quiet = 3, 4
	b := code.Bitmap(scale, quiet)
	want := (code.Size + 2*quiet) * scale
	if b.Width != want || b.Height != want {
		t.Fatalf("size %dx%d, want %d", b.Width, b.Height, want)
	}
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					px := (x+quiet)*scale + dx
					py := (y+quiet)*scale + dy
					if got := b.pixelAt(px, py); got != code.Module(x, y) {
						t.Fatalf("pixel (%d,%d) = %v, want %v", px, py, got, code.Module(x, y))
					}
				}
			}
		}
	}
}

func TestBitmapMarginIsLight(t *testing.T) {
	code, err := Encode([]byte("margin"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b := code.Bitmap(2, 4)
	for x := 0; x < b.Width; x++ {
		if b.pixelAt(x, 0) || b.pixelAt(x, b.Height-1) {
			t.Fatalf("the margin at the column %d is dark", x)
		}
	}
	for y := 0; y < b.Height; y++ {
		if b.pixelAt(0, y) || b.pixelAt(b.Width-1, y) {
			t.Fatalf("the margin at the row %d is dark", y)
		}
	}
}

func TestBitmapCorrectsAnInvalidScaleAndMargin(t *testing.T) {
	code, err := Encode([]byte("limits"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b := code.Bitmap(0, -1)
	if b.Width != code.Size {
		t.Fatalf("width = %d, want %d", b.Width, code.Size)
	}
	if got := b.pixelAt(0, 0); !got {
		t.Fatal("the upper left finder module must be dark without a margin")
	}
}
