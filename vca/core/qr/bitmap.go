// SPDX-License-Identifier: Apache-2.0

package qr

// Bitmap is a one bit per pixel image of a QR symbol. A zero bit is a
// dark pixel and a one bit is a light pixel, which is the convention of
// a PDF DeviceGray image with one bit per component. Every row starts on
// a byte boundary.
type Bitmap struct {
	// Width is the pixel width.
	Width int
	// Height is the pixel height. It equals Width.
	Height int
	// Pixels holds the rows, most significant bit first.
	Pixels []byte
}

// Bitmap returns the symbol as an image. Every module becomes a square of
// scale by scale pixels. The quiet value is the width of the light margin
// in modules. The standard asks for a margin of at least four modules.
// A value below one becomes one.
func (c Code) Bitmap(scale, quiet int) Bitmap {
	if scale < 1 {
		scale = 1
	}
	if quiet < 0 {
		quiet = 0
	}
	modules := c.Size + 2*quiet
	width := modules * scale
	stride := (width + 7) / 8
	pixels := make([]byte, stride*width)
	for i := range pixels {
		pixels[i] = 0xFF
	}
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.Module(x, y) {
				continue
			}
			for dy := 0; dy < scale; dy++ {
				row := ((y+quiet)*scale + dy) * stride
				for dx := 0; dx < scale; dx++ {
					px := (x+quiet)*scale + dx
					pixels[row+px/8] &^= 1 << uint(7-px%8)
				}
			}
		}
	}
	return Bitmap{Width: width, Height: width, Pixels: pixels}
}
