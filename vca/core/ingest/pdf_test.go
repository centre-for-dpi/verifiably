// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	"image/jpeg"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
)

// pdfWithStream builds a one object PDF with the dictionary and stream.
func pdfWithStream(dict string, stream []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n1 0 obj\n<< " + dict + fmt.Sprintf(" /Length %d >>\nstream\n", len(stream)))
	buf.Write(stream)
	buf.WriteString("\nendstream\nendobj\n%%EOF\n")
	return buf.Bytes()
}

// grayImage renders a QR code as 8 bit grey samples.
func grayImage(t *testing.T, text string) (samples []byte, width, height int) {
	t.Helper()
	img := qrImage(t, text)
	b := img.Bounds()
	width, height = b.Dx(), b.Dy()
	samples = make([]byte, 0, width*height)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, _, _, _ := img.At(x, y).RGBA()
			samples = append(samples, byte(r>>8))
		}
	}
	return samples, width, height
}

func TestExtractPDFImagesGray(t *testing.T) {
	samples, width, height := grayImage(t, sampleSDJWT)
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray", width, height)
	pdf := pdfWithStream(dict, deflate(t, samples))
	text, err := ingest.DecodePDF(pdf)
	if err != nil {
		t.Fatal(err)
	}
	if text != sampleSDJWT {
		t.Errorf("text = %q", text)
	}
	res, err := ingest.Decode(pdf, ingest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Carrier != ingest.CarrierPDF || res.Steps[0] != "pdf" {
		t.Errorf("result = %+v", res)
	}
}

func TestExtractPDFImagesRGBAndPalette(t *testing.T) {
	samples, width, height := grayImage(t, "RGB")
	rgb := make([]byte, 0, len(samples)*3)
	for _, s := range samples {
		rgb = append(rgb, s, s, s)
	}
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceRGB", width, height)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, rgb))); err != nil {
		t.Fatalf("a DeviceRGB image must decode: %v", err)
	}
	cmyk := make([]byte, 0, len(samples)*4)
	for _, s := range samples {
		cmyk = append(cmyk, 0, 0, 0, 255-s)
	}
	dict = fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceCMYK", width, height)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, cmyk))); err != nil {
		t.Fatalf("a DeviceCMYK image must decode: %v", err)
	}
	// One bit indexed palette, black and white.
	packed := packBits(samples, width, height, 1)
	dict = fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 1 /ColorSpace [/Indexed /DeviceRGB 1 <000000 FFFFFF>]", width, height)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, packed))); err != nil {
		t.Fatalf("an indexed image must decode: %v", err)
	}
	// Four bit grey.
	packed4 := packBits(samples, width, height, 4)
	dict = fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 4 /ColorSpace /DeviceGray", width, height)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, packed4))); err != nil {
		t.Fatalf("a four bit image must decode: %v", err)
	}
}

// packBits packs 8 bit grey samples into bits samples for each pixel.
func packBits(samples []byte, width, height, bits int) []byte {
	rowLen := (width*bits + 7) / 8
	out := make([]byte, rowLen*height)
	maxValue := (1 << bits) - 1
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			value := int(samples[y*width+x]) * maxValue / 255
			bit := x * bits
			shift := 8 - bits - bit%8
			out[y*rowLen+bit/8] |= byte(value << shift)
		}
	}
	return out
}

func TestExtractPDFImagesPredictor(t *testing.T) {
	samples, width, height := grayImage(t, "PREDICTOR")
	rows := make([]byte, 0, (width+1)*height)
	previous := make([]byte, width)
	for y := 0; y < height; y++ {
		row := samples[y*width : (y+1)*width]
		rows = append(rows, 2)
		for x := 0; x < width; x++ {
			rows = append(rows, row[x]-previous[x])
		}
		previous = row
	}
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray "+
		"/DecodeParms << /Predictor 15 /Colors 1 /BitsPerComponent 8 /Columns %d >>", width, height, width)
	text, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, rows)))
	if err != nil {
		t.Fatal(err)
	}
	if text != "PREDICTOR" {
		t.Errorf("text = %q", text)
	}
}

func TestExtractPDFImagesPredictorFilters(t *testing.T) {
	samples, width, height := grayImage(t, "FILTERS")
	rows := make([]byte, 0, (width+1)*height)
	previous := make([]byte, width)
	for y := 0; y < height; y++ {
		row := samples[y*width : (y+1)*width]
		filter := byte(y % 5)
		rows = append(rows, filter)
		for x := 0; x < width; x++ {
			var left, up, upLeft byte
			if x > 0 {
				left, upLeft = row[x-1], previous[x-1]
			}
			up = previous[x]
			switch filter {
			case 1:
				rows = append(rows, row[x]-left)
			case 2:
				rows = append(rows, row[x]-up)
			case 3:
				rows = append(rows, row[x]-byte((int(left)+int(up))/2))
			case 4:
				rows = append(rows, row[x]-byte(paethTest(int(left), int(up), int(upLeft))))
			default:
				rows = append(rows, row[x])
			}
		}
		previous = row
	}
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray "+
		"/DecodeParms << /Predictor 12 /Columns %d >>", width, height, width)
	if _, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, rows))); err != nil {
		t.Fatalf("every PNG filter must decode: %v", err)
	}
}

// paethTest is the PNG Paeth predictor, for the test fixture.
func paethTest(a, b, c int) int {
	p := a + b - c
	pa, pb, pc := absTest(p-a), absTest(p-b), absTest(p-c)
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func absTest(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func TestExtractPDFImagesJPEG(t *testing.T) {
	img := qrImage(t, "JPEG QR CODE")
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatal(err)
	}
	dict := "/Subtype /Image /Filter /DCTDecode /Width 1 /Height 1"
	text, err := ingest.DecodePDF(pdfWithStream(dict, buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if text != "JPEG QR CODE" {
		t.Errorf("text = %q", text)
	}
	if _, err := ingest.ExtractPDFImages(pdfWithStream(dict, []byte("not a jpeg"))); err == nil {
		t.Error("a broken JPEG stream wants an error")
	}
}

func TestExtractPDFImagesWholePNG(t *testing.T) {
	dict := "/Subtype /Image /Filter /FlateDecode /Width 1 /Height 1"
	text, err := ingest.DecodePDF(pdfWithStream(dict, deflate(t, qrPNG(t, "PNG IN STREAM"))))
	if err != nil {
		t.Fatal(err)
	}
	if text != "PNG IN STREAM" {
		t.Errorf("text = %q", text)
	}
}

func TestExtractPDFImagesErrors(t *testing.T) {
	samples, width, height := grayImage(t, "ERRORS")
	good := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray", width, height)
	cases := []struct {
		name string
		pdf  []byte
	}{
		{"not a PDF", []byte("hello")},
		{"no object", []byte("%PDF-1.7\n%%EOF\n")},
		{"no stream", []byte("%PDF-1.7\n1 0 obj\n<< /Subtype /Image >>\nendobj\n")},
		{"no endstream", []byte("%PDF-1.7\n1 0 obj\n<< /Subtype /Image >>\nstream\nabc\nendobj\n")},
		{"no filter", pdfWithStream("/Subtype /Image /Width 1 /Height 1", []byte("x"))},
		{"unknown filter", pdfWithStream("/Subtype /Image /Filter /LZWDecode", []byte("x"))},
		{"broken stream", pdfWithStream("/Subtype /Image /Filter /FlateDecode", []byte("not zlib"))},
		{"no size", pdfWithStream("/Subtype /Image /Filter /FlateDecode", deflate(t, samples))},
		{"huge", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 99999999 /Height 99999999", deflate(t, samples))},
		{"bad colour space", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 /ColorSpace /Separation", deflate(t, samples))},
		{"bad palette", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 /ColorSpace [/Indexed /DeviceRGB 1 (raw)]", deflate(t, samples))},
		{"short palette", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 /ColorSpace [/Indexed /DeviceRGB 1 <00>]", deflate(t, samples))},
		{"odd palette", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 /ColorSpace [/Indexed /DeviceRGB 1 <zz00 00>]", deflate(t, samples))},
		{"bad depth", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2 /BitsPerComponent 16 /ColorSpace /DeviceGray", deflate(t, samples))},
		{"short stream", pdfWithStream(good, deflate(t, samples[:10]))},
		{"no QR code", pdfWithStream("/Subtype /Image /Filter /FlateDecode /Width 4 /Height 4 /BitsPerComponent 8 /ColorSpace /DeviceGray", deflate(t, bytes.Repeat([]byte{0xff}, 16)))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ingest.DecodePDF(c.pdf); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestExtractPDFImagesOversizeStream(t *testing.T) {
	big := deflate(t, make([]byte, ingest.MaxInflatedBytes+16))
	dict := "/Subtype /Image /Filter /FlateDecode /Width 2 /Height 2"
	if _, err := ingest.ExtractPDFImages(pdfWithStream(dict, big)); err == nil {
		t.Error("an oversized image stream wants an error")
	}
}

func TestExtractPDFImagesLimit(t *testing.T) {
	samples, width, height := grayImage(t, "LIMIT")
	dict := fmt.Sprintf("/Subtype /Image /Filter /FlateDecode /Width %d /Height %d /BitsPerComponent 8 /ColorSpace /DeviceGray", width, height)
	one := pdfWithStream(dict, deflate(t, samples))
	body := strings.TrimPrefix(string(one), "%PDF-1.7\n")
	body = strings.TrimSuffix(body, "%%EOF\n")
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	for i := 0; i < ingest.MaxPDFImages+2; i++ {
		buf.WriteString(body)
	}
	buf.WriteString("%%EOF\n")
	images, err := ingest.ExtractPDFImages(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != ingest.MaxPDFImages {
		t.Errorf("images = %d, want %d", len(images), ingest.MaxPDFImages)
	}
}

func TestDecodeQRFramesAndImage(t *testing.T) {
	frames := []image.Image{plainGray(), qrImage(t, "FRAMES")}
	text, err := ingest.DecodeQRFrames(frames)
	if err != nil {
		t.Fatal(err)
	}
	if text != "FRAMES" {
		t.Errorf("text = %q", text)
	}
	if _, err := ingest.DecodeQRFrames(nil); err == nil {
		t.Error("no frame wants an error")
	}
	if _, err := ingest.DecodeQRImage(image.NewGray(image.Rect(0, 0, 0, 0))); err == nil {
		t.Error("an empty image wants an error")
	}
}

// plainGray returns a small white image with no QR code.
func plainGray() image.Image {
	img := image.NewGray(image.Rect(0, 0, 16, 16))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	return img
}

// flateNoHeader checks the reader on a stream without a zlib header.
func TestInflateWithoutHeader(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ingest.Inflate(buf.Bytes()); err != nil {
		t.Fatalf("a zlib stream must inflate: %v", err)
	}
}
