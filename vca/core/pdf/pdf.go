// SPDX-License-Identifier: Apache-2.0

// Package pdf writes a small PDF 1.4 document without an external
// dependency (ADR-016 decision 3, ADR-030 decision 5).
//
// The package covers what a credential document needs: one A4 page, text
// in the standard Helvetica font, straight lines, and one image that
// carries the credential QR. The image is a one bit per pixel DeviceGray
// XObject, which is the shape the core/qr Bitmap has.
//
// All measurements are in PDF points. One point is 1/72 of an inch. The
// origin is the lower left corner of the page.
package pdf

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"strings"
)

// A4 page size in points.
const (
	// PageWidth is the width of an A4 page.
	PageWidth = 595.28
	// PageHeight is the height of an A4 page.
	PageHeight = 841.89
)

// Font names the Helvetica faces the package embeds by reference. A
// reader supplies the glyphs, so the file stays small.
type Font string

const (
	// Helvetica is the regular face.
	Helvetica Font = "Helvetica"
	// HelveticaBold is the bold face.
	HelveticaBold Font = "Helvetica-Bold"
	// HelveticaOblique is the slanted face.
	HelveticaOblique Font = "Helvetica-Oblique"
	// Courier is the fixed width face for credential text.
	Courier Font = "Courier"
)

// fontNames lists the faces in the order the resource dictionary uses.
var fontNames = []Font{Helvetica, HelveticaBold, HelveticaOblique, Courier}

// Image is a one bit per pixel grey image. A zero bit is black.
type Image struct {
	// Width is the pixel width.
	Width int
	// Height is the pixel height.
	Height int
	// Pixels holds the rows, most significant bit first. Every row
	// starts on a byte boundary.
	Pixels []byte
}

// ErrBadImage reports an image whose size does not match its pixels.
var ErrBadImage = errors.New("pdf: the image size does not match the pixel data")

// Doc collects the content of one page.
type Doc struct {
	ops   bytes.Buffer
	image *Image
	// title is the document title in the information dictionary.
	title string
}

// New returns an empty one page document with the title.
func New(title string) *Doc { return &Doc{title: title} }

// Text draws one line of text with its left edge at x and its baseline
// at y. Grey runs from 0 for black to 1 for white.
func (d *Doc) Text(font Font, size, x, y float64, grey float64, text string) {
	fmt.Fprintf(&d.ops, "BT /%s %.2f Tf %.3f g %.2f %.2f Td (%s) Tj ET\n",
		resourceName(font), size, clamp(grey), x, y, escape(text))
}

// TextCentered draws one line of text centred on the page width.
func (d *Doc) TextCentered(font Font, size, y float64, grey float64, text string) {
	width := TextWidth(font, size, text)
	d.Text(font, size, (PageWidth-width)/2, y, grey, text)
}

// Line draws a straight line of the given width in points.
func (d *Doc) Line(x1, y1, x2, y2, width, grey float64) {
	fmt.Fprintf(&d.ops, "%.3f G %.2f w %.2f %.2f m %.2f %.2f l S\n",
		clamp(grey), width, x1, y1, x2, y2)
}

// Image places the image with its lower left corner at x and y. The
// image fills a square of the given size in points. A document holds one
// image, so a second call replaces the first.
func (d *Doc) Image(img Image, x, y, size float64) error {
	stride := (img.Width + 7) / 8
	if img.Width <= 0 || img.Height <= 0 || len(img.Pixels) != stride*img.Height {
		return ErrBadImage
	}
	d.image = &img
	fmt.Fprintf(&d.ops, "q %.2f 0 0 %.2f %.2f %.2f cm /Im0 Do Q\n", size, size, x, y)
	return nil
}

// Bytes returns the finished PDF file.
func (d *Doc) Bytes() []byte {
	content := deflate(d.ops.Bytes())
	var objects [][]byte
	add := func(format string, args ...any) {
		objects = append(objects, []byte(fmt.Sprintf(format, args...)))
	}
	// 1 catalogue, 2 page tree, 3 page, 4 content, 5 information.
	add("<< /Type /Catalog /Pages 2 0 R >>")
	add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << %s >>%s >> /Contents 4 0 R >>",
		PageWidth, PageHeight, fontResources(), imageResources(d.image))
	objects = append(objects, stream(
		fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(content)), content))
	add("<< /Title (%s) /Producer (Verifiable Credentials Adapters) >>", escape(d.title))
	for i, name := range fontNames {
		add("<< /Type /Font /Subtype /Type1 /Name /F%d /BaseFont /%s /Encoding /WinAnsiEncoding >>", i, name)
	}
	if d.image != nil {
		pixels := deflate(d.image.Pixels)
		objects = append(objects, stream(fmt.Sprintf(
			"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray"+
				" /BitsPerComponent 1 /Filter /FlateDecode /Length %d >>",
			d.image.Width, d.image.Height, len(pixels)), pixels))
	}
	return assemble(objects)
}

// stream returns one indirect object that holds a stream.
func stream(dict string, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(dict)
	buf.WriteString("\nstream\n")
	buf.Write(body)
	buf.WriteString("\nendstream")
	return buf.Bytes()
}

// assemble writes the objects, the cross reference table, and the
// trailer. The objects are numbered from one in order.
func assemble(objects [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", i+1)
		buf.Write(obj)
		buf.WriteString("\nendobj\n")
	}
	start := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, start)
	return buf.Bytes()
}

// fontResources returns the font entries of the resource dictionary.
func fontResources() string {
	var b strings.Builder
	for i := range fontNames {
		fmt.Fprintf(&b, "/F%d %d 0 R ", i, 6+i)
	}
	return strings.TrimSpace(b.String())
}

// imageResources returns the XObject entry of the resource dictionary.
func imageResources(img *Image) string {
	if img == nil {
		return ""
	}
	return fmt.Sprintf(" /XObject << /Im0 %d 0 R >>", 6+len(fontNames))
}

// resourceName returns the resource name of the font.
func resourceName(font Font) string {
	for i, name := range fontNames {
		if name == font {
			return fmt.Sprintf("F%d", i)
		}
	}
	return "F0"
}

// deflate compresses the bytes with zlib.
func deflate(in []byte) []byte {
	var buf bytes.Buffer
	// Writes to a bytes.Buffer never fail.
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = w.Write(in)
	_ = w.Close()
	return buf.Bytes()
}

// clamp keeps a grey value between zero and one.
func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// escape makes a string safe inside PDF round brackets and drops the
// characters that WinAnsiEncoding cannot show.
func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 32 || r > 126:
			b.WriteByte('?')
		default:
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}
