// SPDX-License-Identifier: Apache-2.0

package preview

import (
	"bytes"
	"fmt"
	"strings"
)

// PDF page geometry in points (A4).
const (
	pageWidth  = 595
	pageHeight = 842
	margin     = 56
	lineHeight = 16
	fontSize   = 11
	titleSize  = 18
	maxLine    = 80
)

// PDF renders the wallet card of p as a one page PDF document. The
// document uses the standard Helvetica font, so it needs no embedded
// font. Text outside Latin-1 becomes a question mark.
func PDF(p Preview) []byte {
	lines := []line{{text: p.Card.Title, size: titleSize}}
	if p.Card.Description != "" {
		lines = append(lines, line{text: p.Card.Description, size: fontSize})
	}
	lines = append(lines, line{text: "Format: " + p.Format, size: fontSize}, line{})
	for _, r := range p.Card.Rows {
		value := r.Value
		if r.SelectivelyDisclosable {
			value += " (selectively disclosable)"
		}
		for _, part := range wrap(r.Label + ": " + value) {
			lines = append(lines, line{text: part, size: fontSize})
		}
	}
	if len(p.Problems) > 0 {
		lines = append(lines, line{}, line{text: "Problems", size: fontSize})
		for _, problem := range p.Problems {
			for _, part := range wrap("- " + problem) {
				lines = append(lines, line{text: part, size: fontSize})
			}
		}
	}
	return document(content(lines))
}

type line struct {
	text string
	size int
}

// wrap splits text into parts of at most maxLine characters.
func wrap(text string) []string {
	runes := []rune(text)
	var parts []string
	for len(runes) > maxLine {
		cut := maxLine
		for i := maxLine; i > maxLine/2; i-- {
			if runes[i] == ' ' {
				cut = i
				break
			}
		}
		parts = append(parts, string(runes[:cut]))
		runes = runes[cut:]
		if len(runes) > 0 && runes[0] == ' ' {
			runes = runes[1:]
		}
	}
	return append(parts, string(runes))
}

// content builds the page content stream.
func content(lines []line) string {
	var b strings.Builder
	y := pageHeight - margin
	for _, l := range lines {
		if y < margin {
			break
		}
		if l.text != "" {
			fmt.Fprintf(&b, "BT /F1 %d Tf %d %d Td (%s) Tj ET\n", l.size, margin, y, escapePDF(l.text))
		}
		y -= lineHeight
		if l.size > fontSize {
			y -= l.size - fontSize
		}
	}
	return b.String()
}

// escapePDF encodes text for a PDF literal string.
func escapePDF(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 32 || r > 255:
			b.WriteByte('?')
		default:
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}

// document assembles the objects and the cross reference table.
func document(stream string) []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>", pageWidth, pageHeight),
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
	}
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return buf.Bytes()
}
