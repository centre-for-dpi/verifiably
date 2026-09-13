// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// checkStructure reads the file back: it checks the header, the object
// count, the cross reference offsets, and the trailer.
func checkStructure(t *testing.T, file []byte) int {
	t.Helper()
	if !bytes.HasPrefix(file, []byte("%PDF-1.4\n")) {
		t.Fatal("the file does not start with the PDF 1.4 header")
	}
	if !bytes.HasSuffix(file, []byte("%%EOF\n")) {
		t.Fatal("the file does not end with the end of file marker")
	}
	startIdx := bytes.LastIndex(file, []byte("startxref\n"))
	if startIdx < 0 {
		t.Fatal("no startxref")
	}
	rest := string(file[startIdx+len("startxref\n"):])
	offset, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0]))
	if err != nil {
		t.Fatalf("startxref is not a number: %v", err)
	}
	if offset <= 0 || offset >= len(file) || !bytes.HasPrefix(file[offset:], []byte("xref\n")) {
		t.Fatalf("the startxref offset %d does not point at the table", offset)
	}
	table := string(file[offset:])
	lines := strings.Split(table, "\n")
	count, err := strconv.Atoi(strings.Fields(lines[1])[1])
	if err != nil {
		t.Fatalf("the object count is not a number: %v", err)
	}
	for i := 1; i < count; i++ {
		entry := strings.Fields(lines[2+i])
		at, err := strconv.Atoi(entry[0])
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		want := []byte(strconv.Itoa(i) + " 0 obj\n")
		if !bytes.HasPrefix(file[at:], want) {
			t.Fatalf("entry %d points at %q, want %q", i, file[at:at+12], want)
		}
	}
	if !bytes.Contains(file, []byte("/Root 1 0 R")) {
		t.Fatal("the trailer has no catalogue reference")
	}
	return count - 1
}

// contentStream returns the page content of the file.
func contentStream(t *testing.T, file []byte) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)4 0 obj\n<< /Length \d+ /Filter /FlateDecode >>\nstream\n(.*?)\nendstream`)
	m := re.FindSubmatch(file)
	if m == nil {
		t.Fatal("no page content stream")
	}
	r, err := zlib.NewReader(bytes.NewReader(m[1]))
	if err != nil {
		t.Fatalf("open the content stream: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the content stream: %v", err)
	}
	return string(out)
}

func TestEmptyDocumentHasTheExpectedObjects(t *testing.T) {
	d := New("Empty")
	file := d.Bytes()
	if got := checkStructure(t, file); got != 9 {
		t.Fatalf("object count = %d, want 9", got)
	}
	if !bytes.Contains(file, []byte("/MediaBox [0 0 595.28 841.89]")) {
		t.Fatal("the page is not A4")
	}
	if bytes.Contains(file, []byte("/XObject")) {
		t.Fatal("an empty document must carry no image")
	}
	if !bytes.Contains(file, []byte("/Title (Empty)")) {
		t.Fatal("the title is missing")
	}
}

func TestTextWritesTheOperators(t *testing.T) {
	d := New("Text")
	d.Text(HelveticaBold, 12, 20, 700, 0.2, "Name: Ada")
	content := contentStream(t, d.Bytes())
	if !strings.Contains(content, "/F1 12.00 Tf") {
		t.Fatalf("content %q does not select the bold font", content)
	}
	if !strings.Contains(content, "(Name: Ada) Tj") {
		t.Fatalf("content %q does not hold the text", content)
	}
	if !strings.Contains(content, "0.200 g") {
		t.Fatalf("content %q does not set the grey", content)
	}
}

func TestTextCenteredUsesTheFontMetrics(t *testing.T) {
	d := New("Centre")
	text := "Farmer Credential"
	d.TextCentered(Helvetica, 22, 780, 0, text)
	content := contentStream(t, d.Bytes())
	want := (PageWidth - TextWidth(Helvetica, 22, text)) / 2
	if !strings.Contains(content, strconv.FormatFloat(want, 'f', 2, 64)+" 780.00 Td") {
		t.Fatalf("content %q does not centre the line at %.2f", content, want)
	}
}

func TestLineWritesAStrokeOperator(t *testing.T) {
	d := New("Line")
	d.Line(40, 700, 555, 700, 0.5, 0.8)
	content := contentStream(t, d.Bytes())
	if !strings.Contains(content, "40.00 700.00 m 555.00 700.00 l S") {
		t.Fatalf("content %q has no line", content)
	}
	if !strings.Contains(content, "0.800 G 0.50 w") {
		t.Fatalf("content %q has no stroke settings", content)
	}
}

// testImage returns a small checked image.
func testImage(w, h int) Image {
	stride := (w + 7) / 8
	px := make([]byte, stride*h)
	for i := range px {
		px[i] = 0xA5
	}
	return Image{Width: w, Height: h, Pixels: px}
}

func TestImageAddsAnXObject(t *testing.T) {
	d := New("Image")
	if err := d.Image(testImage(16, 16), 100, 200, 240); err != nil {
		t.Fatalf("Image: %v", err)
	}
	file := d.Bytes()
	if got := checkStructure(t, file); got != 10 {
		t.Fatalf("object count = %d, want 10", got)
	}
	if !bytes.Contains(file, []byte("/XObject << /Im0 10 0 R >>")) {
		t.Fatal("the resource dictionary has no image")
	}
	if !bytes.Contains(file, []byte("/Width 16 /Height 16 /ColorSpace /DeviceGray /BitsPerComponent 1")) {
		t.Fatal("the image dictionary is wrong")
	}
	if !strings.Contains(contentStream(t, file), "q 240.00 0 0 240.00 100.00 200.00 cm /Im0 Do Q") {
		t.Fatal("the content stream does not place the image")
	}
}

func TestImageRejectsAMismatchedSize(t *testing.T) {
	d := New("Bad")
	cases := []Image{
		{Width: 0, Height: 8, Pixels: make([]byte, 8)},
		{Width: 8, Height: 0, Pixels: make([]byte, 8)},
		{Width: 8, Height: 8, Pixels: make([]byte, 4)},
	}
	for i, img := range cases {
		if err := d.Image(img, 0, 0, 10); !errors.Is(err, ErrBadImage) {
			t.Fatalf("case %d: error = %v, want ErrBadImage", i, err)
		}
	}
}

func TestImageReplacesAnEarlierImage(t *testing.T) {
	d := New("Two")
	if err := d.Image(testImage(8, 8), 0, 0, 10); err != nil {
		t.Fatalf("first image: %v", err)
	}
	if err := d.Image(testImage(24, 24), 0, 0, 10); err != nil {
		t.Fatalf("second image: %v", err)
	}
	if !bytes.Contains(d.Bytes(), []byte("/Width 24 /Height 24")) {
		t.Fatal("the second image did not replace the first")
	}
}

func TestEscapeMakesAStringSafe(t *testing.T) {
	cases := map[string]string{
		"plain":            "plain",
		"a(b)c\\d":         `a\(b\)c\\d`,
		"line\nbreak":      "line break",
		"tab\there":        "tab here",
		"return\rhere":     "return here",
		"café":             "caf?",
		"\x01control":      "?control",
		"emoji \U0001F600": "emoji ?",
	}
	for in, want := range cases {
		if got := escape(in); got != want {
			t.Fatalf("escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClampKeepsGreyInRange(t *testing.T) {
	if clamp(-1) != 0 || clamp(2) != 1 || clamp(0.4) != 0.4 {
		t.Fatal("clamp is wrong")
	}
}

func TestResourceNameFallsBackToTheRegularFont(t *testing.T) {
	if got := resourceName("Times-Roman"); got != "F0" {
		t.Fatalf("resourceName = %q, want F0", got)
	}
	if got := resourceName(Courier); got != "F3" {
		t.Fatalf("resourceName(Courier) = %q, want F3", got)
	}
}

func TestTextWidthMatchesTheFontMetrics(t *testing.T) {
	cases := []struct {
		font Font
		text string
		want float64
	}{
		{Helvetica, "AB", (667 + 667) * 10.0 / 1000},
		{HelveticaBold, "AB", (722 + 722) * 10.0 / 1000},
		{HelveticaOblique, " ", 278 * 10.0 / 1000},
		{Courier, "abcd", 4 * 600 * 10.0 / 1000},
		{Helvetica, "é", 278 * 10.0 / 1000},
	}
	for _, c := range cases {
		if got := TextWidth(c.font, 10, c.text); got != c.want {
			t.Fatalf("TextWidth(%s, %q) = %v, want %v", c.font, c.text, got, c.want)
		}
	}
}

func TestImageResourcesIsEmptyWithoutAnImage(t *testing.T) {
	if got := imageResources(nil); got != "" {
		t.Fatalf("imageResources(nil) = %q, want an empty string", got)
	}
}
