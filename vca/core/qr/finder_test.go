// SPDX-License-Identifier: Apache-2.0

package qr

import (
	"encoding/json"
	"image"
	"image/color"
	"os"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// falseFinderCase is one payload of testdata/false-finders.json. The
// payloads are Claim 169 texts that failed to scan. Under each listed
// mask, the version 11 symbol holds a data shape that a single pass
// ZXing scanner takes for the third finder pattern.
type falseFinderCase struct {
	Masks []int  `json:"masks"`
	Text  string `json:"text"`
}

func loadFalseFinders(t *testing.T) []falseFinderCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/false-finders.json")
	if err != nil {
		t.Fatalf("read the cases: %v", err)
	}
	var out []falseFinderCase
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse the cases: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no cases")
	}
	return out
}

// scan reads a symbol the way the scanner of the ingest service reads
// a clean image: one pass of the ZXing QR reader, no hints.
func scan(t *testing.T, c Code) (string, error) {
	t.Helper()
	const scale, quiet = 4, 4
	b := c.Bitmap(scale, quiet)
	img := image.NewGray(image.Rect(0, 0, b.Width, b.Height))
	for y := 0; y < b.Height; y++ {
		for x := 0; x < b.Width; x++ {
			v := uint8(0xff)
			if b.pixelAt(x, y) {
				v = 0
			}
			img.SetGray(x, y, color.Gray{Y: v})
		}
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		t.Fatalf("bitmap: %v", err)
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		return "", err
	}
	return result.GetText(), nil
}

// TestEncodeAvoidsFalseFinderPatterns proves the encoder never picks a
// mask that hides the third finder pattern from a ZXing scanner, when
// another mask is free of such a shape.
func TestEncodeAvoidsFalseFinderPatterns(t *testing.T) {
	for i, c := range loadFalseFinders(t) {
		code, err := Encode([]byte(c.Text))
		if err != nil {
			t.Fatalf("case %d: Encode: %v", i, err)
		}
		if n := scoreFalseFinders(code); n != 0 {
			t.Errorf("case %d: mask %d holds %d false finder centres", i, code.Mask, n)
		}
		if got, err := scan(t, code); err != nil || got != c.Text {
			t.Errorf("case %d: the scanner cannot read mask %d: %v", i, code.Mask, err)
		}
		for _, mask := range c.Masks {
			bad, err := EncodeMask([]byte(c.Text), code.Version, mask)
			if err != nil {
				t.Fatalf("case %d: EncodeMask %d: %v", i, mask, err)
			}
			if scoreFalseFinders(bad) == 0 {
				t.Errorf("case %d: mask %d holds a false finder the count misses", i, mask)
			}
			if _, err := scan(t, bad); err == nil {
				t.Errorf("case %d: mask %d scans, so the case no longer covers a false finder", i, mask)
			}
		}
	}
}

// scoreFalseFinders counts the false finder centres of a finished symbol.
func scoreFalseFinders(c Code) int {
	m := &matrix{version: c.Version, size: c.Size, dark: c.modules, fixed: make([]bool, c.Size*c.Size)}
	return m.falseFinders()
}

func TestFalseFindersIgnoresTheThreeFinderPatterns(t *testing.T) {
	for _, version := range []int{1, 7, 40} {
		m := newMatrix(version)
		m.drawFunctionPatterns()
		if n := m.falseFinders(); n != 0 {
			t.Errorf("version %d: %d false finders in the function patterns", version, n)
		}
	}
}

func TestFalseFindersFindsAFinderShapeInTheData(t *testing.T) {
	m := newMatrix(5)
	m.drawFunctionPatterns()
	// A copy of a finder pattern in the middle of the data area, on a
	// light ground, is the shape a scanner confirms.
	const x0, y0 = 14, 14
	for dy := 0; dy < 7; dy++ {
		for dx := 0; dx < 7; dx++ {
			ring := dx == 0 || dx == 6 || dy == 0 || dy == 6
			core := dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4
			m.set(x0+dx, y0+dy, ring || core, false)
		}
	}
	if n := m.falseFinders(); n == 0 {
		t.Fatal("the copy of a finder pattern is not counted")
	}
	// A row that looks like a finder pattern is not enough: a scanner
	// checks the column through the centre too.
	row := newMatrix(5)
	row.drawFunctionPatterns()
	for dx, dark := range []bool{true, false, true, true, true, false, true} {
		row.set(x0+dx, y0+3, dark, false)
	}
	if n := row.falseFinders(); n != 0 {
		t.Fatalf("a row without the column ratio counts %d times", n)
	}
}

func TestFinderRatioFollowsTheScannerTolerance(t *testing.T) {
	cases := []struct {
		runs [5]int
		want bool
	}{
		{[5]int{1, 1, 3, 1, 1}, true},
		{[5]int{1, 1, 2, 1, 1}, true},
		{[5]int{1, 1, 4, 1, 1}, true},
		{[5]int{2, 2, 6, 2, 2}, true},
		{[5]int{1, 1, 1, 1, 1}, false},
		{[5]int{1, 1, 6, 1, 1}, true},
		{[5]int{1, 1, 8, 1, 1}, false},
		{[5]int{2, 1, 3, 1, 1}, false},
		{[5]int{1, 2, 3, 1, 1}, false},
		{[5]int{1, 1, 3, 2, 1}, false},
		{[5]int{1, 1, 3, 1, 2}, false},
		{[5]int{0, 1, 3, 1, 1}, false},
		{[5]int{1, 1, 3, 1, 0}, false},
	}
	for _, tc := range cases {
		if got := finderRatio(tc.runs); got != tc.want {
			t.Errorf("finderRatio(%v) = %v, want %v", tc.runs, got, tc.want)
		}
	}
}

func TestRunsStopAtTheEdgeOfTheSymbol(t *testing.T) {
	m := newMatrix(1)
	// A dark module at the left edge has no light run to its left, so
	// its row cannot read as a finder pattern.
	m.set(0, 10, true, false)
	runs := m.runsThrough(0, 10, 1, 0)
	if runs[0] != 0 || runs[1] != 0 || runs[2] != 1 {
		t.Fatalf("runs = %v", runs)
	}
}

// TestSymbolsWithoutFalseFindersScan checks the count against the
// reader on seeded random payloads: every mask without a false finder
// scans. The count may flag a mask that scans, never the reverse.
func TestSymbolsWithoutFalseFindersScan(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
	// A linear congruential generator gives the same payloads on every
	// run.
	state := uint64(169)
	next := func(n uint64) uint64 {
		state = state*6364136223846793005 + 1442695040888963407
		return (state >> 33) % n
	}
	for i := 0; i < 24; i++ {
		data := make([]byte, 20+next(400))
		for j := range data {
			data[j] = alphabet[next(uint64(len(alphabet)))]
		}
		v := version(t, data)
		for mask := 0; mask < 8; mask++ {
			code, err := EncodeMask(data, v, mask)
			if err != nil {
				t.Fatalf("EncodeMask: %v", err)
			}
			if scoreFalseFinders(code) > 0 {
				continue
			}
			if got, err := scan(t, code); err != nil || got != string(data) {
				t.Errorf("payload %d, mask %d: no false finder counted, yet the scan fails: %v", i, mask, err)
			}
		}
	}
}

// version returns the version Encode picks for data.
func version(t *testing.T, data []byte) int {
	t.Helper()
	code, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return code.Version
}
