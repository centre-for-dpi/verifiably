// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"math"
	"testing"
)

func TestDictValue(t *testing.T) {
	cases := []struct {
		dict string
		key  string
		want string
	}{
		{"/Width 12 /Height 8", "Width", "12"},
		{"/Width 12", "Height", ""},
		{"/Filter /FlateDecode /Width 2", "Filter", "/FlateDecode"},
		{"/ColorSpace [/Indexed /DeviceRGB 1 <00>] /Width 2", "ColorSpace", "[/Indexed /DeviceRGB 1 <00>]"},
		{"/DecodeParms << /Predictor 15 >> /Width 2", "DecodeParms", "<< /Predictor 15 >>"},
		{"/Key <00FF> /Width 2", "Key", "<00FF>"},
		{"/Key <00FF", "Key", "<00FF"},
		{"/Key", "Key", ""},
		{"/Key  ", "Key", ""},
		{"/Key [1 2", "Key", "[1 2"},
		{"/Key value", "Key", "value"},
	}
	for _, c := range cases {
		if got := dictValue(c.dict, c.key); got != c.want {
			t.Errorf("dictValue(%q, %q) = %q, want %q", c.dict, c.key, got, c.want)
		}
	}
}

func TestNameToken(t *testing.T) {
	if got := nameToken("FlateDecode/Next"); got != "FlateDecode" {
		t.Errorf("nameToken = %q", got)
	}
	if got := nameToken("Plain"); got != "Plain" {
		t.Errorf("nameToken = %q", got)
	}
}

func TestDictInt(t *testing.T) {
	if _, ok := dictInt("/Width text", "Width"); ok {
		t.Error("a value that is not a number reports false")
	}
	if _, ok := dictInt("/Width 2", "Height"); ok {
		t.Error("a missing key reports false")
	}
	if n, ok := dictInt("/Width 24", "Width"); !ok || n != 24 {
		t.Errorf("dictInt = %d, %v", n, ok)
	}
}

func TestDictNames(t *testing.T) {
	if got := dictNames("/Width 2", "Filter"); got != nil {
		t.Errorf("a missing key gives no name, got %v", got)
	}
	got := dictNames("/Filter [/FlateDecode /DCTDecode] /Width 2", "Filter")
	if len(got) != 2 || got[1] != "DCTDecode" {
		t.Errorf("dictNames = %v", got)
	}
}

func TestSampleAndPaeth(t *testing.T) {
	row := []byte{0b10110000, 0xff}
	if got := sample(row, 0, 1); got != 1 {
		t.Errorf("one bit sample = %d", got)
	}
	if got := sample(row, 1, 1); got != 0 {
		t.Errorf("one bit sample = %d", got)
	}
	if got := sample(row, 0, 4); got != 0b1011 {
		t.Errorf("four bit sample = %d", got)
	}
	if got := sample(row, 1, 8); got != 0xff {
		t.Errorf("eight bit sample = %d", got)
	}
	if got := paeth(10, 20, 30); got != 10 {
		t.Errorf("paeth a = %d", got)
	}
	if got := paeth(10, 20, 5); got != 20 {
		t.Errorf("paeth b = %d", got)
	}
	if got := paeth(0, 100, 50); got != 50 {
		t.Errorf("paeth c = %d", got)
	}
	if got := abs(-3); got != 3 {
		t.Errorf("abs = %d", got)
	}
}

func TestUnfilterPNGErrors(t *testing.T) {
	if _, err := unfilterPNG([]byte{0, 1}, 0, 0, 8); err == nil {
		t.Error("a zero row length wants an error")
	}
	out, err := unfilterPNG([]byte{0, 1, 2, 0, 3}, 2, 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Errorf("a truncated last row still gives full rows, got %d bytes", len(out))
	}
	if _, err := unfilterPNG([]byte{0, 1, 2}, 2, 0, 8); err == nil {
		t.Error("zero colours gives a zero row length and an error")
	}
}

func TestColourSpaceIndexedErrors(t *testing.T) {
	if _, _, err := colourSpace("/ColorSpace [/Indexed /DeviceRGB 1 (raw)]"); err == nil {
		t.Error("a palette that is not hexadecimal wants an error")
	}
	_, palette, err := colourSpace("/ColorSpace [/Indexed /DeviceRGB 1 <0000000>]")
	if err != nil {
		t.Fatalf("an odd length palette takes a trailing zero: %v", err)
	}
	if len(palette) != 1 {
		t.Errorf("palette = %v", palette)
	}
	if _, _, err := colourSpace("/ColorSpace [/Indexed /DeviceRGB 1 <00>]"); err == nil {
		t.Error("a palette shorter than one entry wants an error")
	}
	if _, _, err := colourSpace("/ColorSpace [/Indexed /DeviceRGB 1 <GG00 00>]"); err == nil {
		t.Error("a palette outside the alphabet wants an error")
	}
}

func TestPixelIndexedOutOfRange(t *testing.T) {
	s := space{name: "Indexed", components: 1, indexed: true}
	got := pixel([]byte{0xff}, 0, 8, 255, s, nil)
	r, g, b, a := got.RGBA()
	if r != 0 || g != 0 || b != 0 || a == 0 {
		t.Errorf("an index outside the palette is opaque black, got %v", got)
	}
}

func TestRemovePredictorBelowTen(t *testing.T) {
	raw := []byte{1, 2, 3}
	out, err := removePredictor("/DecodeParms << /Predictor 2 >>", raw, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(raw) {
		t.Errorf("a predictor below ten changes nothing, got %d bytes", len(out))
	}
}

func TestAsIntRejectsOutOfRangeNumbers(t *testing.T) {
	if _, ok := asInt(uint64(math.MaxUint64)); ok {
		t.Fatal("a uint64 above MaxInt64 must not convert")
	}
	if _, ok := asInt(math.MaxFloat64); ok {
		t.Fatal("a float above MaxInt64 must not convert")
	}
	if _, ok := asInt(-math.MaxFloat64); ok {
		t.Fatal("a float below MinInt64 must not convert")
	}
}

func TestClamp8LimitsTheRange(t *testing.T) {
	if got := clamp8(-1); got != 0 {
		t.Fatalf("clamp8(-1) = %d", got)
	}
	if got := clamp8(300); got != 255 {
		t.Fatalf("clamp8(300) = %d", got)
	}
	if got := clamp8(7); got != 7 {
		t.Fatalf("clamp8(7) = %d", got)
	}
}
