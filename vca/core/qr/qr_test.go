// SPDX-License-Identifier: Apache-2.0

package qr

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// vector is one reference symbol from testdata/vectors.json. The file
// comes from an independent encoder, so it proves the package writes the
// module grid of the standard and not only a self consistent one.
type vector struct {
	Name    string   `json:"name"`
	Data    string   `json:"data"`
	Version int      `json:"version"`
	Mask    int      `json:"mask"`
	Matrix  []string `json:"matrix"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var out []vector
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no vectors")
	}
	return out
}

func TestEncodeMatchesReferenceVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(v.Data)
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			chosen, err := Encode(data)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if chosen.Version != v.Version {
				t.Fatalf("version = %d, want %d", chosen.Version, v.Version)
			}
			// The reference encoder may pick another data mask. Every
			// mask is valid, so the grid is compared at the mask of the
			// reference symbol.
			code, err := EncodeMask(data, v.Version, v.Mask)
			if err != nil {
				t.Fatalf("EncodeMask: %v", err)
			}
			if code.Size != len(v.Matrix) {
				t.Fatalf("size = %d, want %d", code.Size, len(v.Matrix))
			}
			for y, row := range v.Matrix {
				for x, r := range row {
					want := r == '1'
					if got := code.Module(x, y); got != want {
						t.Fatalf("module (%d,%d) = %v, want %v", x, y, got, want)
					}
				}
			}
		})
	}
}

func TestModuleOutsideSymbolIsLight(t *testing.T) {
	code, err := Encode([]byte("edge"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, p := range [][2]int{{-1, 0}, {0, -1}, {code.Size, 0}, {0, code.Size}} {
		if code.Module(p[0], p[1]) {
			t.Fatalf("module %v is dark", p)
		}
	}
}

func TestEncodeRejectsEmptyPayload(t *testing.T) {
	if _, err := Encode(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Encode(nil) error = %v, want ErrEmpty", err)
	}
	if _, err := EncodeVersion(nil, 1); !errors.Is(err, ErrEmpty) {
		t.Fatalf("EncodeVersion(nil) error = %v, want ErrEmpty", err)
	}
}

func TestEncodeRejectsPayloadThatIsTooLong(t *testing.T) {
	tooLong := make([]byte, capacityOf(MaxVersion)+1)
	for i := range tooLong {
		tooLong[i] = 'x'
	}
	if _, err := Encode(tooLong); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Encode error = %v, want ErrTooLong", err)
	}
	if _, err := chooseVersion(len(tooLong)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("chooseVersion error = %v, want ErrTooLong", err)
	}
}

func TestEncodeVersionChecksTheVersionRange(t *testing.T) {
	for _, v := range []int{0, MaxVersion + 1} {
		if _, err := EncodeVersion([]byte("x"), v); err == nil {
			t.Fatalf("EncodeVersion(version %d) returned no error", v)
		}
	}
}

func TestEncodeVersionRejectsATooSmallVersion(t *testing.T) {
	data := make([]byte, capacityOf(1)+1)
	_, err := EncodeVersion(data, 1)
	if !errors.Is(err, ErrTooLong) {
		t.Fatalf("error = %v, want ErrTooLong", err)
	}
	if !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("error %q does not name the version", err)
	}
}

func TestEncodeVersionAcceptsALargerVersionThanNeeded(t *testing.T) {
	code, err := EncodeVersion([]byte("small payload"), 12)
	if err != nil {
		t.Fatalf("EncodeVersion: %v", err)
	}
	if code.Version != 12 || code.Size != 65 {
		t.Fatalf("version = %d size = %d, want 12 and 65", code.Version, code.Size)
	}
}

func TestEncodeFillsEveryVersionToItsCapacity(t *testing.T) {
	for v := 1; v <= MaxVersion; v++ {
		data := make([]byte, capacityOf(v))
		for i := range data {
			data[i] = byte('A' + i%26)
		}
		code, err := Encode(data)
		if err != nil {
			t.Fatalf("version %d: %v", v, err)
		}
		if code.Version != v {
			t.Fatalf("version %d: chose %d", v, code.Version)
		}
		if code.Size != 17+4*v {
			t.Fatalf("version %d: size %d", v, code.Size)
		}
	}
}

func TestBlockPlansMatchTheCodewordTable(t *testing.T) {
	for i, p := range plans {
		if got, want := p.totalCodewords(), totalCodewordsByVersion[i]; got != want {
			t.Fatalf("version %d: total codewords %d, want %d", i+1, got, want)
		}
	}
}

func TestPayloadPadsWithTheAlternatingPadCodewords(t *testing.T) {
	got := payload([]byte("A"), 1)
	want := []byte{0x40, 0x14, 0x10, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC}
	if len(got) != len(want) {
		t.Fatalf("length %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("codeword %d = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestPayloadUsesAShortTerminatorWhenTheSymbolIsFull(t *testing.T) {
	data := make([]byte, capacityOf(1))
	got := payload(data, 1)
	if len(got) != plans[0].dataCodewords() {
		t.Fatalf("length %d, want %d", len(got), plans[0].dataCodewords())
	}
}

func TestFormatBitsMatchTheStandardTable(t *testing.T) {
	// Level M format strings from ISO/IEC 18004 table C.1.
	want := []int{
		0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
	}
	for mask, w := range want {
		if got := formatBits(mask); got != w {
			t.Fatalf("mask %d: format %#x, want %#x", mask, got, w)
		}
	}
}

func TestVersionBitsMatchTheStandardTable(t *testing.T) {
	// Version information strings from ISO/IEC 18004 table D.1.
	want := map[int]int{7: 0x07C94, 8: 0x085BC, 21: 0x15683, 40: 0x28C69}
	for v, w := range want {
		if got := versionBits(v); got != w {
			t.Fatalf("version %d: %#x, want %#x", v, got, w)
		}
	}
}

func TestErrorCorrectionMatchesAKnownBlock(t *testing.T) {
	// The worked example of ISO/IEC 18004 annex I, version 1 level M.
	data := []byte{
		0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11,
		0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11,
	}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	got := errorCorrection(data, 10)
	if len(got) != len(want) {
		t.Fatalf("length %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("codeword %d = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestMulIsZeroWithAZeroFactor(t *testing.T) {
	if mul(0, 5) != 0 || mul(5, 0) != 0 {
		t.Fatal("a zero factor must give zero")
	}
	if mul(2, 3) != 6 {
		t.Fatalf("mul(2,3) = %d, want 6", mul(2, 3))
	}
}

func TestMaskAtCoversEveryPattern(t *testing.T) {
	want := []bool{true, true, true, true, true, true, true, true}
	for pattern := 0; pattern < 8; pattern++ {
		if got := maskAt(pattern, 0, 0); got != want[pattern] {
			t.Fatalf("mask %d at the origin = %v", pattern, got)
		}
	}
	// A second point separates the patterns from each other.
	seen := map[string]bool{}
	for pattern := 0; pattern < 8; pattern++ {
		key := ""
		for y := 0; y < 6; y++ {
			for x := 0; x < 6; x++ {
				if maskAt(pattern, x, y) {
					key += "1"
				} else {
					key += "0"
				}
			}
		}
		if seen[key] {
			t.Fatalf("mask %d repeats an earlier pattern", pattern)
		}
		seen[key] = true
	}
}

func TestPenaltyBalanceScoresAnAllDarkSymbol(t *testing.T) {
	m := newMatrix(1)
	for i := range m.dark {
		m.dark[i] = true
	}
	if got := m.penaltyBalance(); got != 90 {
		t.Fatalf("penalty = %d, want 90", got)
	}
	half := newMatrix(1)
	for i := range half.dark {
		half.dark[i] = i%2 == 0
	}
	if got := half.penaltyBalance(); got != 0 {
		t.Fatalf("balanced penalty = %d, want 0", got)
	}
}

func TestEncodeChoosesTheMaskWithTheLowestPenalty(t *testing.T) {
	data := []byte("choose the best data mask for this payload")
	code, err := Encode(data)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	best := -1
	for mask := 0; mask < 8; mask++ {
		other, err := EncodeMask(data, code.Version, mask)
		if err != nil {
			t.Fatalf("EncodeMask %d: %v", mask, err)
		}
		score := scoreOf(other)
		if best < 0 || score < best {
			best = score
		}
	}
	if got := scoreOf(code); got != best {
		t.Fatalf("penalty of the chosen mask = %d, want the lowest %d", got, best)
	}
}

// scoreOf returns the penalty score of a finished symbol.
func scoreOf(c Code) int {
	m := &matrix{version: c.Version, size: c.Size, dark: c.modules, fixed: make([]bool, c.Size*c.Size)}
	return m.penalty()
}

func TestEncodeMaskRejectsAMaskOutOfRange(t *testing.T) {
	if _, err := EncodeMask([]byte("x"), 1, 8); err == nil {
		t.Fatal("EncodeMask accepted the mask 8")
	}
}

func TestPenaltyFinderLikeFindsBothDirections(t *testing.T) {
	m := newMatrix(1)
	for x, on := range finderLike {
		m.dark[x] = on
	}
	if got := m.penaltyFinderLike(); got < 40 {
		t.Fatalf("penalty = %d, want at least 40", got)
	}
	m2 := newMatrix(1)
	for x, on := range finderLike {
		m2.dark[10-x] = on
	}
	if got := m2.penaltyFinderLike(); got < 40 {
		t.Fatalf("reversed penalty = %d, want at least 40", got)
	}
}

func TestSetIgnoresAPositionOutsideTheMatrix(t *testing.T) {
	m := newMatrix(1)
	m.set(-1, 0, true, true)
	m.set(0, -1, true, true)
	m.set(m.size, 0, true, true)
	m.set(0, m.size, true, true)
	for _, v := range m.dark {
		if v {
			t.Fatal("a module outside the matrix changed the grid")
		}
	}
}

func TestCountBitsSwitchesAtVersionTen(t *testing.T) {
	if countBits(9) != 8 || countBits(10) != 16 {
		t.Fatal("the character count width is wrong")
	}
}
