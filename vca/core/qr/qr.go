// SPDX-License-Identifier: Apache-2.0

// Package qr encodes bytes as an ISO/IEC 18004 QR symbol.
//
// The package writes byte mode symbols at error correction level M, the
// level ADR-016 decision 4 asks for. It covers the versions 1 to 40 and
// picks the smallest version that holds the payload. The package is pure:
// it reads no files and makes no network calls.
//
// The output is a square module grid. A true module is dark.
package qr

import (
	"errors"
	"fmt"
)

// MaxVersion is the largest symbol version the package writes.
const MaxVersion = 40

// levelBits is the format information value of error correction level M.
const levelBits = 0

// ErrTooLong reports that no version holds the payload.
var ErrTooLong = errors.New("qr: the payload does not fit in a version 40 symbol")

// ErrEmpty reports an empty payload.
var ErrEmpty = errors.New("qr: the payload is empty")

// Code is one finished QR symbol.
type Code struct {
	// Version is the symbol version, 1 to 40.
	Version int
	// Size is the width and the height in modules.
	Size int
	// Mask is the data mask pattern the encoder chose, 0 to 7.
	Mask int

	modules []bool
}

// Module reports whether the module at the column x and the row y is
// dark. A position outside the symbol is light.
func (c Code) Module(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.modules[y*c.Size+x]
}

// Encode returns the smallest level M symbol that holds data.
func Encode(data []byte) (Code, error) {
	if len(data) == 0 {
		return Code{}, ErrEmpty
	}
	version, err := chooseVersion(len(data))
	if err != nil {
		return Code{}, err
	}
	return EncodeVersion(data, version)
}

// EncodeVersion returns a level M symbol of the named version with the
// data mask of the lowest penalty score. It fails when the version is out
// of range or too small for data.
func EncodeVersion(data []byte, version int) (Code, error) {
	return EncodeMask(data, version, -1)
}

// EncodeMask returns a level M symbol of the named version and data mask.
// A mask below zero selects the mask with the lowest penalty score.
func EncodeMask(data []byte, version, mask int) (Code, error) {
	if len(data) == 0 {
		return Code{}, ErrEmpty
	}
	if version < 1 || version > MaxVersion {
		return Code{}, fmt.Errorf("qr: version %d is not between 1 and %d", version, MaxVersion)
	}
	if mask > 7 {
		return Code{}, fmt.Errorf("qr: mask %d is not between 0 and 7", mask)
	}
	if need := len(data); need > capacityOf(version) {
		return Code{}, fmt.Errorf("qr: %d bytes do not fit in version %d, which holds %d: %w",
			need, version, capacityOf(version), ErrTooLong)
	}
	codewords := interleave(version, payload(data, version))
	m := newMatrix(version)
	m.drawFunctionPatterns()
	m.placeData(codewords)
	if mask < 0 {
		mask = m.bestMask()
	}
	m.applyMask(mask)
	m.drawFormat(mask)
	return Code{Version: version, Size: m.size, Mask: mask, modules: m.dark}, nil
}

// capacityOf returns the number of payload bytes a version holds.
func capacityOf(version int) int {
	// The header is the 4 bit mode indicator plus the character count.
	header := 4 + countBits(version)
	bits := plans[version-1].dataCodewords()*8 - header
	return bits / 8
}

// countBits returns the width of the character count indicator.
func countBits(version int) int {
	if version <= 9 {
		return 8
	}
	return 16
}

// chooseVersion returns the smallest version that holds n bytes.
func chooseVersion(n int) (int, error) {
	for v := 1; v <= MaxVersion; v++ {
		if n <= capacityOf(v) {
			return v, nil
		}
	}
	return 0, ErrTooLong
}

// bitWriter collects bits into codewords, most significant bit first.
type bitWriter struct {
	out  []byte
	bits int
}

func (w *bitWriter) write(value, n int) {
	for i := n - 1; i >= 0; i-- {
		if w.bits%8 == 0 {
			w.out = append(w.out, 0)
		}
		if value&(1<<i) != 0 {
			w.out[w.bits/8] |= 1 << (7 - w.bits%8)
		}
		w.bits++
	}
}

// payload returns the data codewords of the version: the header, the
// data, the terminator, and the pad codewords.
func payload(data []byte, version int) []byte {
	want := plans[version-1].dataCodewords()
	var w bitWriter
	// Mode indicator 0100 selects byte mode.
	w.write(4, 4)
	w.write(len(data), countBits(version))
	for _, b := range data {
		w.write(int(b), 8)
	}
	// The terminator is four zero bits. In byte mode the header is 12 or
	// 20 bits, so the free space is always at least four bits and the
	// standard never truncates the terminator here.
	// The header, the payload, and the terminator together always fill a
	// whole number of codewords, so no extra alignment bits are needed.
	w.write(0, 4)
	out := w.out
	for i := 0; len(out) < want; i++ {
		if i%2 == 0 {
			out = append(out, 0xEC)
		} else {
			out = append(out, 0x11)
		}
	}
	return out
}

// interleave splits the data into blocks, adds the error correction
// codewords of each block, and reads the blocks column by column.
func interleave(version int, data []byte) []byte {
	p := plans[version-1]
	blocks := make([][]byte, 0, p.blocks1+p.blocks2)
	ecs := make([][]byte, 0, p.blocks1+p.blocks2)
	at := 0
	add := func(count, size int) {
		for i := 0; i < count; i++ {
			b := data[at : at+size]
			at += size
			blocks = append(blocks, b)
			ecs = append(ecs, errorCorrection(b, p.ecPerBlock))
		}
	}
	add(p.blocks1, p.data1)
	add(p.blocks2, p.data2)
	out := make([]byte, 0, p.totalCodewords())
	maxData := p.data1
	if p.data2 > maxData {
		maxData = p.data2
	}
	for i := 0; i < maxData; i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < p.ecPerBlock; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	return out
}
