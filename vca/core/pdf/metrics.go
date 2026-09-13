// SPDX-License-Identifier: Apache-2.0

package pdf

// The width tables come from the Adobe Core 14 font metrics. A value is
// the advance width of one character in units of 1/1000 of the font
// size. Index 0 is the space, which is the character 32.

// helveticaWidths holds the widths of Helvetica and Helvetica-Oblique.
var helveticaWidths = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
}

// boldWidths holds the widths of Helvetica-Bold.
var boldWidths = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
	975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
	333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
	611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
}

// courierWidth is the fixed advance width of every Courier character.
const courierWidth = 600

// TextWidth returns the width of the text in points.
func TextWidth(font Font, size float64, text string) float64 {
	total := 0
	for _, r := range text {
		total += charWidth(font, r)
	}
	return float64(total) * size / 1000
}

// charWidth returns the advance width of one character in units of
// 1/1000. An unknown character has the width of the space.
func charWidth(font Font, r rune) int {
	if font == Courier {
		return courierWidth
	}
	table := helveticaWidths
	if font == HelveticaBold {
		table = boldWidths
	}
	if r < 32 || r > 126 {
		return table[0]
	}
	return table[r-32]
}
