// SPDX-License-Identifier: Apache-2.0

package qr

// A scanner finds a symbol by its three finder patterns. The ZXing
// reader, which the ingest service and many MOSIP readers use, scans the
// rows from the top. It stops once it confirms three patterns of one
// module size. A shape in the data area can pass its test for a finder
// pattern. When the reader confirms such a shape before it reaches the
// lower left finder pattern, it reads the wrong grid and the symbol does
// not scan. The penalty rules of ISO/IEC 18004 allow that shape, so the
// encoder counts it on its own and prefers a mask without it.

// falseFinders counts the dark modules outside the three finder
// patterns that pass the row and column tests of the ZXing
// FinderPatternFinder in module units:
//
//  1. the row reads 1:1:3:1:1 and spans seven modules, so the module
//     size matches the real patterns and the reader stops early;
//  2. the column reads 1:1:3:1:1, no side run is longer than the centre
//     run of the row, and its span is within two fifths of the row.
//
// The reader also walks a diagonal, pixel by pixel. That walk depends on
// the pixel scale, so the count leaves it out. The count then holds
// every shape the reader can confirm, and some it rejects.
func (m *matrix) falseFinders() int {
	count := 0
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if m.at(x, y) && !m.inFinder(x, y) && m.passesFinderTests(x, y) {
				count++
			}
		}
	}
	return count
}

// passesFinderTests applies the tests of falseFinders to the dark module
// at x and y.
func (m *matrix) passesFinderTests(x, y int) bool {
	row := m.runsThrough(x, y, 1, 0)
	if sum(row) != 7 || !finderRatio(row) {
		return false
	}
	col := m.runsThrough(x, y, 0, 1)
	centre := row[2]
	if col[0] > centre || col[1] > centre || col[3] >= centre || col[4] >= centre {
		return false
	}
	return 5*abs(sum(col)-7) < 2*7 && finderRatio(col)
}

// inFinder reports whether the module belongs to one of the three
// finder patterns.
func (m *matrix) inFinder(x, y int) bool {
	far := m.size - 7
	return (x < 7 || x >= far) && y < 7 || x < 7 && y >= far
}

// runsThrough returns the five runs a scanner reads through the dark
// module at x and y along the step dx and dy: the dark run before the
// light run before the module, that light run, the dark run of the
// module, the light run after it, and the dark run after that. A run
// stops at the edge of the symbol. The margin beyond the edge is light,
// so a light run that reaches the edge leaves the outer dark run empty.
func (m *matrix) runsThrough(x, y, dx, dy int) [5]int {
	// run counts the modules of one colour from the offset from along
	// the step s.
	run := func(from, s int, dark bool) int {
		n := 0
		for i := from; ; i += s {
			px, py := x+i*dx, y+i*dy
			if px < 0 || py < 0 || px >= m.size || py >= m.size || m.at(px, py) != dark {
				return n
			}
			n++
		}
	}
	var runs [5]int
	before := run(0, -1, true)
	after := run(1, 1, true)
	runs[2] = before + after
	runs[1] = run(-before, -1, false)
	if runs[1] > 0 {
		runs[0] = run(-before-runs[1], -1, true)
	}
	runs[3] = run(1+after, 1, false)
	if runs[3] > 0 {
		runs[4] = run(1+after+runs[3], 1, true)
	}
	return runs
}

// finderRatio applies the test of ZXing foundPatternCross to five runs:
// every run is present, and each is within half a module of 1, 1, 3, 1,
// 1 modules, where a module is a seventh of the total. In whole numbers,
// |share total/7 - run| < share total/14 becomes
// 2 |share total - 7 run| < share total.
func finderRatio(runs [5]int) bool {
	total := 0
	for _, r := range runs {
		if r == 0 {
			return false
		}
		total += r
	}
	for i, r := range runs {
		share := 1
		if i == 2 {
			share = 3
		}
		if 2*abs(share*total-7*r) >= share*total {
			return false
		}
	}
	return true
}

// sum returns the total of the runs.
func sum(runs [5]int) int {
	return runs[0] + runs[1] + runs[2] + runs[3] + runs[4]
}

// abs returns the absolute value of n.
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
