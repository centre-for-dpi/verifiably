// SPDX-License-Identifier: Apache-2.0

package qr

// matrix is the module grid while the encoder builds it.
type matrix struct {
	version int
	size    int
	// dark holds the module colour. True is dark.
	dark []bool
	// fixed marks the modules of the function patterns. The data mask
	// never changes them.
	fixed []bool
}

func newMatrix(version int) *matrix {
	size := 17 + 4*version
	return &matrix{
		version: version,
		size:    size,
		dark:    make([]bool, size*size),
		fixed:   make([]bool, size*size),
	}
}

func (m *matrix) set(x, y int, dark, fixed bool) {
	if x < 0 || y < 0 || x >= m.size || y >= m.size {
		return
	}
	m.dark[y*m.size+x] = dark
	if fixed {
		m.fixed[y*m.size+x] = true
	}
}

func (m *matrix) at(x, y int) bool { return m.dark[y*m.size+x] }

func (m *matrix) isFixed(x, y int) bool { return m.fixed[y*m.size+x] }

// drawFunctionPatterns draws every pattern that is not data: the finder
// patterns, the separators, the alignment patterns, the timing patterns,
// the dark module, the format areas, and the version areas.
func (m *matrix) drawFunctionPatterns() {
	m.drawFinder(0, 0)
	m.drawFinder(m.size-7, 0)
	m.drawFinder(0, m.size-7)
	m.drawAlignment()
	m.drawTiming()
	// The dark module sits next to the lower left finder pattern.
	m.set(8, m.size-8, true, true)
	m.reserveFormat()
	m.drawVersion()
}

// drawFinder draws one 7 by 7 finder pattern and its separator.
func (m *matrix) drawFinder(x0, y0 int) {
	for dy := -1; dy <= 7; dy++ {
		for dx := -1; dx <= 7; dx++ {
			x, y := x0+dx, y0+dy
			if x < 0 || y < 0 || x >= m.size || y >= m.size {
				continue
			}
			inner := dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6
			ring := dx == 0 || dx == 6 || dy == 0 || dy == 6
			core := dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4
			m.set(x, y, inner && (ring || core), true)
		}
	}
}

// drawAlignment draws every alignment pattern of the version. A pattern
// that overlaps a finder pattern is left out.
func (m *matrix) drawAlignment() {
	centers := alignmentCenters[m.version-1]
	last := len(centers) - 1
	for i, cx := range centers {
		for j, cy := range centers {
			if i == 0 && j == 0 || i == 0 && j == last || i == last && j == 0 {
				continue
			}
			m.drawAlignmentAt(cx, cy)
		}
	}
}

func (m *matrix) drawAlignmentAt(cx, cy int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			ring := dx == -2 || dx == 2 || dy == -2 || dy == 2
			m.set(cx+dx, cy+dy, ring || (dx == 0 && dy == 0), true)
		}
	}
}

// drawTiming draws the two timing patterns on the row and the column 6.
func (m *matrix) drawTiming() {
	for i := 8; i < m.size-8; i++ {
		on := i%2 == 0
		m.set(i, 6, on, true)
		m.set(6, i, on, true)
	}
}

// reserveFormat marks the format information modules as function
// modules. drawFormat fills them after the mask is known.
func (m *matrix) reserveFormat() {
	for i := 0; i <= 8; i++ {
		if i != 6 {
			m.set(i, 8, false, true)
			m.set(8, i, false, true)
		}
	}
	for i := 0; i < 8; i++ {
		m.set(m.size-1-i, 8, false, true)
	}
	for i := 0; i < 7; i++ {
		m.set(8, m.size-1-i, false, true)
	}
}

// drawVersion draws the version information of the versions 7 and above.
func (m *matrix) drawVersion() {
	if m.version < 7 {
		return
	}
	bits := versionBits(m.version)
	for i := 0; i < 18; i++ {
		on := bits&(1<<uint(i)) != 0
		x, y := i/3, m.size-11+i%3
		m.set(x, y, on, true)
		m.set(y, x, on, true)
	}
}

// versionBits returns the 18 bit version information: six version bits
// and a twelve bit BCH remainder.
func versionBits(version int) int {
	rem := version
	for i := 0; i < 12; i++ {
		rem <<= 1
		if rem&(1<<12) != 0 {
			rem ^= 0x1f25
		}
	}
	return version<<12 | rem
}

// formatBits returns the 15 bit format information of the mask at level M.
func formatBits(mask int) int {
	data := levelBits<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem <<= 1
		if rem&(1<<10) != 0 {
			rem ^= 0x537
		}
	}
	return (data<<10 | rem) ^ 0x5412
}

// drawFormat writes the format information in both of its places.
func (m *matrix) drawFormat(mask int) {
	bits := formatBits(mask)
	get := func(i int) bool { return bits&(1<<uint(i)) != 0 }
	// The first copy runs around the upper left finder pattern.
	for i := 0; i <= 5; i++ {
		m.set(8, i, get(i), true)
	}
	m.set(8, 7, get(6), true)
	m.set(8, 8, get(7), true)
	m.set(7, 8, get(8), true)
	for i := 9; i <= 14; i++ {
		m.set(14-i, 8, get(i), true)
	}
	// The second copy splits between the other two finder patterns.
	for i := 0; i <= 7; i++ {
		m.set(m.size-1-i, 8, get(i), true)
	}
	for i := 8; i <= 14; i++ {
		m.set(8, m.size-15+i, get(i), true)
	}
}

// placeData writes the codeword bits in the zigzag order of the
// standard: two module columns at a time, from the lower right corner,
// skipping the vertical timing pattern.
func (m *matrix) placeData(codewords []byte) {
	bit := 0
	up := true
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for step := 0; step < m.size; step++ {
			y := m.size - 1 - step
			if !up {
				y = step
			}
			for dx := 0; dx < 2; dx++ {
				x := right - dx
				if m.isFixed(x, y) {
					continue
				}
				on := false
				if i := bit / 8; i < len(codewords) {
					on = codewords[i]&(1<<uint(7-bit%8)) != 0
				}
				m.set(x, y, on, false)
				bit++
			}
		}
		up = !up
	}
}

// maskAt reports whether the mask pattern flips the module.
func maskAt(pattern, x, y int) bool {
	switch pattern {
	case 0:
		return (y+x)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (y+x)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (y*x)%2+(y*x)%3 == 0
	case 6:
		return ((y*x)%2+(y*x)%3)%2 == 0
	default:
		return ((y+x)%2+(y*x)%3)%2 == 0
	}
}

// applyMask flips every data module the pattern selects.
func (m *matrix) applyMask(pattern int) {
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if m.isFixed(x, y) {
				continue
			}
			if maskAt(pattern, x, y) {
				m.dark[y*m.size+x] = !m.dark[y*m.size+x]
			}
		}
	}
}

// bestMask returns the mask pattern with the lowest penalty score.
func (m *matrix) bestMask() int {
	best, bestScore := 0, -1
	for pattern := 0; pattern < 8; pattern++ {
		m.applyMask(pattern)
		m.drawFormat(pattern)
		score := m.penalty()
		m.applyMask(pattern)
		if bestScore < 0 || score < bestScore {
			best, bestScore = pattern, score
		}
	}
	return best
}

// penalty returns the sum of the four penalty scores of the standard.
func (m *matrix) penalty() int {
	return m.penaltyRuns() + m.penaltyBlocks() + m.penaltyFinderLike() + m.penaltyBalance()
}

// penaltyRuns scores runs of five or more modules of the same colour.
func (m *matrix) penaltyRuns() int {
	score := 0
	count := func(get func(i int) bool) {
		run, prev := 1, get(0)
		for i := 1; i < m.size; i++ {
			cur := get(i)
			if cur == prev {
				run++
				continue
			}
			if run >= 5 {
				score += run - 2
			}
			run, prev = 1, cur
		}
		if run >= 5 {
			score += run - 2
		}
	}
	for y := 0; y < m.size; y++ {
		row := y
		count(func(i int) bool { return m.at(i, row) })
	}
	for x := 0; x < m.size; x++ {
		col := x
		count(func(i int) bool { return m.at(col, i) })
	}
	return score
}

// penaltyBlocks scores every two by two block of one colour.
func (m *matrix) penaltyBlocks() int {
	score := 0
	for y := 0; y < m.size-1; y++ {
		for x := 0; x < m.size-1; x++ {
			v := m.at(x, y)
			if m.at(x+1, y) == v && m.at(x, y+1) == v && m.at(x+1, y+1) == v {
				score += 3
			}
		}
	}
	return score
}

// finderLike is the 1:1:3:1:1 run the third penalty rule looks for.
var finderLike = [11]bool{true, false, true, true, true, false, true, false, false, false, false}

// penaltyFinderLike scores patterns that look like a finder pattern.
func (m *matrix) penaltyFinderLike() int {
	score := 0
	check := func(get func(i int) bool) {
		for start := 0; start+11 <= m.size; start++ {
			forward, backward := true, true
			for i := 0; i < 11; i++ {
				if get(start+i) != finderLike[i] {
					forward = false
				}
				if get(start+i) != finderLike[10-i] {
					backward = false
				}
			}
			if forward {
				score += 40
			}
			if backward {
				score += 40
			}
		}
	}
	for y := 0; y < m.size; y++ {
		row := y
		check(func(i int) bool { return m.at(i, row) })
	}
	for x := 0; x < m.size; x++ {
		col := x
		check(func(i int) bool { return m.at(col, i) })
	}
	return score
}

// penaltyBalance scores how far the share of dark modules is from half.
func (m *matrix) penaltyBalance() int {
	darkCount := 0
	for _, v := range m.dark {
		if v {
			darkCount++
		}
	}
	total := m.size * m.size
	// k is the largest whole number for which the share of dark modules
	// is outside 50 plus or minus 5k percent. The integer form avoids
	// floating point rounding.
	diff := darkCount*20 - total*10
	if diff < 0 {
		diff = -diff
	}
	k := (diff+total-1)/total - 1
	return k * 10
}
