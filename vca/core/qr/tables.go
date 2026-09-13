// SPDX-License-Identifier: Apache-2.0

package qr

// blockPlan describes how ISO/IEC 18004 splits the codewords of one
// version at error correction level M.
type blockPlan struct {
	// ecPerBlock is the number of error correction codewords per block.
	ecPerBlock int
	// blocks1 is the number of blocks in group one.
	blocks1 int
	// data1 is the number of data codewords in each group one block.
	data1 int
	// blocks2 is the number of blocks in group two.
	blocks2 int
	// data2 is the number of data codewords in each group two block.
	data2 int
}

// dataCodewords returns the number of data codewords of the version.
func (p blockPlan) dataCodewords() int {
	return p.blocks1*p.data1 + p.blocks2*p.data2
}

// totalCodewords returns the number of data and error correction
// codewords of the version.
func (p blockPlan) totalCodewords() int {
	return p.dataCodewords() + (p.blocks1+p.blocks2)*p.ecPerBlock
}

// plans holds the block plan of every version at level M. Index 0 is
// version 1.
var plans = [MaxVersion]blockPlan{
	{10, 1, 16, 0, 0},
	{16, 1, 28, 0, 0},
	{26, 1, 44, 0, 0},
	{18, 2, 32, 0, 0},
	{24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0},
	{18, 4, 31, 0, 0},
	{22, 2, 38, 2, 39},
	{22, 3, 36, 2, 37},
	{26, 4, 43, 1, 44},
	{30, 1, 50, 4, 51},
	{22, 6, 36, 2, 37},
	{22, 8, 37, 1, 38},
	{24, 4, 40, 5, 41},
	{24, 5, 41, 5, 42},
	{28, 7, 45, 3, 46},
	{28, 10, 46, 1, 47},
	{26, 9, 43, 4, 44},
	{26, 3, 44, 11, 45},
	{26, 3, 41, 13, 42},
	{26, 17, 42, 0, 0},
	{28, 17, 46, 0, 0},
	{28, 4, 47, 14, 48},
	{28, 6, 45, 14, 46},
	{28, 8, 47, 13, 48},
	{28, 19, 46, 4, 47},
	{28, 22, 45, 3, 46},
	{28, 3, 45, 23, 46},
	{28, 21, 45, 7, 46},
	{28, 19, 47, 10, 48},
	{28, 2, 46, 29, 47},
	{28, 10, 46, 23, 47},
	{28, 14, 46, 21, 47},
	{28, 14, 46, 23, 47},
	{28, 12, 47, 26, 48},
	{28, 6, 47, 34, 48},
	{28, 29, 46, 14, 47},
	{28, 13, 46, 32, 47},
	{28, 40, 47, 7, 48},
	{28, 18, 47, 31, 48},
}

// totalCodewordsByVersion is the codeword count of every version from
// ISO/IEC 18004 table 1. The tests compare it with the block plans.
var totalCodewordsByVersion = [MaxVersion]int{
	26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
	404, 466, 532, 581, 655, 733, 815, 901, 991, 1085,
	1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185,
	2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706,
}

// alignmentCenters holds the row and column centres of the alignment
// patterns of every version. Index 0 is version 1, which has none.
var alignmentCenters = [MaxVersion][]int{
	nil,
	{6, 18},
	{6, 22},
	{6, 26},
	{6, 30},
	{6, 34},
	{6, 22, 38},
	{6, 24, 42},
	{6, 26, 46},
	{6, 28, 50},
	{6, 30, 54},
	{6, 32, 58},
	{6, 34, 62},
	{6, 26, 46, 66},
	{6, 26, 48, 70},
	{6, 26, 50, 74},
	{6, 30, 54, 78},
	{6, 30, 56, 82},
	{6, 30, 58, 86},
	{6, 34, 62, 90},
	{6, 28, 50, 72, 94},
	{6, 26, 50, 74, 98},
	{6, 30, 54, 78, 102},
	{6, 28, 54, 80, 106},
	{6, 32, 58, 84, 110},
	{6, 30, 58, 86, 114},
	{6, 34, 62, 90, 118},
	{6, 26, 50, 74, 98, 122},
	{6, 30, 54, 78, 102, 126},
	{6, 26, 52, 78, 104, 130},
	{6, 30, 56, 82, 108, 134},
	{6, 34, 60, 86, 112, 138},
	{6, 30, 58, 86, 114, 142},
	{6, 34, 62, 90, 118, 146},
	{6, 30, 54, 78, 102, 126, 150},
	{6, 24, 50, 76, 102, 128, 154},
	{6, 28, 54, 80, 106, 132, 158},
	{6, 32, 58, 84, 110, 136, 162},
	{6, 26, 54, 82, 110, 138, 166},
	{6, 30, 58, 86, 114, 142, 170},
}
