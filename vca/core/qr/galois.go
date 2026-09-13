// SPDX-License-Identifier: Apache-2.0

package qr

// The Reed Solomon code of ISO/IEC 18004 works in GF(256) with the
// primitive polynomial x^8 + x^4 + x^3 + x^2 + 1, which is 0x11d.

// expTable holds the powers of the primitive element 2.
var expTable = buildExp()

// logTable holds the discrete logarithm to the base 2.
var logTable = buildLog(expTable)

func buildExp() [512]byte {
	var t [512]byte
	x := 1
	for i := 0; i < 255; i++ {
		t[i] = byte(x)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		t[i] = t[i-255]
	}
	return t
}

func buildLog(exp [512]byte) [256]byte {
	var t [256]byte
	for i := 0; i < 255; i++ {
		t[exp[i]] = byte(i)
	}
	return t
}

// mul returns the product of a and b in GF(256).
func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[int(logTable[a])+int(logTable[b])]
}

// generator returns the Reed Solomon generator polynomial of degree n.
// The coefficients run from the highest power to the constant term.
func generator(n int) []byte {
	poly := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(poly)+1)
		root := expTable[i]
		for j, c := range poly {
			next[j] ^= c
			next[j+1] ^= mul(c, root)
		}
		poly = next
	}
	return poly
}

// errorCorrection returns the n error correction codewords of data.
func errorCorrection(data []byte, n int) []byte {
	gen := generator(n)
	rem := make([]byte, n)
	for _, d := range data {
		factor := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		if factor != 0 {
			for i := 0; i < n; i++ {
				rem[i] ^= mul(gen[i+1], factor)
			}
		}
	}
	return rem
}
