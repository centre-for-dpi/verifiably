// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"fmt"
	"math"
	"strconv"
)

// ParseHex converts "#RRGGBB" to its three 8-bit channel values.
func ParseHex(hex string) (r, g, b uint8, err error) {
	if len(hex) != 7 || hex[0] != '#' {
		return 0, 0, 0, fmt.Errorf("invalid hex colour %q", hex)
	}
	v, err := strconv.ParseUint(hex[1:], 16, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid hex colour %q", hex)
	}
	return uint8(v >> 16), uint8(v >> 8), uint8(v), nil
}

// RelativeLuminance computes the WCAG relative luminance of "#RRGGBB".
// See https://www.w3.org/TR/WCAG22/#dfn-relative-luminance.
func RelativeLuminance(hex string) (float64, error) {
	r, g, b, err := ParseHex(hex)
	if err != nil {
		return 0, err
	}
	lin := func(c uint8) float64 {
		s := float64(c) / 255
		if s <= 0.04045 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b), nil
}

// ContrastRatio returns the WCAG contrast ratio between two colours.
// The result is between 1 and 21.
// See https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio.
func ContrastRatio(fg, bg string) (float64, error) {
	l1, err := RelativeLuminance(fg)
	if err != nil {
		return 0, err
	}
	l2, err := RelativeLuminance(bg)
	if err != nil {
		return 0, err
	}
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05), nil
}
