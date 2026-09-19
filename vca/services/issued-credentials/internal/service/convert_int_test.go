// SPDX-License-Identifier: Apache-2.0

package service

import (
	"math"
	"testing"
)

func TestToInt32Clamps(t *testing.T) {
	if got := toInt32(7); got != 7 {
		t.Fatalf("want 7, got %d", got)
	}
	if got := toInt32(math.MaxInt32 + 1); got != math.MaxInt32 {
		t.Fatalf("want the upper limit, got %d", got)
	}
	if got := toInt32(math.MinInt32 - 1); got != math.MinInt32 {
		t.Fatalf("want the lower limit, got %d", got)
	}
}
