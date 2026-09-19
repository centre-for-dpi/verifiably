// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

// mustAs converts v to type T. It stops the test on another type.
func mustAs[T any](t *testing.T, v any) T {
	t.Helper()
	out, ok := v.(T)
	if !ok {
		t.Fatalf("want type %T, got %T", out, v)
	}
	return out
}
