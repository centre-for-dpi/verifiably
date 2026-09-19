// SPDX-License-Identifier: Apache-2.0

package login_test

import (
	"io"
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

// mustWrite writes b to w. It reports a write error.
func mustWrite(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Errorf("the write failed: %v", err)
	}
}
