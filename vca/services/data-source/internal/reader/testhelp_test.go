// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"io"
	"testing"
)

// mustWrite writes b to w. It reports a write error.
func mustWrite(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Errorf("the write failed: %v", err)
	}
}
