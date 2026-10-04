// SPDX-License-Identifier: Apache-2.0

package consenttest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryHolderAdapterRunsTheContract is the guard of ADR-081 decision
// 6: each adapter package holds a test that calls consenttest.Run.
func TestEveryHolderAdapterRunsTheContract(t *testing.T) {
	adapters, err := filepath.Glob(filepath.Join("..", "..", "dpg-adapter-*"))
	if err != nil || len(adapters) < 3 {
		t.Fatalf("found adapters %v (%v), want at least three", adapters, err)
	}
	for _, dir := range adapters {
		found := false
		werr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return err
			}
			raw, rerr := os.ReadFile(path) //nolint:gosec // G304: a test file of an adapter package under the walk
			if rerr != nil {
				return rerr
			}
			found = found || strings.Contains(string(raw), "consenttest.Run(")
			return nil
		})
		if werr != nil {
			t.Fatal(werr)
		}
		if !found {
			t.Errorf("%s runs no consenttest.Run against its holder service", filepath.Base(dir))
		}
	}
}
