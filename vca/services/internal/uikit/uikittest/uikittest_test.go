// SPDX-License-Identifier: Apache-2.0

package uikittest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// fakeT records the failures the assert helper reports.
type fakeT struct {
	testing.TB
	dir  string
	msgs []string
}

func (f *fakeT) Helper()        {}
func (f *fakeT) Error(a ...any) { f.msgs = append(f.msgs, fmt.Sprint(a...)) }
func (f *fakeT) Fatal(a ...any) { f.msgs = append(f.msgs, fmt.Sprint(a...)) }

// TempDir returns a path that is a file, so a write under it fails.
func (f *fakeT) TempDir() string { return f.dir }

func TestLowContrastFileFailsOnThePairing(t *testing.T) {
	path := LowContrastFile(t)
	_, err := themefile.Load(path)
	AssertBadThemeError(t, err, path)
	if got := Problems(err, path); len(got) != 0 {
		t.Errorf("problems = %v", got)
	}
}

func TestProblemsNameEveryGap(t *testing.T) {
	if got := Problems(nil, "x.yaml"); len(got) != 1 {
		t.Errorf("nil error: %v", got)
	}
	if got := Problems(errors.New("config: something else"), "x.yaml"); len(got) != 2 {
		t.Errorf("other error: %v", got)
	}
	if got := Problems(errors.New("theme file x.yaml: version: 2 is not supported; use 1"), "x.yaml"); len(got) != 1 {
		t.Errorf("wrong rule: %v", got)
	}
	ft := &fakeT{}
	AssertBadThemeError(ft, nil, "x.yaml")
	if len(ft.msgs) != 1 {
		t.Errorf("AssertBadThemeError reported %d problems, want 1", len(ft.msgs))
	}
}

func TestLowContrastFileReportsAWriteFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ft := &fakeT{dir: file}
	LowContrastFile(ft)
	if len(ft.msgs) != 1 {
		t.Errorf("LowContrastFile reported %d problems, want 1", len(ft.msgs))
	}
}
