// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/store"
)

func TestDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := s.Load("missing", &got); err != nil || got != nil {
		t.Fatalf("missing: %v %v", got, err)
	}
	if err := s.Save("list", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Load("list", &got); err != nil || len(got) != 2 {
		t.Fatalf("load: %v %v", got, err)
	}
	info, _ := os.Stat(filepath.Join(dir, "list.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	if err := s.Save("Bad Name", 1); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := s.Load("../etc", &got); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := s.Save("fn", func() {}); err == nil {
		t.Fatal("unmarshalable accepted")
	}
	_ = os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{"), 0o600)
	if err := s.Load("corrupt", &got); err == nil {
		t.Fatal("corrupt accepted")
	}
	// A directory in place of the file makes reads and writes fail.
	_ = os.Mkdir(filepath.Join(dir, "d.json"), 0o700)
	if err := s.Load("d", &got); err == nil {
		t.Fatal("dir read accepted")
	}
	if err := s.Save("d", 1); err == nil {
		t.Fatal("dir write accepted")
	}
	_ = os.Mkdir(filepath.Join(dir, "ro.json.tmp"), 0o700)
	if err := s.Save("ro", 1); err == nil {
		t.Fatal("tmp dir write accepted")
	}
	if _, err := store.Open(filepath.Join(dir, "list.json", "x")); err == nil {
		t.Fatal("open under a file accepted")
	}
	if p, err := store.New(""); err != nil || p == nil {
		t.Fatal("memory")
	}
	if p, err := store.New(filepath.Join(dir, "sub")); err != nil || p == nil {
		t.Fatal("dir")
	}
}
