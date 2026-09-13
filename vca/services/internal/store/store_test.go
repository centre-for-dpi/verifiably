// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func backends(t *testing.T) map[string]KeyValue {
	t.Helper()
	f, err := File(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]KeyValue{"memory": Memory(), "file": f}
}

func TestValidateKey(t *testing.T) {
	for _, ok := range []string{"a", "lists/abc-1.2_x", "A/B/C"} {
		if err := ValidateKey(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/a", "a/", "a//b", "a/../b", ".", "a b", "a/é", "a\\b"} {
		if err := ValidateKey(bad); !errors.Is(err, ErrBadKey) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestBackends(t *testing.T) {
	ctx := context.Background()
	for name, kv := range backends(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := kv.Get(ctx, "lists/a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("get missing: %v", err)
			}
			if err := kv.Put(ctx, "lists/a", []byte(`{"n":1}`)); err != nil {
				t.Fatal(err)
			}
			if err := kv.Put(ctx, "lists/b", []byte(`{"n":2}`)); err != nil {
				t.Fatal(err)
			}
			if err := kv.Put(ctx, "keys/k", []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			got, err := kv.Get(ctx, "lists/a")
			if err != nil || string(got) != `{"n":1}` {
				t.Fatalf("get: %s %v", got, err)
			}
			got[0] = 'x'
			if again, _ := kv.Get(ctx, "lists/a"); string(again) != `{"n":1}` {
				t.Fatal("get returned shared memory")
			}
			keys, err := kv.List(ctx, "lists/")
			if err != nil || strings.Join(keys, ",") != "lists/a,lists/b" {
				t.Fatalf("list: %v %v", keys, err)
			}
			all, _ := kv.List(ctx, "")
			if len(all) != 3 {
				t.Fatalf("list all: %v", all)
			}
			// CompareAndSwap
			if err := kv.CompareAndSwap(ctx, "lists/a", nil, []byte(`{}`)); !errors.Is(err, ErrConflict) {
				t.Fatalf("cas create over existing: %v", err)
			}
			if err := kv.CompareAndSwap(ctx, "lists/a", []byte(`{"n":9}`), []byte(`{}`)); !errors.Is(err, ErrConflict) {
				t.Fatalf("cas stale: %v", err)
			}
			if err := kv.CompareAndSwap(ctx, "lists/a", []byte(`{"n":1}`), []byte(`{"n":3}`)); err != nil {
				t.Fatalf("cas: %v", err)
			}
			if got, _ := kv.Get(ctx, "lists/a"); string(got) != `{"n":3}` {
				t.Fatalf("after cas: %s", got)
			}
			if err := kv.CompareAndSwap(ctx, "lists/c", []byte(`{}`), []byte(`{}`)); !errors.Is(err, ErrConflict) {
				t.Fatalf("cas update missing: %v", err)
			}
			if err := kv.CompareAndSwap(ctx, "lists/c", nil, []byte(`{"new":true}`)); err != nil {
				t.Fatalf("cas create: %v", err)
			}
			// Delete
			if err := kv.Delete(ctx, "lists/a"); err != nil {
				t.Fatal(err)
			}
			if err := kv.Delete(ctx, "lists/a"); err != nil {
				t.Fatalf("delete twice: %v", err)
			}
			if _, err := kv.Get(ctx, "lists/a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("after delete: %v", err)
			}
			// Empty value round trip.
			if err := kv.Put(ctx, "empty", nil); err != nil {
				t.Fatal(err)
			}
			if got, err := kv.Get(ctx, "empty"); err != nil || len(got) != 0 {
				t.Fatalf("empty: %v %v", got, err)
			}
			// Bad keys on every method.
			if _, err := kv.Get(ctx, "../x"); !errors.Is(err, ErrBadKey) {
				t.Fatal("get bad key")
			}
			if err := kv.Put(ctx, "", nil); !errors.Is(err, ErrBadKey) {
				t.Fatal("put bad key")
			}
			if err := kv.Delete(ctx, "a b"); !errors.Is(err, ErrBadKey) {
				t.Fatal("delete bad key")
			}
			if err := kv.CompareAndSwap(ctx, "a/", nil, nil); !errors.Is(err, ErrBadKey) {
				t.Fatal("cas bad key")
			}
		})
	}
}

func TestFileLayoutAndErrors(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	kv, err := File(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := kv.Put(ctx, "lists/a", []byte(`1`)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lists", "a.json")); err != nil {
		t.Fatal(err)
	}
	// A stray temporary file and a non JSON file are not keys.
	_ = os.WriteFile(filepath.Join(dir, "lists", ".b.json.tmp"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "lists", "notes.txt"), []byte("x"), 0o600)
	keys, err := kv.List(ctx, "")
	if err != nil || strings.Join(keys, ",") != "lists/a" {
		t.Fatalf("%v %v", keys, err)
	}
	// A directory in place of a file is a read error, not ErrNotFound.
	if err := os.MkdirAll(filepath.Join(dir, "dir.json", "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get(ctx, "dir"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("get dir: %v", err)
	}
	if err := kv.CompareAndSwap(ctx, "dir", nil, []byte("x")); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("cas dir: %v", err)
	}
	if err := kv.Delete(ctx, "dir"); err == nil {
		t.Fatal("delete dir")
	}
	// A file in place of a directory blocks writes and listing below it.
	if err := kv.Put(ctx, "lists/a.json/child", []byte("x")); err == nil {
		t.Fatal("put below a file")
	}
	// File() fails when the parent is a file.
	if _, err := File(filepath.Join(dir, "lists", "a.json", "sub")); err == nil {
		t.Fatal("File under a file")
	}
	// A write into an unwritable directory fails.
	if os.Getuid() != 0 {
		ro := filepath.Join(t.TempDir(), "ro")
		rkv, err := File(ro)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(ro, 0o700)
		if err := rkv.Put(ctx, "x", []byte("1")); err == nil {
			t.Fatal("write into read-only dir")
		}
		if err := os.Chmod(ro, 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := rkv.List(ctx, ""); err == nil {
			t.Fatal("list unreadable dir")
		}
	}
}

func TestFileRenameFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kv, err := File(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The target is a non-empty directory, so the rename fails.
	if err := os.MkdirAll(filepath.Join(dir, "k.json", "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := kv.Put(ctx, "k", []byte("1")); err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("rename: %v", err)
	}
}
