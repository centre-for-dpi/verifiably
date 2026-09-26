// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"
)

// TestListWalksOnlyTheFolderOfThePrefix: a list of one prefix reads the
// folder of that prefix, not the whole store, so a sweep of a few
// records stays cheap next to many others (ADR-056 decision 5).
func TestListWalksOnlyTheFolderOfThePrefix(t *testing.T) {
	dir := t.TempDir()
	for prefix, want := range map[string]string{
		"":              dir,
		"authz":         dir,
		"authz/":        filepath.Join(dir, "authz"),
		"authz/logins":  filepath.Join(dir, "authz"),
		"authz/logins/": filepath.Join(dir, "authz", "logins"),
		"offer/ab":      filepath.Join(dir, "offer"),
	} {
		if got := walkRoot(dir, prefix); got != want {
			t.Errorf("walkRoot(%q) = %q, want %q", prefix, got, want)
		}
	}
	kv, err := File(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, key := range []string{"authz/logins/a", "authz/codes/b", "offer/c"} {
		if err := kv.Put(ctx, key, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	for prefix, want := range map[string]int{"authz/logins/": 1, "authz/": 2, "authz": 2, "": 3, "missing/": 0, "offer/c": 1} {
		keys, err := kv.List(ctx, prefix)
		if err != nil || len(keys) != want {
			t.Errorf("List(%q) = %v, %v; want %d keys", prefix, keys, err, want)
		}
	}
}
