// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"testing"
)

// TestSyncHandsEachFreshStatusListOn: a sync of the status lists hands
// every list it read and checked to Refreshed, so the online copy of a
// check follows the sync. A refused list goes nowhere.
func TestSyncHandsEachFreshStatusListOn(t *testing.T) {
	w := newWorld(t)
	got := map[string]string{}
	c, err := New(Options{
		KV: w.kv, TrustURL: trustURL, Snapshot: w.export, Fetch: w.fetch, Defaults: offline(), Now: w.clock, Log: quiet,
		Refreshed: func(url string, body []byte) { got[url] = string(body) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Sync(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if got[listURL] != string(w.docs[listURL]) {
		t.Fatalf("the sync handed on %q for the list, want the list it read", got[listURL])
	}
	w.docs[listURL] = []byte("garbage")
	delete(got, listURL)
	if _, err := c.Sync(ctx, KindStatus); err != nil {
		t.Fatal(err)
	}
	if _, ok := got[listURL]; ok {
		t.Fatal("a refused list reached the online copy")
	}
}
