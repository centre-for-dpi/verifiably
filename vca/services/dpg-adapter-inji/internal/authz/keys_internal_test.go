// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// TestTheRingTakesTheKeyOfAnEarlierRelease: a store of an earlier
// release holds one sealed key under authz/key. The first start of the
// ring keeps that key, so the tokens and the key set of Certify stay
// valid through the upgrade.
func TestTheRingTakesTheKeyOfAnEarlierRelease(t *testing.T) {
	ctx := context.Background()
	secret := []byte("0123456789abcdef0123456789abcdef")
	aead, err := sealer(secret)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := makeKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(aead, keyStoreKey, legacy, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	kv := store.Memory()
	if perr := kv.Put(ctx, keyStoreKey, raw); perr != nil {
		t.Fatal(perr)
	}
	ring, err := loadRing(ctx, kv, secret)
	if err != nil {
		t.Fatalf("loadRing: %v", err)
	}
	now := time.Now()
	if got := ring.signer(now); got.public.KeyID != legacy.public.KeyID {
		t.Fatalf("the signer is %s, want the key of the earlier release %s", got.public.KeyID, legacy.public.KeyID)
	}
	if _, gerr := kv.Get(ctx, keyStoreKey); gerr == nil {
		t.Error("the old record stays beside the ring")
	}
	again, err := loadRing(ctx, kv, secret)
	if err != nil || again.signer(now).public.KeyID != legacy.public.KeyID {
		t.Fatalf("the second start = %v, %v", again, err)
	}
}
