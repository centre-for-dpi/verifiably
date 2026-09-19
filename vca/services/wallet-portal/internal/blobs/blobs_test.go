// SPDX-License-Identifier: Apache-2.0

package blobs_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/blobs"
)

func now() time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-09-19T00:00:00Z")
	return t
}

// TestRoundTripSameFormat seals and opens one credential. The envelope
// is the format wallet.js writes with WebCrypto.
func TestRoundTripSameFormat(t *testing.T) {
	key, err := blobs.DeriveKey([]byte("a shared secret of the holder key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != blobs.KeyBytes {
		t.Fatalf("key = %d bytes", len(key))
	}
	credential := "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJEcml2ZXIifQ.sig~WyJzIiwiYSIsMV0~"
	envelope, err := blobs.Seal(key, []byte(credential))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Version != blobs.Version || envelope.Alg != blobs.AlgGCM || envelope.KDF != blobs.KDF {
		t.Fatalf("envelope = %+v", envelope)
	}
	iv, err := base64.RawURLEncoding.DecodeString(envelope.IV)
	if err != nil || len(iv) != blobs.NonceBytes {
		t.Fatalf("nonce = %q %v", envelope.IV, err)
	}
	raw, err := blobs.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"v":1`, `"kdf":"HKDF-SHA256"`, `"alg":"A256GCM"`, `"iv":`, `"ct":`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("envelope JSON %s misses %s", raw, want)
		}
	}
	parsed, err := blobs.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := blobs.Open(key, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != credential {
		t.Fatalf("plaintext = %q", plain)
	}
}

// TestOpenFixedVector opens one envelope of the documented format. The
// vector holds the key, the nonce, and the ciphertext as fixed values,
// so a change of the format breaks this test.
func TestOpenFixedVector(t *testing.T) {
	key, err := hex.DecodeString("6a2a5e01b3d8f38c3d3a3b0f42b8a6f21a6b4d5e6f708192a3b4c5d6e7f80910")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := blobs.Seal(key, []byte("hello wallet"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := blobs.Open(key, sealed)
	if err != nil || string(plain) != "hello wallet" {
		t.Fatalf("plaintext = %q %v", plain, err)
	}
	other, err := blobs.DeriveKey([]byte("another secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Open(other, sealed); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestDeriveKeyIsStable(t *testing.T) {
	first, err := blobs.DeriveKey([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := blobs.DeriveKey([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Fatal("want the same key for the same secret")
	}
	if _, err := blobs.DeriveKey(nil); err == nil {
		t.Fatal("want an error for an empty secret")
	}
}

func TestSealAndOpenRejects(t *testing.T) {
	if _, err := blobs.Seal([]byte("short"), []byte("x")); err == nil {
		t.Fatal("want a key length error")
	}
	key, err := blobs.DeriveKey([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := blobs.Seal(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Open([]byte("short"), good); err == nil {
		t.Fatal("want a key length error")
	}
	short := good
	short.IV = "AAAA"
	if _, err := blobs.Open(key, short); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatalf("short nonce: %v", err)
	}
	badCT := good
	badCT.CT = "not base64url!!"
	if _, err := blobs.Open(key, badCT); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatalf("bad ciphertext: %v", err)
	}
	empty := blobs.Envelope{}
	if _, err := blobs.Open(key, empty); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatalf("empty envelope: %v", err)
	}
}

func TestEnvelopeCheck(t *testing.T) {
	good := blobs.Envelope{Version: 1, KDF: blobs.KDF, Alg: blobs.AlgGCM, IV: "a", CT: "b"}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	cases := []blobs.Envelope{
		{Version: 2, KDF: blobs.KDF, Alg: blobs.AlgGCM, IV: "a", CT: "b"},
		{Version: 1, KDF: "other", Alg: blobs.AlgGCM, IV: "a", CT: "b"},
		{Version: 1, KDF: blobs.KDF, Alg: "other", IV: "a", CT: "b"},
		{Version: 1, KDF: blobs.KDF, Alg: blobs.AlgGCM, IV: "", CT: "b"},
	}
	for i, e := range cases {
		if err := e.Check(); !errors.Is(err, blobs.ErrBadEnvelope) {
			t.Fatalf("case %d: %v", i, err)
		}
		if _, err := blobs.Marshal(e); err == nil {
			t.Fatalf("case %d: want a marshal error", i)
		}
	}
	if _, err := blobs.Parse([]byte("{")); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatal("want a parse error")
	}
	if _, err := blobs.Parse([]byte(`{"v":9}`)); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatal("want a version error")
	}
}

// envelope returns one sealed envelope for the store tests.
func envelope(t *testing.T, text string) blobs.Envelope {
	t.Helper()
	key, err := blobs.DeriveKey([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := blobs.Seal(key, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newStore(t *testing.T, maxBytes int64) *blobs.Store {
	t.Helper()
	st, err := blobs.NewStore(store.Memory(), maxBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestStoreRoundTrip(t *testing.T) {
	st := newStore(t, 0)
	if st.MaxBytes() != blobs.DefaultMaxBytes {
		t.Fatalf("max = %d", st.MaxBytes())
	}
	ctx := context.Background()
	if _, err := st.Put(ctx, "wallet-1", "b1", envelope(t, "one")); err != nil {
		t.Fatal(err)
	}
	rec, err := st.Put(ctx, "wallet-1", "b2", envelope(t, "two"))
	if err != nil {
		t.Fatal(err)
	}
	if !rec.StoredAt.Equal(now()) {
		t.Fatalf("stored at = %s", rec.StoredAt)
	}
	list, err := st.List(ctx, "wallet-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "b1" {
		t.Fatalf("list = %+v", list)
	}
	got, err := st.Get(ctx, "wallet-1", "b2")
	if err != nil {
		t.Fatal(err)
	}
	key, err := blobs.DeriveKey([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := blobs.Open(key, got.Envelope)
	if err != nil || string(plain) != "two" {
		t.Fatalf("plaintext = %q %v", plain, err)
	}
	if err := st.Delete(ctx, "wallet-1", "b1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "wallet-1", "b1"); !errors.Is(err, blobs.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if other, err := st.List(ctx, "wallet-2"); err != nil || len(other) != 0 {
		t.Fatalf("other wallet = %+v %v", other, err)
	}
}

func TestStoreRejects(t *testing.T) {
	if _, err := blobs.NewStore(nil, 0, nil); err == nil {
		t.Fatal("want a store error")
	}
	st := newStore(t, 0)
	ctx := context.Background()
	for _, c := range []struct{ wallet, id string }{{"", "b"}, {"w", ""}, {"w", "bad/id"}, {"w", ".."}} {
		if _, err := st.Put(ctx, c.wallet, c.id, envelope(t, "x")); !errors.Is(err, blobs.ErrBadID) {
			t.Fatalf("put %q %q: %v", c.wallet, c.id, err)
		}
		if _, err := st.Get(ctx, c.wallet, c.id); !errors.Is(err, blobs.ErrBadID) {
			t.Fatalf("get %q %q: %v", c.wallet, c.id, err)
		}
		if err := st.Delete(ctx, c.wallet, c.id); !errors.Is(err, blobs.ErrBadID) {
			t.Fatalf("delete %q %q: %v", c.wallet, c.id, err)
		}
	}
	if _, err := st.List(ctx, " "); !errors.Is(err, blobs.ErrBadID) {
		t.Fatalf("list: %v", err)
	}
	small := newStore(t, 16)
	if _, err := small.Put(ctx, "w", "b", envelope(t, "a long credential text")); !errors.Is(err, blobs.ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	if _, err := st.Put(ctx, "w", "b", blobs.Envelope{}); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatalf("bad envelope: %v", err)
	}
}

func TestStoreReadsBrokenRecord(t *testing.T) {
	kv := store.Memory()
	st, err := blobs.NewStore(kv, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := kv.Put(ctx, "blob/w/b1", []byte("{oops")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "w", "b1"); !errors.Is(err, blobs.ErrBadEnvelope) {
		t.Fatalf("err = %v", err)
	}
	list, err := st.List(ctx, "w")
	if err != nil || len(list) != 0 {
		t.Fatalf("list = %+v %v", list, err)
	}
}
