package injiwallet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// The store must keep each OIDC user's wallet separate, newest-first, deduped by
// VCID, and durably recoverable from an encrypted-at-rest file.
func TestStore_IsolationOrderingDedupeDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inji-wallets.json")
	key := fixedKey()
	s, err := NewStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()

	mustAdd := func(user string, c HeldCred) {
		t.Helper()
		if err := s.Add(user, c); err != nil {
			t.Fatal(err)
		}
	}
	mustAdd("prov|A", HeldCred{VCID: "a1", VC: "vcA1", HolderKey: "keyA1", ClaimedAt: now})
	mustAdd("prov|A", HeldCred{VCID: "a2", VC: "vcA2", ClaimedAt: now})
	mustAdd("prov|B", HeldCred{VCID: "b1", VC: "vcB1", ClaimedAt: now})

	if a := s.List("prov|A"); len(a) != 2 || a[0].VCID != "a2" || a[1].VCID != "a1" {
		t.Fatalf("A not newest-first: %+v", a)
	}
	if b := s.List("prov|B"); len(b) != 1 || b[0].VCID != "b1" {
		t.Fatalf("B isolation broken: %+v", b)
	}
	if z := s.List("prov|Z"); len(z) != 0 {
		t.Fatalf("unknown user not empty: %+v", z)
	}

	// Re-adding an existing VCID replaces it and moves it to the front.
	mustAdd("prov|A", HeldCred{VCID: "a1", VC: "vcA1v2", ClaimedAt: now})
	if a := s.List("prov|A"); len(a) != 2 || a[0].VCID != "a1" || a[0].VC != "vcA1v2" {
		t.Fatalf("dedupe/move-to-front broken: %+v", a)
	}

	if err := s.Delete("prov|A", "a2"); err != nil {
		t.Fatal(err)
	}
	if a := s.List("prov|A"); len(a) != 1 || a[0].VCID != "a1" {
		t.Fatalf("after delete: %+v", a)
	}

	// Durability: a fresh store on the same file recovers each user's set.
	s2, err := NewStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if a := s2.List("prov|A"); len(a) != 1 || a[0].VC != "vcA1v2" || a[0].HolderKey != "" {
		t.Fatalf("reload A: %+v", a)
	}
	if b := s2.List("prov|B"); len(b) != 1 || b[0].VC != "vcB1" {
		t.Fatalf("reload B: %+v", b)
	}

	// Encrypted at rest: raw bytes must not contain the plaintext VC or user key.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "vcA1v2") || strings.Contains(string(raw), "prov|A") {
		t.Errorf("wallet file is not encrypted — found plaintext")
	}
}

func TestStore_Guards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.json")
	s, err := NewStore(path, nil) // nil key => plaintext branch
	if err != nil {
		t.Fatal(err)
	}
	// no-ops: empty user / empty vcId / delete of absent id.
	if err := s.Add("", HeldCred{VCID: "x", VC: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("u", HeldCred{VCID: "", VC: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("u", "nope"); err != nil {
		t.Fatal(err)
	}
	if len(s.List("u")) != 0 || len(s.List("")) != 0 {
		t.Fatalf("guards should have stored nothing")
	}
	// plaintext round-trip still works.
	if err := s.Add("u", HeldCred{VCID: "1", VC: "hello"}); err != nil {
		t.Fatal(err)
	}
	s2, _ := NewStore(path, nil)
	if a := s2.List("u"); len(a) != 1 || a[0].VC != "hello" {
		t.Fatalf("plaintext reload: %+v", a)
	}
}
