// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func issuer(did string) entry.Entry {
	return entry.Entry{DID: did, Role: entry.RoleIssuer, Status: entry.StatusActive}
}

func TestMemoryLifecycle(t *testing.T) {
	s, err := Open(Memory())
	if err != nil {
		t.Fatal(err)
	}
	if s.Revision() != 0 || len(s.List()) != 0 {
		t.Fatal("empty store")
	}
	e, created, err := s.Upsert(issuer("did:web:b"), t0)
	if err != nil || !created || e.Version != 1 || e.UpdatedAt != t0 || e.Source != entry.SourceAdmin {
		t.Fatalf("first upsert %+v %v %v", e, created, err)
	}
	e2 := issuer("did:web:b")
	e2.DisplayName = "B"
	e2.Source = entry.SourceEtsiImport
	e, created, err = s.Upsert(e2, t0.Add(time.Hour))
	if err != nil || created || e.Version != 2 || e.Source != entry.SourceEtsiImport {
		t.Fatalf("second upsert %+v %v %v", e, created, err)
	}
	if _, _, err = s.Upsert(issuer("did:web:a"), t0); err != nil {
		t.Fatal(err)
	}
	if s.Revision() != 3 {
		t.Fatalf("revision %d", s.Revision())
	}
	list := s.List()
	if len(list) != 2 || list[0].DID != "did:web:a" || list[1].DisplayName != "B" {
		t.Fatalf("list %+v", list)
	}
	got, ok := s.Get("did:web:b")
	if !ok || got.Version != 2 {
		t.Fatal("get")
	}
	found, err := s.Delete("did:web:b")
	if err != nil || !found {
		t.Fatal("delete")
	}
	found, err = s.Delete("did:web:b")
	if err != nil || found {
		t.Fatal("delete again")
	}
	if _, ok := s.Get("did:web:b"); ok || s.Revision() != 4 {
		t.Fatal("after delete")
	}
	if _, _, err := s.Upsert(entry.Entry{}, t0); err == nil {
		t.Fatal("invalid entry")
	}
}

func TestFilePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	s, err := Open(File(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Upsert(issuer("did:web:a"), t0); err != nil {
		t.Fatal(err)
	}
	again, err := Open(File(path))
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision() != 1 {
		t.Fatalf("revision %d", again.Revision())
	}
	if got, ok := again.Get("did:web:a"); !ok || got.Version != 1 {
		t.Fatal("reloaded entry")
	}
}

func TestFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(File(filepath.Join(dir, "bad.json"))); err == nil {
		t.Fatal("bad json")
	}
	if err := os.WriteFile(filepath.Join(dir, "null.json"), []byte(`{"revision":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(File(filepath.Join(dir, "null.json")))
	if err != nil || s.Revision() != 2 || len(s.List()) != 0 {
		t.Fatal("nil entries map")
	}
	if _, err := Open(File(dir)); err == nil {
		t.Fatal("read a directory")
	}
	if err := File(filepath.Join(dir, "missing", "x.json")).Save([]byte("{}")); err == nil {
		t.Fatal("write into a missing directory")
	}
	if err := os.Mkdir(filepath.Join(dir, "target.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := File(filepath.Join(dir, "target.json")).Save([]byte("{}")); err == nil {
		t.Fatal("rename over a directory")
	}
}

type failing struct{ err error }

func (f failing) Load() ([]byte, bool, error) { return nil, false, f.err }
func (f failing) Save([]byte) error           { return f.err }

func TestBackendErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := Open(failing{err: boom}); !errors.Is(err, boom) {
		t.Fatal("load error")
	}
	s := &Store{backend: failing{err: boom}, doc: document{Entries: map[string]entry.Entry{"did:web:a": issuer("did:web:a")}}}
	if _, _, err := s.Upsert(issuer("did:web:b"), t0); !errors.Is(err, boom) {
		t.Fatal("upsert save error")
	}
	if _, err := s.Delete("did:web:a"); !errors.Is(err, boom) {
		t.Fatal("delete save error")
	}
	if s.Revision() != 0 || len(s.List()) != 1 {
		t.Fatal("state must not change on a failed save")
	}
}
