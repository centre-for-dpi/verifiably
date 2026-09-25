// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

const doc = `{"type": "object", "properties": {"name": {"type": "string"}}}`

var now = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

func sample(typ string) record.Record {
	return record.Record{Type: typ, JSONSchema: doc, Formats: []string{record.FormatDcSdJwt}}
}

func fixedID(id string) func(string) string {
	return func(string) string { return id }
}

func open(t *testing.T, b sharedstore.Document, opts Options) *Store {
	t.Helper()
	s, err := Open(b, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRandomID(t *testing.T) {
	id := RandomID("University Degree!!")
	if !strings.HasPrefix(id, "university-degree-") || !record.ValidID(id) {
		t.Fatalf("id %q", id)
	}
	if !strings.HasPrefix(RandomID("???"), "schema-") {
		t.Fatal("empty slug")
	}
	long := RandomID(strings.Repeat("a", 60) + "-b")
	if len(long) > 50 || !record.ValidID(long) {
		t.Fatalf("long id %q", long)
	}
}

func TestCreateVersionsAndTransitions(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc(), Options{NewID: fixedID("degree")})
	r, err := s.Create(sample("Degree"), now)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "degree" || r.Version != 1 || r.State != record.StateDraft || !r.CreatedAt.Equal(now) {
		t.Fatalf("created %+v", r)
	}
	if s.Revision() != 1 {
		t.Fatal("revision")
	}
	if dup, serr := s.Create(sample("Degree"), now); serr != nil || dup.ID == "degree" {
		t.Fatalf("duplicate id must get a random id: %+v %v", dup, serr)
	}
	if _, serr := s.Create(record.Record{}, now); serr == nil {
		t.Fatal("invalid record must fail")
	}
	v2, err := s.AddVersion("degree", sample("Degree"), now.Add(time.Hour))
	if err != nil || v2.Version != 2 || v2.State != record.StateDraft {
		t.Fatalf("v2 %+v %v", v2, err)
	}
	if _, serr := s.AddVersion("degree", record.Record{}, now); serr == nil {
		t.Fatal("invalid version must fail")
	}
	if _, serr := s.AddVersion("nope", sample("X"), now); !errors.Is(serr, ErrNotFound) {
		t.Fatalf("missing id: %v", serr)
	}
	got, ok := s.Get("degree", 0)
	if !ok || got.Version != 2 {
		t.Fatal("latest")
	}
	if got, ok := s.Get("degree", 1); !ok || got.Version != 1 {
		t.Fatal("version 1")
	}
	if _, ok := s.Get("degree", 9); ok {
		t.Fatal("version 9")
	}
	if _, ok := s.Get("nope", 0); ok {
		t.Fatal("missing")
	}
	if len(s.Versions("degree")) != 2 || len(s.Latest()) != 2 || len(s.All()) != 3 {
		t.Fatal("lists")
	}
	if len(s.Published()) != 0 || len(s.LatestPublished()) != 0 {
		t.Fatal("nothing published")
	}
	pub, err := s.Transition("degree", 1, func(r record.Record) (record.Record, error) {
		return r.Publish(now, map[string]string{"dc+sd-jwt": "Degree_dc+sd-jwt"})
	})
	if err != nil || pub.State != record.StatePublished || pub.Version != 1 {
		t.Fatalf("publish %+v %v", pub, err)
	}
	if len(s.Published()) != 1 || len(s.LatestPublished()) != 1 || s.LatestPublished()[0].Version != 1 {
		t.Fatal("published lists")
	}
	if _, err := s.Transition("degree", 1, func(r record.Record) (record.Record, error) { return r.Publish(now, nil) }); err == nil {
		t.Fatal("second publish must fail")
	}
	if _, err := s.Transition("degree", 7, func(r record.Record) (record.Record, error) { return r, nil }); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing version")
	}
	if _, err := s.Transition("degree", 1, func(r record.Record) (record.Record, error) { r.Version = 3; return r, nil }); err == nil {
		t.Fatal("version change must fail")
	}
}

func TestCreateRetriesBadIDs(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc(), Options{NewID: fixedID("Not Valid")})
	r, err := s.Create(sample("Degree"), now)
	if err != nil || !record.ValidID(r.ID) {
		t.Fatalf("retry %+v %v", r, err)
	}
	s = open(t, sharedstore.MemoryDoc(), Options{NewID: fixedID("fixed")})
	if _, err := s.Create(sample("A"), now); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Create(sample("B"), now); err != nil || r.ID == "fixed" {
		t.Fatalf("collision retry %+v %v", r, err)
	}
}

func TestFileBackendRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schemas.json")
	s := open(t, sharedstore.FileDoc(path), Options{NewID: fixedID("degree")})
	if _, err := s.Create(sample("Degree"), now); err != nil {
		t.Fatal(err)
	}
	again := open(t, sharedstore.FileDoc(path), Options{})
	if got, ok := again.Get("degree", 1); !ok || got.Type != "Degree" || again.Revision() != 1 {
		t.Fatal("reload")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sharedstore.FileDoc(path), Options{}); err == nil {
		t.Fatal("bad document must fail")
	}
	if err := os.WriteFile(path, []byte(`{"revision": 3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := open(t, sharedstore.FileDoc(path), Options{}); s.Revision() != 3 || len(s.All()) != 0 {
		t.Fatal("nil schemas map")
	}
}

type failing struct{ err error }

func (f failing) Load() ([]byte, bool, error) { return nil, false, f.err }
func (f failing) Save([]byte) error           { return f.err }

func TestBackendErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := Open(failing{boom}, Options{}); !errors.Is(err, boom) {
		t.Fatal("load error")
	}
	s := &Store{backend: failing{boom}, doc: document{Schemas: map[string][]record.Record{}}, newID: fixedID("x")}
	if _, err := s.Create(sample("X"), now); !errors.Is(err, boom) {
		t.Fatal("save error")
	}
	if s.Revision() != 0 {
		t.Fatal("failed save must not raise the revision")
	}
}

// TestRemove checks that Remove drops one version when the check takes
// it, drops the id with its last version, and keeps the state when the
// check or the save fails.
func TestRemove(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc(), Options{NewID: fixedID("degree")})
	if _, err := s.Create(sample("Degree"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddVersion("degree", sample("Degree"), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Remove("degree", 9, record.Record.CanDelete); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	refuse := errors.New("no")
	if _, _, err := s.Remove("degree", 1, func(record.Record) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("refused: %v", err)
	}
	removed, gone, err := s.Remove("degree", 1, record.Record.CanDelete)
	if err != nil || removed.Version != 1 || gone || len(s.Versions("degree")) != 1 {
		t.Fatalf("first: %+v %v %v", removed, gone, err)
	}
	s.backend = failing{errors.New("boom")}
	if _, _, err := s.Remove("degree", 2, record.Record.CanDelete); err == nil || len(s.Versions("degree")) != 1 {
		t.Fatalf("save error: %v", err)
	}
	s.backend = sharedstore.MemoryDoc()
	if _, gone, err := s.Remove("degree", 2, record.Record.CanDelete); err != nil || !gone {
		t.Fatalf("last: %v %v", gone, err)
	}
	if _, ok := s.Get("degree", 0); ok || len(s.Latest()) != 0 {
		t.Fatal("the id stays after its last version")
	}
}
