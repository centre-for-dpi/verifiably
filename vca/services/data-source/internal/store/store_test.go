// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/source"
)

func csvSource(name string) source.Source {
	return source.Source{DisplayName: name, Kind: source.KindCSV, CSV: &source.CSV{FileRef: name + ".csv", HasHeader: true}}
}

type failBackend struct{ Backend }

func (failBackend) Save([]byte) error { return errors.New("disk full") }

func TestStoreLifecycle(t *testing.T) {
	st, err := Open(Memory())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := st.Create(source.Source{}, now); !errors.Is(err, source.ErrInvalid) {
		t.Fatalf("invalid create: %v", err)
	}
	b, err := st.Create(csvSource("b"), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.Create(csvSource("a"), now)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "src-2" || b.ID != "src-1" || !a.CreatedAt.Equal(now) {
		t.Fatalf("ids: %+v %+v", a, b)
	}
	if got := st.List(); len(got) != 2 || got[0].ID != a.ID {
		t.Fatalf("list order: %+v", got)
	}
	if _, ok := st.Get("nope"); ok {
		t.Fatal("get missing")
	}
	a.DisplayName = "a2"
	a2, err := st.Update(a, now.Add(2*time.Hour))
	if err != nil || a2.DisplayName != "a2" || !a2.CreatedAt.Equal(now) || a2.UpdatedAt.Equal(now) {
		t.Fatalf("update: %+v %v", a2, err)
	}
	if _, err := st.Update(csvSource("x"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if _, err := st.Update(source.Source{ID: a.ID}, now); !errors.Is(err, source.ErrInvalid) {
		t.Fatalf("update invalid: %v", err)
	}
	fm := mapping.FieldMap{SourceID: a.ID, SchemaID: "s", Rules: []mapping.Rule{{Property: "p", SourceFields: []string{"f"}}}}
	if err := st.SetFieldMap(fm); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFieldMap(mapping.FieldMap{SourceID: "nope", Rules: fm.Rules}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("map for missing source: %v", err)
	}
	if err := st.SetFieldMap(mapping.FieldMap{SourceID: a.ID, Rules: []mapping.Rule{{}}}); !errors.Is(err, mapping.ErrEmptyProperty) {
		t.Fatalf("invalid map: %v", err)
	}
	if got, ok := st.GetFieldMap(a.ID, "s"); !ok || len(got.Rules) != 1 {
		t.Fatal("get map")
	}
	if err := st.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.GetFieldMap(a.ID, "s"); ok {
		t.Fatal("map must go with the source")
	}
	if err := st.Delete(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestFileBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	st, err := Open(File(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(csvSource("a"), time.Now()); err != nil {
		t.Fatal(err)
	}
	again, err := Open(File(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := again.List(); len(got) != 1 || got[0].DisplayName != "a" {
		t.Fatalf("reload: %+v", got)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(File(path)); err == nil {
		t.Fatal("bad json must fail")
	}
	dir := t.TempDir()
	if _, err := Open(File(dir)); err == nil {
		t.Fatal("directory must fail to load")
	}
	if err := File(filepath.Join(dir, "missing", "x.json")).Save([]byte("{}")); err == nil {
		t.Fatal("missing dir must fail to save")
	}
	if err := os.WriteFile(filepath.Join(dir, "dst"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dst2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := File(filepath.Join(dir, "dst2")).Save([]byte("{}")); err == nil {
		t.Fatal("rename over a non empty directory must fail")
	}
}

func TestSaveFailure(t *testing.T) {
	st, err := Open(failBackend{Memory()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(csvSource("a"), time.Now()); err == nil {
		t.Fatal("create must report the save error")
	}
	if len(st.List()) != 0 {
		t.Fatal("state must not change after a failed save")
	}
}
