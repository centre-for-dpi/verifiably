// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func documents(t *testing.T) map[string]Document {
	t.Helper()
	kv, err := File(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Document{
		"memory": MemoryDoc(),
		"kvfile": Doc(kv, "state"),
		"file":   FileDoc(filepath.Join(t.TempDir(), "doc.json")),
	}
}

func TestDocumentRoundTrip(t *testing.T) {
	for name, d := range documents(t) {
		t.Run(name, func(t *testing.T) {
			if _, found, err := d.Load(); err != nil || found {
				t.Fatalf("first load: %v %v", found, err)
			}
			if err := d.Save([]byte(`{"a":1}`)); err != nil {
				t.Fatal(err)
			}
			data, found, err := d.Load()
			if err != nil || !found || string(data) != `{"a":1}` {
				t.Fatalf("load: %q %v %v", data, found, err)
			}
			if err := d.Save([]byte(`{"a":2}`)); err != nil {
				t.Fatal(err)
			}
			if data, _, _ := d.Load(); string(data) != `{"a":2}` {
				t.Fatalf("replace: %q", data)
			}
		})
	}
}

func TestDocumentErrors(t *testing.T) {
	bad := Doc(Memory(), "a b")
	if _, _, err := bad.Load(); !errors.Is(err, ErrBadKey) {
		t.Fatalf("load: %v", err)
	}
	if err := bad.Save(nil); !errors.Is(err, ErrBadKey) {
		t.Fatalf("save: %v", err)
	}
	dir := t.TempDir()
	if _, _, err := FileDoc(dir).Load(); err == nil {
		t.Fatal("want a read error on a directory")
	}
	if err := FileDoc(filepath.Join(dir, "sub", "doc.json")).Save([]byte("{}")); err == nil {
		t.Fatal("want a write error in a missing directory")
	}
	target := filepath.Join(dir, "taken")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := FileDoc(target).Save([]byte("{}")); err == nil {
		t.Fatal("want a rename error over a directory")
	}
}

func TestJSONStore(t *testing.T) {
	j := NewJSON(Memory())
	type doc struct {
		Name string `json:"name"`
	}
	got := doc{Name: "keep"}
	if err := j.Load("missing", &got); err != nil || got.Name != "keep" {
		t.Fatalf("missing: %+v %v", got, err)
	}
	if err := j.Save("one", doc{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Load("one", &got); err != nil || got.Name != "first" {
		t.Fatalf("load: %+v %v", got, err)
	}
}

func TestJSONStoreErrors(t *testing.T) {
	kv := Memory()
	j := NewJSON(kv)
	if err := j.Save("a b", 1); !errors.Is(err, ErrBadKey) {
		t.Fatalf("bad key save: %v", err)
	}
	if err := j.Load("a b", &struct{}{}); !errors.Is(err, ErrBadKey) {
		t.Fatalf("bad key load: %v", err)
	}
	if err := j.Save("cycle", make(chan int)); err == nil {
		t.Fatal("want an encode error")
	}
	if err := kv.Put(context.Background(), "broken", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := j.Load("broken", &struct{}{}); err == nil {
		t.Fatal("want a decode error")
	}
}
