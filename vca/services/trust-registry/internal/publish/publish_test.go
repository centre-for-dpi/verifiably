// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"testing"
)

func TestFileETag(t *testing.T) {
	a := File{Body: []byte("a")}
	b := File{Body: []byte("b")}
	if a.ETag() == b.ETag() || a.ETag() != (File{Body: []byte("a")}).ETag() || len(a.ETag()) != 34 {
		t.Fatal("etag")
	}
}

func TestSnapshot(t *testing.T) {
	var nilSnap *Snapshot
	if _, ok := nilSnap.File("/x"); ok {
		t.Fatal("nil snapshot file")
	}
	if _, ok := nilSnap.Publication("etsi"); ok || nilSnap.Methods() != nil || nilSnap.Paths() != nil {
		t.Fatal("nil snapshot")
	}
	etsi := Publication{Method: MethodEtsi, Files: map[string]File{"/trust-list/etsi.json": {Body: []byte("{}")}}}
	dedi := Publication{Method: MethodDedi, Files: map[string]File{"/.well-known/dedi.index.json": {Body: []byte("{}")}}}
	s, err := NewSnapshot(dedi, etsi)
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := s.File("/trust-list/etsi.json"); !ok || string(f.Body) != "{}" {
		t.Fatal("file")
	}
	if _, ok := s.File("/missing"); ok {
		t.Fatal("missing file")
	}
	if p, ok := s.Publication(MethodDedi); !ok || p.Method != MethodDedi {
		t.Fatal("publication")
	}
	if m := s.Methods(); len(m) != 2 || m[0] != MethodDedi || m[1] != MethodEtsi {
		t.Fatalf("methods %v", m)
	}
	if p := s.Paths(); len(p) != 2 || p[0] != "/.well-known/dedi.index.json" {
		t.Fatalf("paths %v", p)
	}
	if _, err := NewSnapshot(etsi, etsi); err == nil {
		t.Fatal("duplicate path")
	}
}

func TestJoinURL(t *testing.T) {
	if JoinURL("https://a/", "/b") != "https://a/b" || JoinURL("https://a", "b") != "https://a/b" {
		t.Fatal("join")
	}
}
