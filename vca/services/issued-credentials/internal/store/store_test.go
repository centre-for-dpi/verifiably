// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/hashchain"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
)

// at is a fixed time so the tests do not depend on the clock.
func at(day int) time.Time {
	return time.Date(2026, 3, day, 9, 0, 0, 0, time.UTC)
}

// rec returns a valid record with id.
func rec(id string, day int) record.Record {
	return record.Record{
		ID:               id,
		SchemaID:         "diploma",
		SchemaVersion:    1,
		SubjectRef:       "ref-" + id,
		Format:           "dc+sd-jwt",
		IssuedAt:         at(day),
		SearchableClaims: map[string]string{"name": "Wanjiru"},
	}
}

// failing is a backend whose Save always fails.
type failing struct{ loaded []byte }

func (f *failing) Load() ([]byte, bool, error) {
	if f.loaded == nil {
		return nil, false, nil
	}
	return f.loaded, true, nil
}
func (f *failing) Save([]byte) error { return errors.New("disk full") }

// badLoad is a backend whose Load always fails.
type badLoad struct{}

func (badLoad) Load() ([]byte, bool, error) { return nil, false, errors.New("no disk") }
func (badLoad) Save([]byte) error           { return nil }

func open(t *testing.T, b sharedstore.Document) *store.Store {
	t.Helper()
	s, err := store.Open(b)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func TestAppendGetAndHead(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc())
	if _, ok := s.Head(); ok {
		t.Fatal("an empty chain has no head")
	}
	got, err := s.Append(rec("a", 1))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if got.Status != record.Active {
		t.Errorf("status = %q, want active", got.Status)
	}
	if got.RecordHash == "" || got.PreviousHash != "" {
		t.Errorf("first entry hashes = %q %q", got.RecordHash, got.PreviousHash)
	}
	second, err := s.Append(rec("b", 2))
	if err != nil {
		t.Fatalf("append second: %v", err)
	}
	if second.PreviousHash != got.RecordHash {
		t.Errorf("previous hash = %q, want %q", second.PreviousHash, got.RecordHash)
	}
	head, ok := s.Head()
	if !ok || head.RecordID != "b" || head.Length != 2 || head.Hash != second.RecordHash {
		t.Errorf("head = %+v", head)
	}
	if r, ok := s.Get("a"); !ok || r.ID != "a" {
		t.Errorf("get a = %+v %v", r, ok)
	}
	if _, ok := s.Get("zz"); ok {
		t.Error("get of an unknown id must report false")
	}
}

func TestAppendRejectsInvalidAndDuplicate(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc())
	if _, err := s.Append(record.Record{}); !errors.Is(err, record.ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
	if _, err := s.Append(rec("a", 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(rec("a", 1)); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
}

func TestAppendRollsBackOnSaveFailure(t *testing.T) {
	s := open(t, &failing{})
	if _, err := s.Append(rec("a", 1)); err == nil {
		t.Fatal("want a save error")
	}
	if _, ok := s.Get("a"); ok {
		t.Error("a failed save must not change the read index")
	}
	if len(s.All()) != 0 {
		t.Error("a failed save must not add a record")
	}
}

func TestOpenReportsALoadError(t *testing.T) {
	if _, err := store.Open(badLoad{}); err == nil {
		t.Fatal("want a load error")
	}
}

func TestSetStatus(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc())
	if _, err := s.Append(rec("a", 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := s.SetStatus("a", record.Suspended, "under review", at(3))
	if err != nil {
		t.Fatalf("set status: %v", err)
	}
	if got.Status != record.Suspended || got.StatusReason != "under review" || !got.StatusChangedAt.Equal(at(3)) {
		t.Errorf("record = %+v", got)
	}
	if _, err := s.SetStatus("a", record.Revoked, "fraud", at(4)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.SetStatus("a", record.Active, "mistake", at(5)); !errors.Is(err, record.ErrFinal) {
		t.Errorf("err = %v, want ErrFinal", err)
	}
	if _, err := s.SetStatus("gone", record.Revoked, "x", at(5)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSetStatusReportsASaveFailure(t *testing.T) {
	m := sharedstore.MemoryDoc()
	s := open(t, m)
	if _, err := s.Append(rec("a", 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	data, _, err := m.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s2 := open(t, &failing{loaded: data})
	if _, err := s2.SetStatus("a", record.Suspended, "x", at(2)); err == nil {
		t.Fatal("want a save error")
	}
}

func TestAllSortsNewestFirst(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc())
	for _, r := range []record.Record{rec("a", 1), rec("b", 5), rec("c", 3)} {
		if _, err := s.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	got := s.All()
	want := []string{"b", "c", "a"}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("record %d = %q, want %q", i, got[i].ID, w)
		}
	}
}

func TestFileBackendRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.json")
	s := open(t, sharedstore.FileDoc(path))
	if _, err := s.Append(rec("a", 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.SetStatus("a", record.Suspended, "review", at(2)); err != nil {
		t.Fatalf("set status: %v", err)
	}
	again := open(t, sharedstore.FileDoc(path))
	got, ok := again.Get("a")
	if !ok || got.Status != record.Suspended || got.StatusReason != "review" {
		t.Errorf("reloaded record = %+v %v", got, ok)
	}
	head, ok := again.Head()
	if !ok || head.Length != 2 {
		t.Errorf("head = %+v", head)
	}
}

func TestOpenRejectsABrokenChain(t *testing.T) {
	m := sharedstore.MemoryDoc()
	s := open(t, m)
	if _, err := s.Append(rec("a", 1)); err != nil {
		t.Fatalf("append: %v", err)
	}
	data, _, err := m.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var doc struct {
		Entries []hashchain.Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	doc.Entries[0].Hash = "0000"
	broken, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := m.Save(broken); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := store.Open(m); err == nil {
		t.Fatal("want a broken chain error")
	}
}

func TestOpenRejectsBadJSON(t *testing.T) {
	m := sharedstore.MemoryDoc()
	if err := m.Save([]byte("not json")); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := store.Open(m); err == nil {
		t.Fatal("want a decode error")
	}
}

func TestOpenRejectsAnEntryThatIsNotAnEvent(t *testing.T) {
	chain, _, err := hashchain.New().Append([]string{"not", "an", "event"})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	m := sharedstore.MemoryDoc()
	data, err := json.Marshal(map[string]any{"entries": chain.Entries()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := m.Save(data); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := store.Open(m); err == nil {
		t.Fatal("want a decode error for the entry body")
	}
}

func TestFoldIgnoresEmptyEvents(t *testing.T) {
	chain := hashchain.New()
	for _, ev := range []record.Event{{Kind: record.EventIssue}, {Kind: record.EventStatus}, {Kind: "other"}} {
		next, _, err := chain.Append(ev)
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		chain = next
	}
	m := sharedstore.MemoryDoc()
	data, err := json.Marshal(map[string]any{"entries": chain.Entries()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := m.Save(data); err != nil {
		t.Fatalf("save: %v", err)
	}
	s := open(t, m)
	if len(s.All()) != 0 {
		t.Errorf("records = %d, want 0", len(s.All()))
	}
	head, ok := s.Head()
	if !ok || head.RecordID != "" {
		t.Errorf("head = %+v %v", head, ok)
	}
}

func TestStatusEventForAnUnknownRecordIsIgnored(t *testing.T) {
	change := record.Change{RecordID: "ghost", Status: record.Revoked, Reason: "x", ChangedAt: at(1)}
	chain, _, err := hashchain.New().Append(record.Event{Kind: record.EventStatus, Change: &change})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	m := sharedstore.MemoryDoc()
	data, err := json.Marshal(map[string]any{"entries": chain.Entries()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := m.Save(data); err != nil {
		t.Fatalf("save: %v", err)
	}
	s := open(t, m)
	if len(s.All()) != 0 {
		t.Errorf("records = %d, want 0", len(s.All()))
	}
}

func TestVerify(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc())
	for _, r := range []record.Record{rec("a", 1), rec("b", 2), rec("c", 3)} {
		if _, err := s.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	checked, broken, err := s.Verify("")
	if err != nil || broken != "" || checked != 3 {
		t.Errorf("verify = %d %q %v", checked, broken, err)
	}
	checked, broken, err = s.Verify("b")
	if err != nil || broken != "" || checked != 2 {
		t.Errorf("verify from b = %d %q %v", checked, broken, err)
	}
	if _, _, err := s.Verify("ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPrune(t *testing.T) {
	s := open(t, sharedstore.MemoryDoc())
	keep := rec("keep", 1)
	drop := rec("drop", 2)
	drop.RetainUntil = at(3)
	forever := rec("forever", 3)
	for _, r := range []record.Record{keep, drop, forever} {
		if _, err := s.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	n, err := s.Prune(at(2))
	if err != nil || n != 0 {
		t.Errorf("early prune = %d %v, want 0", n, err)
	}
	n, err = s.Prune(at(4))
	if err != nil || n != 1 {
		t.Fatalf("prune = %d %v, want 1", n, err)
	}
	if _, ok := s.Get("drop"); ok {
		t.Error("the pruned record must be gone")
	}
	if len(s.All()) != 2 {
		t.Errorf("records = %d, want 2", len(s.All()))
	}
	if s.Pruned() != 1 {
		t.Errorf("pruned = %d, want 1", s.Pruned())
	}
	head, ok := s.Head()
	if !ok || head.Length != 3 {
		t.Errorf("prune must keep every chain entry, head = %+v", head)
	}
}

func TestPruneSurvivesAReopen(t *testing.T) {
	m := sharedstore.MemoryDoc()
	s := open(t, m)
	drop := rec("drop", 1)
	drop.RetainUntil = at(2)
	if _, err := s.Append(drop); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(rec("keep", 3)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if n, err := s.Prune(at(5)); err != nil || n != 1 {
		t.Fatalf("prune = %d %v", n, err)
	}
	again := open(t, m)
	if _, ok := again.Get("drop"); ok {
		t.Error("a pruned record must not come back")
	}
	if len(again.All()) != 1 {
		t.Errorf("records = %d, want 1", len(again.All()))
	}
}

func TestPruneRollsBackOnSaveFailure(t *testing.T) {
	m := sharedstore.MemoryDoc()
	s := open(t, m)
	drop := rec("drop", 1)
	drop.RetainUntil = at(2)
	if _, err := s.Append(drop); err != nil {
		t.Fatalf("append: %v", err)
	}
	data, _, err := m.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s2 := open(t, &failing{loaded: data})
	if _, err := s2.Prune(at(5)); err == nil {
		t.Fatal("want a save error")
	}
	if _, ok := s2.Get("drop"); !ok {
		t.Error("a failed prune must keep the record")
	}
	if s2.Pruned() != 0 {
		t.Errorf("pruned = %d, want 0", s2.Pruned())
	}
}
