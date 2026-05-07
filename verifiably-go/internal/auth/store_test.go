package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserStore_LoadMissingIsEmpty(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	cfgs, err := s.Load()
	if err != nil {
		t.Fatalf("load missing file: %v", err)
	}
	if len(cfgs) != 0 {
		t.Fatalf("want empty, got %d", len(cfgs))
	}
}

func TestUserStore_AddAndLoadRoundtrip(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	if _, err := s.Add(ProviderConfig{
		ID: "alpha", Type: "oidc", DisplayName: "Alpha",
		IssuerURL: "https://idp.example.com", ClientID: "abc",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].ID != "alpha" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Source != SourceUser {
		t.Errorf("expected Source=user, got %q", got[0].Source)
	}
}

func TestUserStore_AddUpsertsByID(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	if _, err := s.Add(ProviderConfig{ID: "x", DisplayName: "First"}); err != nil {
		t.Fatalf("add#1: %v", err)
	}
	if _, err := s.Add(ProviderConfig{ID: "x", DisplayName: "Second"}); err != nil {
		t.Fatalf("add#2: %v", err)
	}
	got, _ := s.Load()
	if len(got) != 1 {
		t.Fatalf("expected single entry after upsert, got %d", len(got))
	}
	if got[0].DisplayName != "Second" {
		t.Errorf("upsert did not replace; got %q", got[0].DisplayName)
	}
}

func TestUserStore_RemoveReportsHit(t *testing.T) {
	s := NewUserStore(filepath.Join(t.TempDir(), "user.json"))
	_, _ = s.Add(ProviderConfig{ID: "a"})
	_, _ = s.Add(ProviderConfig{ID: "b"})

	rest, ok, err := s.Remove("a")
	if err != nil {
		t.Fatalf("remove a: %v", err)
	}
	if !ok || len(rest) != 1 || rest[0].ID != "b" {
		t.Fatalf("first remove unexpected: ok=%v rest=%+v", ok, rest)
	}
	rest, ok, err = s.Remove("a")
	if err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if ok {
		t.Fatal("second Remove(a) returned ok=true; want false")
	}
	if len(rest) != 1 {
		t.Errorf("rest changed unexpectedly: %+v", rest)
	}
}

// TestUserStore_OverwriteInPlace pins the deliberate non-rename behaviour
// — Save must write to the exact same inode every time so the deploy.sh
// single-file bind mount stays valid. We assert the inode is stable across
// successive saves, which would not hold for a write-tmp+rename pattern.
func TestUserStore_OverwriteInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user.json")
	s := NewUserStore(path)
	if err := s.Save([]ProviderConfig{{ID: "first"}}); err != nil {
		t.Fatalf("save#1: %v", err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat#1: %v", err)
	}
	if err := s.Save([]ProviderConfig{{ID: "second"}}); err != nil {
		t.Fatalf("save#2: %v", err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat#2: %v", err)
	}
	if !os.SameFile(first, second) {
		t.Error("Save changed the file inode — would break a Docker single-file bind mount")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("unexpected scratch file %q in dir", e.Name())
		}
	}
}

// TestUserStore_SourceNotPersisted pins the json:"-" tag — a hand-edited
// user.json that contains "source":"system" must NOT propagate into the
// loaded config (otherwise the admin UI could be tricked into refusing
// to delete a user-added entry).
func TestUserStore_SourceNotPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.json")
	if err := os.WriteFile(path, []byte(`[{"id":"x","source":"system","displayName":"X"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgs, err := NewUserStore(path).Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfgs) != 1 || cfgs[0].Source != SourceUser {
		t.Errorf("Source should be forced to user, got %q", cfgs[0].Source)
	}
}
