package issuance

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAppendListGet(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLog(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	a := IssuedCredential{
		ID: "vc-1", SchemaID: "sx", SchemaName: "Driver License",
		Std: "w3c_vcdm_2", Format: "ldp_vc", IssuerDpg: "Walt Community Stack",
		HolderHint: "Wanjiru",
		SubjectFields: map[string]string{"fullName": "Wanjiru", "id": "X"},
		StatusList: &StatusListEntry{Type: "bitstring", ListID: "v1", Index: 0},
	}
	if _, err := l.Append(a); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := l.Append(a); err == nil {
		t.Fatal("duplicate id should error")
	}
	got, ok := l.Get("vc-1")
	if !ok || got.ID != "vc-1" {
		t.Fatalf("Get: ok=%v got=%+v", ok, got)
	}
	if got.IssuedAt.IsZero() {
		t.Fatal("IssuedAt should auto-populate")
	}
}

func TestListFilter(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLog(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	mustAppend := func(c IssuedCredential) {
		if _, err := l.Append(c); err != nil {
			t.Fatalf("append %s: %v", c.ID, err)
		}
	}
	mustAppend(IssuedCredential{ID: "a", SchemaName: "Driver License", Std: "w3c_vcdm_2", Format: "ldp_vc", HolderHint: "Wanjiru"})
	mustAppend(IssuedCredential{ID: "b", SchemaName: "Health Card", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", HolderHint: "Otieno", SubjectFields: map[string]string{"fullName": "Otieno"}})
	mustAppend(IssuedCredential{ID: "c", SchemaName: "Mobile DL", Std: "mso_mdoc", Format: "mso_mdoc", HolderHint: "Achieng"})

	if got := l.List(Filter{}); len(got) != 3 {
		t.Fatalf("no filter: got %d, want 3", len(got))
	}
	if got := l.List(Filter{Std: "w3c_vcdm_2"}); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("std filter: got %+v", got)
	}
	if got := l.List(Filter{Query: "wanjiru"}); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("query holder hint case-insensitive: got %+v", got)
	}
	if got := l.List(Filter{Query: "health"}); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("query schema name: got %+v", got)
	}
	if got := l.List(Filter{Query: "otieno"}); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("query into subject fields: got %+v", got)
	}
	if got := l.List(Filter{Format: "vc+sd-jwt"}); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("format filter: got %+v", got)
	}
}

func TestRevoke(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLog(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	if _, err := l.Append(IssuedCredential{ID: "a", IssuedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := l.MarkRevoked("a", "")
	if err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("RevokedAt should be set")
	}
	// Revoking again is idempotent.
	if _, err := l.MarkRevoked("a", ""); err != nil {
		t.Fatalf("MarkRevoked again: %v", err)
	}
	if _, err := l.MarkRevoked("missing", ""); err == nil {
		t.Fatal("MarkRevoked on missing id should error")
	}
	// state filter
	if got := l.List(Filter{State: "active"}); len(got) != 0 {
		t.Fatalf("state=active should be 0: got %+v", got)
	}
	if got := l.List(Filter{State: "revoked"}); len(got) != 1 {
		t.Fatalf("state=revoked should be 1: got %+v", got)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.json")
	l1, err := NewLog(path)
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	if _, err := l1.Append(IssuedCredential{ID: "x", SchemaName: "Z"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	l2, err := NewLog(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := l2.List(Filter{})
	if len(got) != 1 || got[0].ID != "x" {
		t.Fatalf("persistence: got %+v", got)
	}
}

// TestOwnerKeyScoping pins the per-issuer isolation contract on the log.
// Two issuers share the same on-disk log (single verifiably-go instance)
// and must each see only their own entries plus be unable to revoke each
// other's credentials.
func TestOwnerKeyScoping(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLog(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	mustAppend := func(c IssuedCredential) {
		if _, err := l.Append(c); err != nil {
			t.Fatalf("append %s: %v", c.ID, err)
		}
	}
	mustAppend(IssuedCredential{ID: "alice-1", SchemaName: "License", OwnerKey: "alice"})
	mustAppend(IssuedCredential{ID: "alice-2", SchemaName: "Cert", OwnerKey: "alice"})
	mustAppend(IssuedCredential{ID: "bob-1", SchemaName: "Pass", OwnerKey: "bob"})
	mustAppend(IssuedCredential{ID: "legacy", SchemaName: "Old"}) // pre-scoping

	// Alice's view: just her two entries.
	got := l.List(Filter{OwnerKey: "alice"})
	if len(got) != 2 {
		t.Fatalf("alice should see 2: got %d (%+v)", len(got), got)
	}
	for _, c := range got {
		if c.OwnerKey != "alice" {
			t.Fatalf("alice should never see entries owned by %q: %+v", c.OwnerKey, c)
		}
	}

	// Bob's view: just his.
	got = l.List(Filter{OwnerKey: "bob"})
	if len(got) != 1 || got[0].ID != "bob-1" {
		t.Fatalf("bob should see exactly bob-1: got %+v", got)
	}

	// Admin (no owner filter) sees everything including the legacy entry.
	got = l.List(Filter{})
	if len(got) != 4 {
		t.Fatalf("admin should see all 4: got %d (%+v)", len(got), got)
	}

	// Bob can't revoke Alice's credential by guessing the id — surfaced as
	// not-found so the existence of alice-1 isn't disclosed to bob.
	if _, err := l.MarkRevoked("alice-1", "bob"); err == nil {
		t.Fatal("bob should not be able to revoke alice's credential")
	}
	a, ok := l.Get("alice-1")
	if !ok || a.RevokedAt != nil {
		t.Fatalf("alice-1 must remain unrevoked after bob's attempt: %+v", a)
	}

	// Alice can revoke her own.
	if _, err := l.MarkRevoked("alice-1", "alice"); err != nil {
		t.Fatalf("alice should be able to revoke her own credential: %v", err)
	}

	// Admin (empty owner) keeps the bypass — needed for cli/migration use.
	if _, err := l.MarkRevoked("legacy", ""); err != nil {
		t.Fatalf("admin revoke on legacy entry should succeed: %v", err)
	}
}

// ─── Hash chain ───────────────────────────────────────────────────────────────

func TestHashChain_AppendSetsHash(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewLog(filepath.Join(dir, "log.json"))

	a, _ := l.Append(IssuedCredential{ID: "first", SchemaID: "s1"})
	if a.PrevHash != "" {
		t.Errorf("genesis entry should have empty PrevHash, got %q", a.PrevHash)
	}
	b, _ := l.Append(IssuedCredential{ID: "second", SchemaID: "s1"})
	if b.PrevHash == "" {
		t.Fatal("second entry must have non-empty PrevHash")
	}
	if b.PrevHash != chainHashOf(a) {
		t.Errorf("second.PrevHash = %q\nwant chainHashOf(first) = %q", b.PrevHash, chainHashOf(a))
	}
}

func TestHashChain_VerifyIntact(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewLog(filepath.Join(dir, "log.json"))
	for _, id := range []string{"a", "b", "c"} {
		if _, err := l.Append(IssuedCredential{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if errs := l.VerifyChain(); len(errs) != 0 {
		t.Fatalf("intact chain should pass VerifyChain: %v", errs)
	}
}

func TestHashChain_VerifyTampered(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewLog(filepath.Join(dir, "log.json"))
	for _, id := range []string{"a", "b", "c"} {
		if _, err := l.Append(IssuedCredential{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupt PrevHash of the third entry.
	l.mu.Lock()
	orig := l.items[2].PrevHash
	l.items[2].PrevHash = "deadbeef" + orig[8:]
	l.mu.Unlock()

	errs := l.VerifyChain()
	if len(errs) == 0 {
		t.Fatal("tampered chain should fail VerifyChain")
	}
}

func TestHashChain_BackwardCompat(t *testing.T) {
	// Entries without PrevHash (pre-chain) must not be flagged as corrupt.
	dir := t.TempDir()
	l, _ := NewLog(filepath.Join(dir, "log.json"))

	// Inject a pre-chain entry directly, bypassing Append's hash logic.
	l.mu.Lock()
	l.items = append(l.items, IssuedCredential{ID: "legacy", IssuedAt: time.Now().UTC()})
	l.mu.Unlock()

	// Append a chained entry on top — it will link to "legacy".
	if _, err := l.Append(IssuedCredential{ID: "chained"}); err != nil {
		t.Fatal(err)
	}
	if errs := l.VerifyChain(); len(errs) != 0 {
		t.Fatalf("chain after legacy entry should pass: %v", errs)
	}
}

func TestSummary(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLog(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	mustAppend := func(c IssuedCredential) {
		if _, err := l.Append(c); err != nil {
			t.Fatal(err)
		}
	}
	mustAppend(IssuedCredential{ID: "1", Std: "w3c_vcdm_2", Format: "ldp_vc"})
	mustAppend(IssuedCredential{ID: "2", Std: "w3c_vcdm_2", Format: "ldp_vc"})
	mustAppend(IssuedCredential{ID: "3", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt"})
	if _, err := l.MarkRevoked("3", ""); err != nil {
		t.Fatal(err)
	}
	s := l.Summary()
	if s.Total != 3 || s.Active != 2 || s.Revoked != 1 {
		t.Fatalf("totals: %+v", s)
	}
	if s.ByStd["w3c_vcdm_2"] != 2 || s.ByStd["sd_jwt_vc (IETF)"] != 1 {
		t.Fatalf("ByStd: %+v", s.ByStd)
	}
}
