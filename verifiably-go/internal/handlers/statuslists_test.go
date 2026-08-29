package handlers

import (
	"testing"

	"github.com/verifiably/verifiably-go/internal/statuslist"
)

func mkList(t *testing.T, dir, kind, id string) statuslist.Backend {
	t.Helper()
	s, err := statuslist.NewStore(kind, id, dir+"/"+id+"-"+kind+".json",
		"https://issuer.test/status-list/"+kind+"/"+id)
	if err != nil {
		t.Fatalf("new %s store %s: %v", kind, id, err)
	}
	return s
}

// A list is identified by (kind, id) — never id alone.
//
// Regression: the legacy bitstring and token lists BOTH have id "v1", so an
// id-keyed index silently drops whichever registers first, and its publish
// route 404s. The PostgreSQL store has the same latent shape (status_lists
// is keyed by list_id alone), which is why per-DPG ids embed the kind.
func TestStatusListSet_SameIDDifferentKindsBothResolve(t *testing.T) {
	dir := t.TempDir()
	bs := mkList(t, dir, "bitstring", "v1")
	tk := mkList(t, dir, "token", "v1")

	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: bs, Kind: "bitstring"})
	set.Register(&StatusListEntry{Store: tk, Kind: "token"})

	got := set.ByID("bitstring", "v1")
	if got == nil || got.Store != bs {
		t.Errorf("ByID(bitstring,v1) = %v, want the bitstring list", got)
	}
	got = set.ByID("token", "v1")
	if got == nil || got.Store != tk {
		t.Errorf("ByID(token,v1) = %v, want the token list", got)
	}
	// A kind that was never registered under this id must not fall through
	// to the other kind's list.
	if e := set.ByID("token", "nope"); e != nil {
		t.Errorf("ByID(token,nope) = %v, want nil", e)
	}
}

// Revocation must flip a bit in the list the credential was ACTUALLY issued
// against, resolved by the id recorded in its binding.
//
// Regression: this resolved by kind alone, which with per-DPG lists means
// writing to whichever list happens to be the default — marking an
// unrelated credential revoked while leaving the real one valid.
func TestStoreForBinding_ResolvesByListIDNotKind(t *testing.T) {
	dir := t.TempDir()
	def := mkList(t, dir, "token", "v1")
	preauth := mkList(t, dir, "token", "inji-certify-pre-auth-token")
	authcode := mkList(t, dir, "token", "inji-certify-auth-code-token")

	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: def, Kind: "token"}) // default
	set.Register(&StatusListEntry{Store: preauth, DPG: "Inji Certify · Pre-Auth", Kind: "token"})
	set.Register(&StatusListEntry{Store: authcode, DPG: "Inji Certify · Auth-Code", Kind: "token"})
	h := &H{StatusLists: set, TokenStore: def}

	if got := h.storeForBinding("token", "inji-certify-pre-auth-token"); got != preauth {
		t.Errorf("pre-auth binding resolved to %v, want the pre-auth list", got)
	}
	if got := h.storeForBinding("token", "inji-certify-auth-code-token"); got != authcode {
		t.Errorf("auth-code binding resolved to %v, want the auth-code list", got)
	}

	// Records written before per-DPG lists carry no id; they were allocated
	// in the default list and must still resolve there.
	if got := h.storeForBinding("token", ""); got != def {
		t.Errorf("legacy binding (no id) resolved to %v, want the default list", got)
	}
	// An id naming no hosted list must fall back rather than panic.
	if got := h.storeForBinding("token", "gone"); got != def {
		t.Errorf("unknown id resolved to %v, want the default list", got)
	}
}

// The end-to-end consequence of the above: revoking a credential issued by
// one DPG must not mark another DPG's credential revoked at the same index.
func TestStoreForBinding_RevokeDoesNotLeakAcrossDPGs(t *testing.T) {
	dir := t.TempDir()
	def := mkList(t, dir, "token", "v1")
	preauth := mkList(t, dir, "token", "inji-certify-pre-auth-token")
	authcode := mkList(t, dir, "token", "inji-certify-auth-code-token")

	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: def, Kind: "token"})
	set.Register(&StatusListEntry{Store: preauth, DPG: "Inji Certify · Pre-Auth", Kind: "token"})
	set.Register(&StatusListEntry{Store: authcode, DPG: "Inji Certify · Auth-Code", Kind: "token"})
	h := &H{StatusLists: set, TokenStore: def}

	// Both DPGs issue a credential; they get the same index in their own lists.
	idx, err := preauth.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	otherIdx, err := authcode.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if idx != otherIdx {
		t.Fatalf("precondition: independent lists should both start at the same index (%d vs %d)", idx, otherIdx)
	}

	// Revoke the pre-auth one, the way the revoke handler does.
	store := h.storeForBinding("token", "inji-certify-pre-auth-token")
	if err := store.Revoke(idx); err != nil {
		t.Fatal(err)
	}

	if !preauth.IsRevoked(idx) {
		t.Error("pre-auth credential should be revoked in its own list")
	}
	if authcode.IsRevoked(idx) {
		t.Error("revoking a pre-auth credential marked an auth-code credential revoked")
	}
	if def.IsRevoked(idx) {
		t.Error("revoke leaked into the default list")
	}
}

// A DPG with no list of its own falls back to the default, rather than
// dropping the binding and silently issuing an unrevocable credential.
func TestStatusListSet_UnknownDPGFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	def := mkList(t, dir, "token", "v1")
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: def, Kind: "token"})

	if e := set.For("Some DPG That Has No List", "token"); e == nil || e.Store != def {
		t.Errorf("unknown DPG = %v, want the default list", e)
	}
	if e := set.For("anything", "mso_mdoc"); e != nil {
		t.Errorf("unmodelled kind = %v, want nil", e)
	}
}

// Slugs are baked into the credentialStatus URL of every credential already
// issued, so they are a wire format: changing this mapping 404s the status
// list of every credential in the field. Golden-pinned deliberately.
func TestStatusListSlugAndIDAreStable(t *testing.T) {
	for _, tc := range []struct{ vendor, slug, tokenID string }{
		{"Inji Certify · Pre-Auth", "inji-certify-pre-auth", "inji-certify-pre-auth-token"},
		{"Inji Certify · Auth-Code", "inji-certify-auth-code", "inji-certify-auth-code-token"},
		{"walt.id", "walt-id", "walt-id-token"},
		{"CREDEBL", "credebl", "credebl-token"},
	} {
		if got := StatusListSlug(tc.vendor); got != tc.slug {
			t.Errorf("StatusListSlug(%q) = %q, want %q", tc.vendor, got, tc.slug)
		}
		if got := StatusListID(tc.vendor, "token"); got != tc.tokenID {
			t.Errorf("StatusListID(%q,token) = %q, want %q", tc.vendor, got, tc.tokenID)
		}
	}

	// The id must carry the kind: the PostgreSQL store keys status_lists by
	// list_id alone, so two kinds sharing an id collide on one row.
	if StatusListID("walt.id", "token") == StatusListID("walt.id", "bitstring") {
		t.Error("a DPG's token and bitstring list ids must differ")
	}
	// Slugs must be URL- and filename-safe: they land in both a path segment
	// and a key filename.
	for _, v := range []string{"Inji Certify · Pre-Auth", "walt.id", "A/B?c=1 d"} {
		for _, bad := range []string{" ", "/", "?", "·", ".", "="} {
			if got := StatusListSlug(v); contains(got, bad) {
				t.Errorf("StatusListSlug(%q) = %q contains unsafe %q", v, got, bad)
			}
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestStatusListSet_NilGuards(t *testing.T) {
	var nilSet *StatusListSet
	nilSet.Register(&StatusListEntry{}) // must not panic
	if nilSet.ByID("bitstring", "v1") != nil || nilSet.Entries() != nil {
		t.Error("nil set should resolve nothing")
	}
	s := NewStatusListSet()
	s.Register(nil)
	s.Register(&StatusListEntry{Kind: "bitstring"}) // nil Store ignored
	if len(s.Entries()) != 0 {
		t.Errorf("entries after ignored registers = %d, want 0", len(s.Entries()))
	}
	if s.ByID("bitstring", "") != nil {
		t.Error("empty id should resolve nil")
	}
}

func TestStatusListSet_EntriesListsEveryRegisteredList(t *testing.T) {
	dir := t.TempDir()
	s := NewStatusListSet()
	s.Register(&StatusListEntry{Store: mkList(t, dir, "bitstring", "v1"), Kind: "bitstring"})
	s.Register(&StatusListEntry{Store: mkList(t, dir, "token", "v1"), Kind: "token"})
	s.Register(&StatusListEntry{Store: mkList(t, dir, "bitstring", "walt-id-bitstring"), DPG: "walt.id", Kind: "bitstring"})
	got := map[string]bool{}
	for _, e := range s.Entries() {
		got[indexKey(e.Kind, e.Store.GetListID())] = true
	}
	for _, want := range []string{"bitstring/v1", "token/v1", "bitstring/walt-id-bitstring"} {
		if !got[want] {
			t.Errorf("Entries missing %s (got %v)", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("Entries len = %d, want 3", len(got))
	}
}

func TestStatusListID_EmptyVendorFallsBackToKind(t *testing.T) {
	if got := StatusListID("", "token"); got != "token" {
		t.Errorf("StatusListID(\"\") = %q, want token", got)
	}
	if got := StatusListID("···", "bitstring"); got != "bitstring" {
		t.Errorf("all-separator vendor = %q, want bitstring", got)
	}
}
