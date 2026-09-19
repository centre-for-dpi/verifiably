// SPDX-License-Identifier: Apache-2.0

package record

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func sample() Record {
	return Record{
		ID: "rec-1", SchemaID: "sch", SchemaVersion: 1,
		SubjectRef: SubjectRef("salt", "did:example:ada"),
		Format:     "dc+sd-jwt", Status: Active, IssuedAt: base,
		SearchableClaims: map[string]string{"given_name": "Ada"},
	}
}

func TestSubjectRefIsSaltedAndStable(t *testing.T) {
	a := SubjectRef("salt", "did:example:ada")
	if a != SubjectRef("salt", "did:example:ada") {
		t.Fatal("the reference must be stable")
	}
	if a == SubjectRef("pepper", "did:example:ada") {
		t.Fatal("a different salt must give a different reference")
	}
	if strings.Contains(a, "ada") || len(a) != 64 {
		t.Fatalf("reference %q", a)
	}
}

func TestValidate(t *testing.T) {
	if err := sample().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Record{
		{},
		{ID: "a"},
		{ID: "a", SchemaID: "s"},
		{ID: "a", SchemaID: "s", SchemaVersion: 1},
		{ID: "a", SchemaID: "s", SchemaVersion: 1, SubjectRef: "r"},
		{ID: "a", SchemaID: "s", SchemaVersion: 1, SubjectRef: "did:example:ada", IssuedAt: base},
	}
	for i, r := range bad {
		if err := r.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d must fail: %v", i, err)
		}
	}
}

func TestKeep(t *testing.T) {
	claims := map[string]string{"given_name": "Ada", "birth_date": "1815-12-10"}
	got := Keep(claims, []string{"given_name", "absent"})
	if len(got) != 1 || got["given_name"] != "Ada" {
		t.Fatalf("keep: %v", got)
	}
	if Keep(claims, nil) != nil || Keep(nil, []string{"a"}) != nil {
		t.Fatal("no allow list keeps nothing")
	}
	if Keep(claims, []string{"absent"}) != nil {
		t.Fatal("no match keeps nothing")
	}
}

func TestNextStatusAndApply(t *testing.T) {
	if err := NextStatus(Active, Revoked); err != nil {
		t.Fatal(err)
	}
	if err := NextStatus(Suspended, Active); err != nil {
		t.Fatal(err)
	}
	if err := NextStatus(Revoked, Active); !errors.Is(err, ErrFinal) {
		t.Fatalf("revoked is final: %v", err)
	}
	if err := NextStatus(Active, Expired); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired is not a change: %v", err)
	}
	got := sample().Apply(Change{Status: Suspended, Reason: "under review", ChangedAt: base})
	if got.Status != Suspended || got.StatusReason != "under review" || !got.StatusChangedAt.Equal(base) {
		t.Fatalf("apply: %+v", got)
	}
}

func TestExpired(t *testing.T) {
	r := sample()
	if r.Expired(base) {
		t.Fatal("no window never expires")
	}
	r.ValidUntil = base
	if r.Expired(base) || !r.Expired(base.Add(time.Second)) {
		t.Fatal("expired")
	}
}

func TestFilterMatch(t *testing.T) {
	r := sample()
	if !(Filter{}).Match(r) {
		t.Fatal("an empty filter matches everything")
	}
	cases := []Filter{
		{SchemaID: "other"},
		{Status: Revoked},
		{Format: "ldp_vc"},
		{SubjectRef: "other"},
		{From: base.Add(time.Hour)},
		{To: base.Add(-time.Hour)},
	}
	for i, f := range cases {
		if f.Match(r) {
			t.Fatalf("case %d must not match", i)
		}
	}
	ok := Filter{SchemaID: "sch", Status: Active, Format: "dc+sd-jwt", SubjectRef: r.SubjectRef, From: base, To: base}
	if !ok.Match(r) {
		t.Fatal("a full filter must match")
	}
}

func TestMatches(t *testing.T) {
	r := sample()
	if !r.Matches("") || !r.Matches("ada") || !r.Matches(" ADA ") {
		t.Fatal("the search must ignore case and space")
	}
	if r.Matches("grace") {
		t.Fatal("no match")
	}
	r.SearchableClaims = nil
	if r.Matches("ada") {
		t.Fatal("no claims, no match")
	}
}

func TestSortAndClaimNames(t *testing.T) {
	rs := []Record{
		{ID: "b", IssuedAt: base, SearchableClaims: map[string]string{"z": "1"}},
		{ID: "a", IssuedAt: base, SearchableClaims: map[string]string{"a": "1"}},
		{ID: "c", IssuedAt: base.Add(time.Hour)},
	}
	SortNewestFirst(rs)
	if rs[0].ID != "c" || rs[1].ID != "a" || rs[2].ID != "b" {
		t.Fatalf("order: %v", []string{rs[0].ID, rs[1].ID, rs[2].ID})
	}
	names := ClaimNames(rs)
	if strings.Join(names, ",") != "a,z" {
		t.Fatalf("claims: %v", names)
	}
}

func TestBindingIsZero(t *testing.T) {
	if !(Binding{}).IsZero() || (Binding{ListID: "v1"}).IsZero() {
		t.Fatal("IsZero")
	}
}

func TestNewIDIsStableAndUnique(t *testing.T) {
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	first := NewID(at, "diploma", "hash-a")
	if len(first) != IDLength {
		t.Fatalf("len = %d, want %d", len(first), IDLength)
	}
	if first != NewID(at, "diploma", "hash-a") {
		t.Error("the same issuance must get the same id")
	}
	if first == NewID(at, "diploma", "hash-b") {
		t.Error("another credential must get another id")
	}
	if first == NewID(at.Add(time.Second), "diploma", "hash-a") {
		t.Error("another time must get another id")
	}
}
