// SPDX-License-Identifier: Apache-2.0

package lookup

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// fake is a publisher whose Verify returns fixed entries or an error.
type fake struct {
	method  string
	entries []entry.Entry
	err     error
	expires time.Time
}

func (f fake) Method() string { return f.method }
func (f fake) Publish(publish.Input) (publish.Publication, error) {
	return publish.Publication{Method: f.method, Files: map[string]publish.File{"/" + f.method: {}}}, nil
}
func (f fake) Verify(map[string]publish.File, jose.JWKS, time.Time) (publish.Verified, error) {
	if f.err != nil {
		return publish.Verified{}, f.err
	}
	return publish.Verified{Entries: f.entries, Sequence: 1, KeyID: "k-" + f.method, ListURL: "https://t/" + f.method, ExpiresAt: f.expires}, nil
}

func snapshot(t *testing.T, pubs ...publish.Publisher) *publish.Snapshot {
	t.Helper()
	var list []publish.Publication
	for _, p := range pubs {
		pub, verr := p.Publish(publish.Input{})
		if verr != nil {
			t.Fatalf("unexpected error: %v", verr)
		}
		list = append(list, pub)
	}
	s, err := publish.NewSnapshot(list...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParsePolicy(t *testing.T) {
	for in, want := range map[string]Policy{"": FailClosed, "fail-closed": FailClosed, "fail-open": FailOpen} {
		if got, err := ParsePolicy(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParsePolicy("maybe"); err == nil {
		t.Fatal("bad policy")
	}
}

func TestLookupAcrossMethods(t *testing.T) {
	issuer := entry.Entry{DID: "did:web:i", Role: entry.RoleIssuer, Status: entry.StatusActive}
	revoked := entry.Entry{DID: "did:web:r", Role: entry.RoleIssuer, Status: entry.StatusRevoked}
	etsi := fake{method: "etsi", entries: []entry.Entry{revoked}, expires: t0.Add(time.Hour)}
	dedi := fake{method: "dedi", entries: []entry.Entry{issuer, revoked}, expires: t0.Add(time.Hour)}
	now := t0
	c := New([]publish.Publisher{etsi, dedi}, func() jose.JWKS { return jose.JWKS{} }, Options{Now: func() time.Time { return now }})
	if r := c.Lookup("did:web:i", entry.RoleIssuer, "", t0); r.Outcome != Unavailable || c.Methods() != nil {
		t.Fatalf("empty cache %+v", r)
	}
	if err := c.Refresh(snapshot(t, etsi, dedi)); err != nil {
		t.Fatal(err)
	}
	if m := c.Methods(); len(m) != 2 || m[0] != "etsi" {
		t.Fatalf("methods %v", m)
	}
	r := c.Lookup("did:web:i", entry.RoleIssuer, "", t0)
	if r.Outcome != Trusted || r.Method != "dedi" || r.KeyID != "k-dedi" || r.ListURL != "https://t/dedi" || r.CheckedAt != t0 || r.Stale || r.Entry == nil {
		t.Fatalf("trusted %+v", r)
	}
	r = c.Lookup("did:web:r", entry.RoleIssuer, "", t0)
	if r.Outcome != Untrusted || r.Method != "etsi" || !strings.Contains(r.Reason, "revoked") {
		t.Fatalf("untrusted %+v", r)
	}
	r = c.Lookup("did:web:x", entry.RoleIssuer, "", t0)
	if r.Outcome != Unknown || r.Method != "etsi" {
		t.Fatalf("unknown %+v", r)
	}
	// Unknown in the first method, untrusted in the second: untrusted wins.
	c2 := New([]publish.Publisher{fake{method: "etsi", expires: t0.Add(time.Hour)}, etsi}, func() jose.JWKS { return jose.JWKS{} }, Options{Now: func() time.Time { return now }})
	c2.publishers[1] = fake{method: "dedi", entries: []entry.Entry{revoked}, expires: t0.Add(time.Hour)}
	if err := c2.Refresh(snapshot(t, c2.publishers...)); err != nil {
		t.Fatal(err)
	}
	if r := c2.Lookup("did:web:r", entry.RoleIssuer, "", t0); r.Outcome != Untrusted || r.Method != "dedi" {
		t.Fatalf("rank %+v", r)
	}
}

func TestStalePolicies(t *testing.T) {
	issuer := entry.Entry{DID: "did:web:i", Role: entry.RoleIssuer, Status: entry.StatusActive}
	etsi := fake{method: "etsi", entries: []entry.Entry{issuer}, expires: t0.Add(24 * time.Hour)}
	now := t0
	clock := func() time.Time { return now }
	closed := New([]publish.Publisher{etsi}, func() jose.JWKS { return jose.JWKS{} }, Options{Policy: FailClosed, MaxAge: time.Hour, Now: clock})
	open := New([]publish.Publisher{etsi}, func() jose.JWKS { return jose.JWKS{} }, Options{Policy: FailOpen, MaxAge: time.Hour, Now: clock})
	snap := snapshot(t, etsi)
	if err := closed.Refresh(snap); err != nil {
		t.Fatal(err)
	}
	if err := open.Refresh(snap); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(2 * time.Hour)
	r := closed.Lookup("did:web:i", entry.RoleIssuer, "", now)
	if r.Outcome != Unavailable || !r.Stale || r.Method != "etsi" || !strings.Contains(r.Reason, "fail-closed") {
		t.Fatalf("closed %+v", r)
	}
	r = open.Lookup("did:web:i", entry.RoleIssuer, "", now)
	if r.Outcome != Trusted || !r.Stale {
		t.Fatalf("open %+v", r)
	}
	// A fresh check but an expired list is stale too.
	now = t0
	if err := closed.Refresh(snap); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(25 * time.Hour)
	closed.copies["etsi"] = copy{Verified: closed.copies["etsi"].Verified, checkedAt: now}
	if r := closed.Lookup("did:web:i", entry.RoleIssuer, "", now); r.Outcome != Unavailable {
		t.Fatalf("expired list %+v", r)
	}
}

func TestRefreshErrors(t *testing.T) {
	good := fake{method: "etsi", entries: []entry.Entry{{DID: "did:web:i", Role: entry.RoleIssuer, Status: entry.StatusActive}}, expires: t0.Add(time.Hour)}
	bad := fake{method: "dedi", err: errors.New("bad signature")}
	c := New([]publish.Publisher{good, bad}, func() jose.JWKS { return jose.JWKS{} }, Options{Now: func() time.Time { return t0 }})
	err := c.Refresh(snapshot(t, good, bad))
	if err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Fatal("refresh must report the failed method")
	}
	if m := c.Methods(); len(m) != 1 || m[0] != "etsi" {
		t.Fatalf("methods %v", m)
	}
	if r := c.Lookup("did:web:i", entry.RoleIssuer, "", t0); r.Outcome != Trusted {
		t.Fatalf("good method still answers %+v", r)
	}
	if err := c.Refresh(snapshot(t)); err != nil || len(c.Methods()) != 1 {
		t.Fatal("empty snapshot keeps copies")
	}
	if c.opts.MaxAge != time.Hour || c.opts.Policy != FailClosed {
		t.Fatal("defaults")
	}
	if New(nil, nil, Options{}).opts.Now == nil {
		t.Fatal("default clock")
	}
}
