// SPDX-License-Identifier: Apache-2.0

package lists

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// fakeSecurer writes the record values as JSON. It produces two media
// types so the tests cover Accept selection.
type fakeSecurer struct {
	kind Kind
	fail error
	// calls counts Secure calls.
	calls int
}

func (f *fakeSecurer) Kind() Kind { return f.kind }
func (f *fakeSecurer) MediaTypes() []string {
	return []string{"application/test+json", "application/test+cbor"}
}
func (f *fakeSecurer) Secure(rec Record, issuer keys.Issuer, url string, signedAt, expiresAt time.Time) ([]Unsigned, error) {
	f.calls++
	if f.fail != nil {
		return nil, f.fail
	}
	body, _ := json.Marshal(map[string]any{
		"url": url, "iss": issuer.DID(), "kid": issuer.Kid(issuer.Active()), "values": rec.Values,
		"iat": signedAt.Unix(), "exp": expiresAt.Unix(),
	})
	return []Unsigned{{MediaType: "application/test+json", Body: body}, {MediaType: "application/test+cbor", Body: append([]byte{0xa0}, body...)}}, nil
}

// emptySecurer returns no artifact.
type emptySecurer struct{ fakeSecurer }

func (e *emptySecurer) Secure(Record, keys.Issuer, string, time.Time, time.Time) ([]Unsigned, error) {
	return nil, nil
}

func newIssuers(t *testing.T, kv store.KeyValue, dids ...string) *keys.Issuers {
	t.Helper()
	is, err := keys.Open(context.Background(), kv, keys.Options{Configured: dids, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	return is
}

func TestNewRecord(t *testing.T) {
	r, err := NewRecord("a", KindBitstring, Revocation, 0, 10, "s", t0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Size != bitstring.MinSize || r.Bits != 1 || r.Free() != bitstring.MinSize || len(r.Values) != bitstring.MinSize/8 {
		t.Fatalf("record = %+v", r)
	}
	tok, err := NewRecord("b", KindToken, Suspension, 2, 5, "s", t0)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Size != 5 || tok.Bits != 2 || len(tok.Values) != 2 || len(tok.Allocated) != 1 || tok.Allocated[0] != 0b00000111 {
		t.Fatalf("token record = %+v", tok)
	}
	tok1, err := NewRecord("c", KindToken, Message, 0, 8, "s", t0)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	if tok1.Bits != 1 || tok1.Allocated[0] != 0 {
		t.Fatalf("token bits default = %+v", tok1)
	}
	bad := []struct {
		kind    Kind
		purpose Purpose
		bits    int
		size    int
	}{
		{KindBitstring, "other", 1, 10},
		{KindBitstring, Revocation, 2, 10},
		{KindToken, Revocation, 3, 10},
		{KindToken, Revocation, 1, 0},
		{"mdoc", Revocation, 1, 10},
	}
	for _, tc := range bad {
		if _, err := NewRecord("x", tc.kind, tc.purpose, tc.bits, tc.size, "s", t0); err == nil {
			t.Errorf("%+v: expected error", tc)
		}
	}
}

func TestAllocateNoReuse(t *testing.T) {
	r, rErr := NewRecord("t", KindToken, Revocation, 1, 13, "s", t0)
	if rErr != nil {
		t.Fatalf("NewRecord: %v", rErr)
	}
	seen := map[int]bool{}
	for i := 0; i < 13; i++ {
		idx, err := r.Allocate(nil)
		if err != nil {
			t.Fatal(err)
		}
		if idx < 0 || idx >= 13 || seen[idx] {
			t.Fatalf("index %d out of range or reused", idx)
		}
		seen[idx] = true
		if !r.IsAllocated(idx) {
			t.Fatal("IsAllocated")
		}
	}
	if _, err := r.Allocate(nil); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v", err)
	}
	if r.IsAllocated(-1) || r.IsAllocated(13) {
		t.Fatal("IsAllocated out of range")
	}
	if _, err := r.Allocate(bytes.NewReader(nil)); !errors.Is(err, ErrFull) {
		t.Fatal("full check must come first")
	}
	fresh, freshErr := NewRecord("f", KindToken, Revocation, 1, 300, "s", t0)
	if freshErr != nil {
		t.Fatalf("NewRecord: %v", freshErr)
	}
	if _, err := fresh.Allocate(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected entropy error")
	}
	// A corrupt count makes Allocate fail instead of returning a used index.
	corrupt, err := NewRecord("c", KindToken, Revocation, 1, 8, "s", t0)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	corrupt.Allocated[0] = 0xff
	if _, err := corrupt.Allocate(nil); err == nil || errors.Is(err, ErrFull) {
		t.Fatalf("err = %v", err)
	}
}

func TestAllocateIsRandom(t *testing.T) {
	r, err := NewRecord("t", KindToken, Revocation, 1, 4096, "s", t0)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	var first []int
	for i := 0; i < 8; i++ {
		idx, err := r.Allocate(nil)
		if err != nil {
			t.Fatalf("r.Allocate: %v", err)
		}
		first = append(first, idx)
	}
	sorted := true
	for i := 1; i < len(first); i++ {
		if first[i] < first[i-1] {
			sorted = false
		}
	}
	if sorted {
		t.Fatalf("8 allocations came out in order: %v", first)
	}
}

func TestSetGetBitstring(t *testing.T) {
	r, rErr := NewRecord("b", KindBitstring, Revocation, 1, 0, "s", t0)
	if rErr != nil {
		t.Fatalf("NewRecord: %v", rErr)
	}
	idx, idxErr := r.Allocate(nil)
	if idxErr != nil {
		t.Fatalf("r.Allocate: %v", idxErr)
	}
	if _, err := r.Set(idx+1, 1, t0); !errors.Is(err, ErrNotAllocated) && !r.IsAllocated(idx+1) {
		t.Fatalf("err = %v", err)
	}
	prev, err := r.Set(idx, 1, t0)
	if err != nil || prev != 0 {
		t.Fatalf("set: %d %v", prev, err)
	}
	v, err := r.Get(idx)
	if err != nil || v != 1 {
		t.Fatalf("get: %d %v", v, err)
	}
	if at, ok := r.ChangedAt(idx); !ok || !at.Equal(t0) {
		t.Fatal("ChangedAt")
	}
	if _, ok := r.ChangedAt(idx + 1); ok {
		t.Fatal("ChangedAt of an unchanged index")
	}
	if _, err := r.Set(idx, 2, t0); err == nil {
		t.Fatal("expected 1 bit error")
	}
	if _, err := r.Set(idx, -1, t0); err == nil {
		t.Fatal("expected range error")
	}
	if _, err := r.Set(idx, 256, t0); err == nil {
		t.Fatal("expected range error")
	}
	if _, err := r.Get(-1); !errors.Is(err, bitstring.ErrOutOfRange) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := r.BitstringList().Get(idx); !got {
		t.Fatal("BitstringList")
	}
	prev, errAssign := r.Set(idx, 0, t0)
	if errAssign != nil {
		t.Fatalf("r.Set: %v", errAssign)
	}
	if prev != 1 {
		t.Fatal("prev")
	}
}

func TestSetGetToken(t *testing.T) {
	r, rErr := NewRecord("t", KindToken, Message, 8, 4, "s", t0)
	if rErr != nil {
		t.Fatalf("NewRecord: %v", rErr)
	}
	idx, idxErr := r.Allocate(nil)
	if idxErr != nil {
		t.Fatalf("r.Allocate: %v", idxErr)
	}
	if _, err := r.Set(idx, 200, t0); err != nil {
		t.Fatal(err)
	}
	if v, _ := r.Get(idx); v != 200 {
		t.Fatalf("v = %d", v)
	}
	l, lErr := r.TokenList()
	if lErr != nil {
		t.Fatal(lErr)
	}
	if v, _ := l.Get(idx); v != 200 {
		t.Fatal("TokenList")
	}
	if _, err := r.Get(4); err == nil {
		t.Fatal("expected range error")
	}
	two, err := NewRecord("t2", KindToken, Message, 2, 4, "s", t0)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	idx, errAssign := two.Allocate(nil)
	if errAssign != nil {
		t.Fatalf("two.Allocate: %v", errAssign)
	}
	if _, err := two.Set(idx, 4, t0); err == nil {
		t.Fatal("expected width error")
	}
	two.Bits = 3
	if _, err := two.Get(0); err == nil {
		t.Fatal("expected bits error")
	}
	if _, err := two.TokenList(); err == nil {
		t.Fatal("expected bits error")
	}
}

func openManager(t *testing.T, kv store.KeyValue, sec Securer, size int) *Manager {
	t.Helper()
	m, err := Open(context.Background(), Options{
		Store: kv, Issuers: newIssuers(t, kv), Securer: sec, BaseURL: "https://status.example/",
		Size: size, TTL: time.Hour, Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManagerLifecycle(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	sec := &fakeSecurer{kind: KindToken}
	m := openManager(t, kv, sec, 4)
	if m.Kind() != KindToken || len(m.MediaTypes()) != 2 || m.URL("x") != "https://status.example/status/x" {
		t.Fatal("accessors")
	}
	a, aErr := m.Allocate(ctx, "", Revocation, 0)
	if aErr != nil {
		t.Fatal(aErr)
	}
	if a.URL != m.URL(a.ListID) || a.Purpose != Revocation || len(a.ListID) != 32 {
		t.Fatalf("allocation = %+v", a)
	}
	if sec.calls != 1 {
		t.Fatalf("a new list is signed once, calls = %d", sec.calls)
	}
	// Three more fill the list. The fifth makes a new list.
	ids := map[string]bool{a.ListID: true}
	for i := 0; i < 4; i++ {
		b, err := m.Allocate(ctx, "", Revocation, 1)
		if err != nil {
			t.Fatal(err)
		}
		ids[b.ListID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 lists, got %d", len(ids))
	}
	// A different purpose or width gets its own list.
	s, sErr := m.Allocate(ctx, "", Suspension, 1)
	if sErr != nil {
		t.Fatalf("m.Allocate: %v", sErr)
	}
	w, wErr := m.Allocate(ctx, "", Suspension, 2)
	if wErr != nil {
		t.Fatalf("m.Allocate: %v", wErr)
	}
	if ids[s.ListID] || s.ListID == w.ListID {
		t.Fatal("purpose and width must select the list")
	}
	prev, signed, err := m.Set(ctx, a.ListID, a.Index, 1)
	if err != nil || prev != 0 || signed.ListID != a.ListID || !signed.SignedAt.Equal(t0) || !signed.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("set: %d %+v %v", prev, signed, err)
	}
	if signed.KeyID == "" || signed.IssuerDID == "" || len(signed.Artifacts) != 2 || signed.Artifacts[0].ETag == "" {
		t.Fatalf("signed = %+v", signed)
	}
	if art, ok := signed.Artifact(""); !ok || art.MediaType != "application/test+json" {
		t.Fatal("default artifact")
	}
	if art, ok := signed.Artifact("APPLICATION/test+cbor"); !ok || art.Body[0] != 0xa0 {
		t.Fatal("cbor artifact")
	}
	if _, ok := signed.Artifact("text/plain"); ok {
		t.Fatal("unknown artifact")
	}
	if _, ok := (Signed{}).Artifact(""); ok {
		t.Fatal("empty signed")
	}
	st, err := m.Get(a.ListID, a.Index)
	if err != nil || st.Value != 1 || !st.Changed || st.Purpose != Revocation {
		t.Fatalf("get: %+v %v", st, err)
	}
	rec, err := m.Record(a.ListID)
	if err != nil || rec.AllocatedCount != 4 {
		t.Fatalf("record: %+v %v", rec, err)
	}
	if _, _, gotErr := m.Set(ctx, "nope", 0, 1); !errors.Is(gotErr, ErrNotFound) {
		t.Fatal(gotErr)
	}
	if _, _, gotErr := m.Set(ctx, a.ListID, 9, 1); !errors.Is(gotErr, ErrNotAllocated) {
		t.Fatal(gotErr)
	}
	if _, gotErr := m.Get("nope", 0); !errors.Is(gotErr, ErrNotFound) {
		t.Fatal(gotErr)
	}
	if _, gotErr := m.Get(a.ListID, 99); gotErr == nil {
		t.Fatal("expected range error")
	}
	if _, gotErr := m.Record("nope"); !errors.Is(gotErr, ErrNotFound) {
		t.Fatal(gotErr)
	}
	if _, gotErr := m.Allocate(ctx, "", "other", 1); !errors.Is(gotErr, ErrBadPurpose) {
		t.Fatal(gotErr)
	}
	if _, gotErr := m.Allocate(ctx, "did:web:none", Revocation, 1); !errors.Is(gotErr, keys.ErrUnknownIssuer) {
		t.Fatal(gotErr)
	}
	if _, gotErr := m.Allocate(ctx, "", Revocation, 3); gotErr == nil {
		t.Fatal("expected bits error")
	}

	// Signed returns the stored copy without a new signature.
	calls := sec.calls
	_, got, err := m.Signed(ctx, a.ListID)
	if err != nil || !bytes.Equal(got.Artifacts[0].Body, signed.Artifacts[0].Body) || sec.calls != calls {
		t.Fatalf("signed: %v calls %d", err, sec.calls)
	}
	if _, _, gotErr := m.Signed(ctx, "nope"); !errors.Is(gotErr, ErrNotFound) {
		t.Fatal(gotErr)
	}

	// Pages.
	p, err := m.List("", 2, "")
	if err != nil || len(p.Entries) != 2 || p.Total != 4 || p.NextToken != "2" {
		t.Fatalf("page = %+v %v", p, err)
	}
	p2, err := m.List("", 2, p.NextToken)
	if err != nil || len(p2.Entries) != 2 || p2.NextToken != "" {
		t.Fatalf("page 2 = %+v %v", p2, err)
	}
	if p2.Entries[0].Signed.ListID != p2.Entries[0].Record.ID {
		t.Fatal("entry signed")
	}
	p3, err := m.List(Suspension, 10, "")
	if err != nil {
		t.Fatalf("m.List: %v", err)
	}
	if len(p3.Entries) != 2 || p3.Total != 2 {
		t.Fatalf("filtered page = %+v", p3)
	}
	p4, err := m.List("", 10, "99")
	if err != nil {
		t.Fatalf("m.List: %v", err)
	}
	if len(p4.Entries) != 0 {
		t.Fatal("page past the end")
	}
	for _, bad := range []string{"x", "-1", "01"} {
		if _, gotErr := m.List("", 10, bad); gotErr == nil {
			t.Errorf("token %q: expected error", bad)
		}
	}
	if _, gotErr := m.List("", 0, ""); gotErr == nil {
		t.Fatal("expected page size error")
	}
	if !json.Valid(m.JWKS()) {
		t.Fatal("JWKS")
	}

	// A restart loads the same records and signatures.
	again := openManager(t, kv, &fakeSecurer{kind: KindToken}, 4)
	_, s2, err := again.Signed(ctx, a.ListID)
	if err != nil || !bytes.Equal(s2.Artifacts[0].Body, signed.Artifacts[0].Body) {
		t.Fatal("restart lost the signature")
	}
	st2, err := again.Get(a.ListID, a.Index)
	if err != nil {
		t.Fatalf("again.Get: %v", err)
	}
	if st2.Value != 1 || !st2.ChangedAt.Equal(t0) {
		t.Fatal("restart lost the value")
	}
	if _, err := Open(ctx, Options{Store: kv, Issuers: newIssuers(t, kv), Securer: &fakeSecurer{kind: KindBitstring}}); err == nil {
		t.Fatal("expected kind mismatch")
	}
}

func TestManagerExpiryAndRotation(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	sec := &fakeSecurer{kind: KindBitstring}
	now := t0
	is := newIssuers(t, kv)
	m, err := Open(ctx, Options{Store: kv, Issuers: is, Securer: sec, BaseURL: "https://s.example", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Allocate(ctx, "", Revocation, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Record(a.ListID)
	if err != nil {
		t.Fatalf("m.Record: %v", err)
	}
	if rec.Size != bitstring.MinSize {
		t.Fatal("bitstring size")
	}
	_, s1, err := m.Signed(ctx, a.ListID)
	if err != nil {
		t.Fatalf("m.Signed: %v", err)
	}
	if !s1.ExpiresAt.Equal(t0.Add(DefaultTTL)) {
		t.Fatalf("default TTL: %v", s1.ExpiresAt)
	}
	now = t0.Add(DefaultTTL)
	_, s2, err := m.Signed(ctx, a.ListID)
	if err != nil || !s2.SignedAt.Equal(now) || sec.calls != 2 {
		t.Fatalf("expired list must be signed again: %v calls %d", err, sec.calls)
	}
	oldDID := s2.IssuerDID
	rot, err := m.Rotate(ctx, "", jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if rot.ListsSigned != 1 || rot.KeyID == rot.PreviousKeyID || !strings.HasSuffix(rot.KeyID, "#0") {
		t.Fatalf("rotation = %+v", rot)
	}
	_, s3, err := m.Signed(ctx, a.ListID)
	if err != nil {
		t.Fatalf("m.Signed: %v", err)
	}
	if s3.KeyID != rot.KeyID || s3.IssuerDID == oldDID {
		t.Fatalf("list not signed with the new key: %+v", s3)
	}
	if !is.Default().Matches(oldDID) {
		t.Fatal("old did:jwk must still resolve")
	}
	if _, err := m.Rotate(ctx, "did:web:none", ""); !errors.Is(err, keys.ErrUnknownIssuer) {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(m.JWKS(), &set); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys", len(set.Keys))
	}
}

func TestManagerErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, Options{}); err == nil {
		t.Fatal("expected options error")
	}
	kv := store.Memory()
	is := newIssuers(t, kv)
	failSec := &fakeSecurer{kind: KindToken, fail: errors.New("hsm down")}
	m, mErr := Open(ctx, Options{Store: kv, Issuers: is, Securer: failSec, Size: 4})
	if mErr != nil {
		t.Fatalf("Open: %v", mErr)
	}
	if _, err := m.Allocate(ctx, "", Revocation, 1); err == nil || !strings.Contains(err.Error(), "hsm down") {
		t.Fatalf("err = %v", err)
	}
	empty := &emptySecurer{fakeSecurer{kind: KindToken}}
	m, errAssign := Open(ctx, Options{Store: kv, Issuers: is, Securer: empty, Size: 4})
	if errAssign != nil {
		t.Fatalf("Open: %v", errAssign)
	}
	if _, err := m.Allocate(ctx, "", Revocation, 1); err == nil || !strings.Contains(err.Error(), "no artifact") {
		t.Fatalf("err = %v", err)
	}
	// A working manager whose store then fails.
	sec := &fakeSecurer{kind: KindToken}
	fs := &flaky{KeyValue: kv, failAfter: -1}
	m, errAssign2 := Open(ctx, Options{Store: fs, Issuers: is, Securer: sec, Size: 4, Rand: bytes.NewReader(nil)})
	if errAssign2 != nil {
		t.Fatalf("Open: %v", errAssign2)
	}
	if _, err := m.Allocate(ctx, "", Revocation, 1); err == nil || !strings.Contains(err.Error(), "random id") {
		t.Fatalf("err = %v", err)
	}
	m, errAssign3 := Open(ctx, Options{Store: fs, Issuers: is, Securer: sec, Size: 4, Now: func() time.Time { return t0 }})
	if errAssign3 != nil {
		t.Fatalf("Open: %v", errAssign3)
	}
	a, aErr := m.Allocate(ctx, "", Revocation, 1)
	if aErr != nil {
		t.Fatal(aErr)
	}
	fs.failAfter = 0
	if _, err := m.Allocate(ctx, "", Revocation, 1); err == nil {
		t.Fatal("expected record save error")
	}
	if _, _, err := m.Set(ctx, a.ListID, a.Index, 1); err == nil {
		t.Fatal("expected signed save error")
	}
	if _, err := m.Rotate(ctx, "", ""); err == nil {
		t.Fatal("expected rotate save error")
	}
	fs.failAfter = 1
	if _, err := m.Allocate(ctx, "", Suspension, 1); err == nil {
		t.Fatal("expected save error after the signature")
	}
	fs.failAfter = -1
	// The issuer of a stored list is no longer configured.
	fs.failAfter = -1
	rec, recErr := m.Record(a.ListID)
	if recErr != nil {
		t.Fatalf("m.Record: %v", recErr)
	}
	rec.IssuerSlug = "gone"
	data, dataErr := json.Marshal(rec)
	if dataErr != nil {
		t.Fatalf("json.Marshal: %v", dataErr)
	}
	if err := kv.Put(ctx, RecordPrefix+rec.ID, data); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	m2, err := Open(ctx, Options{Store: kv, Issuers: is, Securer: sec, Size: 4, Now: func() time.Time { return t0.Add(48 * time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m2.Set(ctx, a.ListID, a.Index, 1); !errors.Is(err, keys.ErrUnknownIssuer) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := m2.Signed(ctx, a.ListID); !errors.Is(err, keys.ErrUnknownIssuer) {
		t.Fatalf("err = %v", err)
	}
	// Broken documents in the store.
	if err := kv.Put(ctx, RecordPrefix+"bad", []byte("{")); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, Options{Store: kv, Issuers: is, Securer: sec}); err == nil {
		t.Fatal("expected parse error")
	}
	if err := kv.Delete(ctx, RecordPrefix+"bad"); err != nil {
		t.Fatalf("kv.Delete: %v", err)
	}
	if err := kv.Put(ctx, SignedPrefix+"bad", []byte("{")); err != nil {
		t.Fatalf("kv.Put: %v", err)
	}
	if _, err := Open(ctx, Options{Store: kv, Issuers: is, Securer: sec}); err == nil {
		t.Fatal("expected parse error")
	}
	if err := kv.Delete(ctx, SignedPrefix+"bad"); err != nil {
		t.Fatalf("kv.Delete: %v", err)
	}
	if _, err := Open(ctx, Options{Store: &flaky{KeyValue: kv, listErr: true}, Issuers: is, Securer: sec}); err == nil {
		t.Fatal("expected list error")
	}
	if _, err := Open(ctx, Options{Store: &flaky{KeyValue: kv, getErr: true}, Issuers: is, Securer: sec}); err == nil {
		t.Fatal("expected get error")
	}
	if _, err := randomHex(4); err != nil {
		t.Fatal(err)
	}
}

// flaky is a store that fails writes after failAfter more successes.
// A negative failAfter never fails.
type flaky struct {
	store.KeyValue
	failAfter int
	listErr   bool
	getErr    bool
}

func (f *flaky) Put(ctx context.Context, key string, value []byte) error {
	if f.failAfter == 0 {
		return fmt.Errorf("disk full")
	}
	if f.failAfter > 0 {
		f.failAfter--
	}
	return f.KeyValue.Put(ctx, key, value)
}

func (f *flaky) List(ctx context.Context, prefix string) ([]string, error) {
	if f.listErr {
		return nil, errors.New("list failed")
	}
	return f.KeyValue.List(ctx, prefix)
}

func (f *flaky) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr {
		return nil, errors.New("get failed")
	}
	return f.KeyValue.Get(ctx, key)
}
