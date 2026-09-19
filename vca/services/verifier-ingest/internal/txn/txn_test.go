// SPDX-License-Identifier: Apache-2.0

package txn_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// clock is the fixed time of the tests.
var clock = time.Unix(1700000000, 0).UTC()

// open returns a store over a memory backend.
func open(t *testing.T) *txn.Store {
	t.Helper()
	s, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewStoreNeedsBackend(t *testing.T) {
	if _, err := txn.NewStore(nil); err == nil {
		t.Error("a nil backend wants an error")
	}
}

func TestNewIDAndValidID(t *testing.T) {
	id, err := txn.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if !txn.ValidID(id) {
		t.Errorf("a new id must be valid, got %q", id)
	}
	for _, bad := range []string{"", "a/b", "a b", strings.Repeat("a", 65)} {
		if txn.ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	record := txn.Transaction{
		ID: "abc", Nonce: "n1", StateParam: "s1", DCQL: "{}", ResponseMode: "direct_post",
		State: txn.StatePending, CreatedAt: clock, ExpiresAt: clock.Add(time.Minute),
	}
	if err := s.Put(ctx, record); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != "n1" || got.State != txn.StatePending {
		t.Errorf("transaction = %+v", got)
	}
	byState, err := s.FindByState(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if byState.ID != "abc" {
		t.Errorf("FindByState = %+v", byState)
	}
	if _, err := s.FindByState(ctx, ""); !errors.Is(err, txn.ErrNotFound) {
		t.Errorf("an empty state wants ErrNotFound, got %v", err)
	}
	if _, err := s.FindByState(ctx, "other"); !errors.Is(err, txn.ErrNotFound) {
		t.Errorf("an unknown state wants ErrNotFound, got %v", err)
	}
	if _, err := s.Get(ctx, "missing"); !errors.Is(err, txn.ErrNotFound) {
		t.Errorf("a missing transaction wants ErrNotFound, got %v", err)
	}
	if _, err := s.Get(ctx, "a/b"); !errors.Is(err, txn.ErrNotFound) {
		t.Errorf("a bad id wants ErrNotFound, got %v", err)
	}
	if err := s.Put(ctx, txn.Transaction{ID: "a/b"}); err == nil {
		t.Error("a bad id wants an error")
	}
}

func TestExpiryAndState(t *testing.T) {
	record := txn.Transaction{State: txn.StatePending, ExpiresAt: clock}
	if !record.Expired(clock.Add(time.Second)) {
		t.Error("a pending request after the expiry is expired")
	}
	if record.StateAt(clock.Add(time.Second)) != txn.StateExpired {
		t.Error("the state of an old pending request is expired")
	}
	if record.StateAt(clock.Add(-time.Second)) != txn.StatePending {
		t.Error("a request before the expiry stays pending")
	}
	answered := txn.Transaction{State: txn.StateReceived, ExpiresAt: clock}
	if answered.Expired(clock.Add(time.Hour)) {
		t.Error("an answered request never expires")
	}
	open := txn.Transaction{State: txn.StatePending}
	if open.Expired(clock) {
		t.Error("a request without an expiry never expires")
	}
}

func TestProtoState(t *testing.T) {
	cases := map[txn.State]ingestv1.GetTransactionResponse_State{
		txn.StatePending:   ingestv1.GetTransactionResponse_STATE_PENDING,
		txn.StateReceived:  ingestv1.GetTransactionResponse_STATE_RECEIVED,
		txn.StateRefused:   ingestv1.GetTransactionResponse_STATE_REFUSED,
		txn.StateExpired:   ingestv1.GetTransactionResponse_STATE_EXPIRED,
		txn.State("other"): ingestv1.GetTransactionResponse_STATE_UNSPECIFIED,
	}
	for state, want := range cases {
		if got := txn.ProtoState(state); got != want {
			t.Errorf("ProtoState(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestListAndPrune(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	old := txn.Transaction{ID: "old", StateParam: "s-old", CreatedAt: clock.Add(-2 * time.Hour), State: txn.StateReceived}
	recent := txn.Transaction{ID: "recent", StateParam: "s-new", CreatedAt: clock, State: txn.StatePending}
	for _, record := range []txn.Transaction{recent, old} {
		if err := s.Put(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "old" {
		t.Errorf("the list is ordered by creation time, got %+v", list)
	}
	removed, err := s.Prune(ctx, clock.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed = %d", removed)
	}
	list, err = s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "recent" {
		t.Errorf("the recent transaction stays, got %+v", list)
	}
}

func TestBrokenDocument(t *testing.T) {
	ctx := context.Background()
	kv := shared.Memory()
	if err := kv.Put(ctx, txn.Prefix+"x", []byte("{")); err != nil {
		t.Fatal(err)
	}
	s, err := txn.NewStore(kv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "x"); err == nil {
		t.Error("a broken document wants an error")
	}
	if _, err := s.List(ctx); err == nil {
		t.Error("a broken document wants an error from the list too")
	}
}

// broken is a backend that fails every call.
type broken struct{ err error }

func (b broken) Get(context.Context, string) ([]byte, error)    { return nil, b.err }
func (b broken) Put(context.Context, string, []byte) error      { return b.err }
func (b broken) Delete(context.Context, string) error           { return b.err }
func (b broken) List(context.Context, string) ([]string, error) { return nil, b.err }
func (b broken) CompareAndSwap(context.Context, string, []byte, []byte) error {
	return b.err
}

func TestBackendErrors(t *testing.T) {
	ctx := context.Background()
	s, err := txn.NewStore(broken{err: errors.New("disk is full")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, txn.Transaction{ID: "x"}); err == nil {
		t.Error("Put wants the backend error")
	}
	if _, err := s.Get(ctx, "x"); err == nil {
		t.Error("Get wants the backend error")
	}
	if _, err := s.List(ctx); err == nil {
		t.Error("List wants the backend error")
	}
	if _, err := s.FindByState(ctx, "s"); err == nil {
		t.Error("FindByState wants the backend error")
	}
	if _, err := s.Prune(ctx, clock); err == nil {
		t.Error("Prune wants the backend error")
	}
}

// deleteFails lists and reads, but never deletes.
type deleteFails struct {
	shared.KeyValue
}

func (deleteFails) Delete(context.Context, string) error { return errors.New("delete failed") }

func TestPruneDeleteError(t *testing.T) {
	ctx := context.Background()
	kv := shared.Memory()
	s, err := txn.NewStore(kv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, txn.Transaction{ID: "old", CreatedAt: clock.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	failing, err := txn.NewStore(deleteFails{KeyValue: kv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Prune(ctx, clock); err == nil {
		t.Error("a delete error stops the prune")
	}
}
