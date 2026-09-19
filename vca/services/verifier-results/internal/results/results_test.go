// SPDX-License-Identifier: Apache-2.0

package results

import (
	"context"
	"errors"
	"testing"
	"time"

	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func newStore() *Store { return New(store.Memory(), nil) }

func TestPutAndGet(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	got, err := s.Put(ctx, &resultsv1.VerificationResult{Carrier: "oid4vp"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetId() == "" {
		t.Fatal("want a generated id")
	}
	read, err := s.Get(ctx, got.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if read.GetCarrier() != "oid4vp" {
		t.Fatalf("unexpected result: %+v", read)
	}
}

func TestPutBadID(t *testing.T) {
	if _, err := newStore().Put(context.Background(),
		&resultsv1.VerificationResult{Id: "bad id"}); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestRawLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if err := s.PutRaw(ctx, "abc", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	raw, err := s.GetRaw(ctx, "abc")
	if err != nil || string(raw) != "payload" {
		t.Fatalf("want the payload, got %q %v", raw, err)
	}
	if err := s.DeleteRaw(ctx, "abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRaw(ctx, "abc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	for _, err := range []error{
		s.PutRaw(ctx, "bad id", nil),
		s.DeleteRaw(ctx, "bad id"),
	} {
		if !errors.Is(err, ErrBadID) {
			t.Fatalf("want a bad id error, got %v", err)
		}
	}
	if _, err := s.GetRaw(ctx, "bad id"); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	stored, err := s.Put(ctx, &resultsv1.VerificationResult{Id: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRaw(ctx, stored.GetId(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if err := s.Delete(ctx, "bad id"); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
	if _, err := s.Get(ctx, "bad id"); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestAllIsNewestFirst(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	for i, id := range []string{"old", "new"} {
		if _, err := s.Put(ctx, &resultsv1.VerificationResult{
			Id: id, EvaluatedAt: timestamppb.New(testNow.Add(time.Duration(i) * time.Hour)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].GetId() != "new" {
		t.Fatalf("want the newest first, got %+v", all)
	}
}

func TestBrokenDocument(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, ResultPrefix+"one", []byte("{oops")); err != nil {
		t.Fatal(err)
	}
	s := New(kv, nil)
	if _, err := s.Get(ctx, "one"); err == nil {
		t.Fatal("want a decode error")
	}
	if _, err := s.All(ctx); err == nil {
		t.Fatal("want a decode error from the list")
	}
}

// brokenKV fails every operation.
type brokenKV struct{ store.KeyValue }

var errBroken = errors.New("broken")

func (brokenKV) Get(context.Context, string) ([]byte, error)    { return nil, errBroken }
func (brokenKV) Put(context.Context, string, []byte) error      { return errBroken }
func (brokenKV) Delete(context.Context, string) error           { return errBroken }
func (brokenKV) List(context.Context, string) ([]string, error) { return nil, errBroken }

func TestBackendErrors(t *testing.T) {
	ctx := context.Background()
	s := New(brokenKV{store.Memory()}, func() string { return "one" })
	if _, err := s.Put(ctx, &resultsv1.VerificationResult{}); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if err := s.PutRaw(ctx, "one", nil); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if _, err := s.GetRaw(ctx, "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if err := s.DeleteRaw(ctx, "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if err := s.Delete(ctx, "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if _, err := s.Get(ctx, "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if _, err := s.All(ctx); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
}

// deleteKV allows the raw delete and fails the result delete.
type deleteKV struct {
	store.KeyValue
	calls int
}

func (d *deleteKV) Delete(ctx context.Context, key string) error {
	d.calls++
	if d.calls == 1 {
		return nil
	}
	return errBroken
}

func TestDeleteResultError(t *testing.T) {
	s := New(&deleteKV{KeyValue: store.Memory()}, nil)
	if err := s.Delete(context.Background(), "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
}

func TestRandomID(t *testing.T) {
	if got := randomID(); !idRE.MatchString(got) {
		t.Fatalf("want a safe id, got %q", got)
	}
}
