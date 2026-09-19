// SPDX-License-Identifier: Apache-2.0

package combos

import (
	"context"
	"errors"
	"strings"
	"testing"

	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

func newStore() *Store { return New(store.Memory(), nil) }

func TestCreateAndGet(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	got, err := s.Create(ctx, &combinedv1.CombinedTemplate{DisplayName: "Guardian pair", TenantId: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.GetId(), "guardian-pair-") {
		t.Fatalf("unexpected id: %q", got.GetId())
	}
	read, err := s.Get(ctx, got.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if read.GetDisplayName() != "Guardian pair" {
		t.Fatalf("unexpected template: %+v", read)
	}
}

func TestCreateProblems(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if _, err := s.Create(ctx, &combinedv1.CombinedTemplate{Id: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, &combinedv1.CombinedTemplate{Id: "one"}); err == nil {
		t.Fatal("want an error for a template that exists")
	}
	if _, err := s.Create(ctx, &combinedv1.CombinedTemplate{Id: "bad id"}); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestListAndDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	for _, id := range []string{"alpha", "beta"} {
		if _, err := s.Create(ctx, &combinedv1.CombinedTemplate{Id: id, TenantId: id}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].GetId() != "alpha" {
		t.Fatalf("unexpected list: %+v", all)
	}
	one, err := s.List(ctx, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 {
		t.Fatalf("unexpected tenant list: %+v", one)
	}
	if err := s.Delete(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if err := s.Delete(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := s.Get(ctx, "bad id"); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestBrokenDocument(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, Prefix+"one", []byte("{oops")); err != nil {
		t.Fatal(err)
	}
	s := New(kv, nil)
	if _, err := s.Get(ctx, "one"); err == nil {
		t.Fatal("want a decode error")
	}
	if _, err := s.List(ctx, ""); err == nil {
		t.Fatal("want a decode error from the list")
	}
}

// brokenKV fails every read and write.
type brokenKV struct{ store.KeyValue }

var errBroken = errors.New("broken")

func (brokenKV) Get(context.Context, string) ([]byte, error)    { return nil, errBroken }
func (brokenKV) Put(context.Context, string, []byte) error      { return errBroken }
func (brokenKV) List(context.Context, string) ([]string, error) { return nil, errBroken }

func TestBackendErrors(t *testing.T) {
	ctx := context.Background()
	s := New(brokenKV{store.Memory()}, nil)
	if _, err := s.Create(ctx, &combinedv1.CombinedTemplate{Id: "one"}); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if _, err := s.List(ctx, ""); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if err := s.Delete(ctx, "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
}

// deleteKV reads fine and fails the delete.
type deleteKV struct{ store.KeyValue }

func (deleteKV) Delete(context.Context, string) error { return errBroken }

func TestDeleteError(t *testing.T) {
	ctx := context.Background()
	mem := store.Memory()
	if _, err := New(mem, nil).Create(ctx, &combinedv1.CombinedTemplate{Id: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := New(deleteKV{mem}, nil).Delete(ctx, "one"); !errors.Is(err, errBroken) {
		t.Fatalf("want the delete error, got %v", err)
	}
}

func TestDefaultIDShapes(t *testing.T) {
	if got := defaultID(""); !strings.HasPrefix(got, "combined-") {
		t.Fatalf("want a generated id, got %q", got)
	}
	if got := defaultID(strings.Repeat("name ", 20)); !idRE.MatchString(got) {
		t.Fatalf("want a safe id, got %q", got)
	}
}
