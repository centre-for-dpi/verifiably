// SPDX-License-Identifier: Apache-2.0

package sets

import (
	"context"
	"errors"
	"strings"
	"testing"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

func newStore() *Store { return New(store.Memory(), nil) }

func TestCreateAndGet(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	created, err := s.Create(ctx, &policyv1.PolicySet{DisplayName: "Age check", TenantId: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetVersion() != 1 || !strings.HasPrefix(created.GetId(), "age-check-") {
		t.Fatalf("unexpected set: %+v", created)
	}
	got, err := s.Get(ctx, created.GetId(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetDisplayName() != "Age check" {
		t.Fatalf("unexpected set: %+v", got)
	}
}

func TestCreateWithID(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if _, err := s.Create(ctx, &policyv1.PolicySet{Id: "default"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, &policyv1.PolicySet{Id: "default"}); !errors.Is(err, ErrExists) {
		t.Fatalf("want an exists error for a set that exists, got %v", err)
	}
	if _, err := s.Create(ctx, &policyv1.PolicySet{Id: "no spaces"}); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestUpdateMakesNewVersion(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	created, err := s.Create(ctx, &policyv1.PolicySet{Id: "default", DisplayName: "One"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Update(ctx, &policyv1.PolicySet{Id: created.GetId(), DisplayName: "Two"})
	if err != nil {
		t.Fatal(err)
	}
	if next.GetVersion() != 2 {
		t.Fatalf("want version 2, got %d", next.GetVersion())
	}
	old, err := s.Get(ctx, "default", 1)
	if err != nil {
		t.Fatal(err)
	}
	if old.GetDisplayName() != "One" {
		t.Fatal("want the old version to stay readable")
	}
	latest, err := s.Get(ctx, "default", 0)
	if err != nil {
		t.Fatal(err)
	}
	if latest.GetVersion() != 2 {
		t.Fatalf("want the latest version, got %d", latest.GetVersion())
	}
	if _, err := s.Update(ctx, &policyv1.PolicySet{Id: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestListAndDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	for _, id := range []string{"alpha", "beta"} {
		if _, err := s.Create(ctx, &policyv1.PolicySet{Id: id, TenantId: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Update(ctx, &policyv1.PolicySet{Id: "alpha", TenantId: "alpha"}); err != nil {
		t.Fatal(err)
	}
	all, err := s.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].GetId() != "alpha" || all[0].GetVersion() != 2 {
		t.Fatalf("unexpected list: %+v", all)
	}
	one, err := s.List(ctx, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].GetId() != "beta" {
		t.Fatalf("unexpected tenant list: %+v", one)
	}
	if err := s.Delete(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "alpha", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if err := s.Delete(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if err := s.Delete(ctx, "bad id"); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestGetProblems(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if _, err := s.Get(ctx, "bad id", 0); !errors.Is(err, ErrBadID) {
		t.Fatalf("want a bad id error, got %v", err)
	}
	if _, err := s.Get(ctx, "missing", 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestBrokenDocument(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, key("default", 1), []byte("{oops")); err != nil {
		t.Fatal(err)
	}
	s := New(kv, nil)
	if _, err := s.Get(ctx, "default", 1); err == nil {
		t.Fatal("want a decode error")
	}
	if _, err := s.List(ctx, ""); err == nil {
		t.Fatal("want a decode error from the list")
	}
}

func TestDefaultIDShapes(t *testing.T) {
	if got := defaultID(""); !strings.HasPrefix(got, "set-") {
		t.Fatalf("want a generated id, got %q", got)
	}
	long := defaultID(strings.Repeat("name ", 20))
	if !idRE.MatchString(long) {
		t.Fatalf("want a safe id, got %q", long)
	}
}

func TestSetIDOfKey(t *testing.T) {
	if got := setID("policyset/default/000001"); got != "default" {
		t.Fatalf("want default, got %q", got)
	}
	if got := setID("other"); got != "" {
		t.Fatalf("want no id, got %q", got)
	}
}

// brokenKV fails every read and write.
type brokenKV struct{ store.KeyValue }

var errBroken = errors.New("broken")

func (brokenKV) Get(context.Context, string) ([]byte, error) { return nil, errBroken }
func (brokenKV) List(context.Context, string) ([]string, error) {
	return nil, errBroken
}

// deleteKV lists one key and fails the delete.
type deleteKV struct{ store.KeyValue }

func (deleteKV) List(context.Context, string) ([]string, error) {
	return []string{key("default", 1)}, nil
}
func (deleteKV) Delete(context.Context, string) error { return errBroken }

func TestBackendErrors(t *testing.T) {
	ctx := context.Background()
	s := New(brokenKV{store.Memory()}, nil)
	if _, err := s.Get(ctx, "default", 0); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if _, err := s.Get(ctx, "default", 1); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if _, err := s.List(ctx, ""); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	if err := s.Delete(ctx, "default"); !errors.Is(err, errBroken) {
		t.Fatalf("want the backend error, got %v", err)
	}
	d := New(deleteKV{store.Memory()}, nil)
	if err := d.Delete(ctx, "default"); !errors.Is(err, errBroken) {
		t.Fatalf("want the delete error, got %v", err)
	}
}

func TestListSkipsKeysWithoutVersion(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, Prefix+"stray", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	got, err := New(kv, nil).List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want no sets, got %+v", got)
	}
}
