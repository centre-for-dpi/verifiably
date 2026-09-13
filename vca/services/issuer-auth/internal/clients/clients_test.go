// SPDX-License-Identifier: Apache-2.0

package clients_test

import (
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
)

type failStore struct {
	oidcflow.Persister
	fail bool
}

func (f *failStore) Save(name string, v any) error {
	if f.fail {
		return errors.New("fail")
	}
	return f.Persister.Save(name, v)
}

func (f *failStore) Load(name string, v any) error {
	if f.fail {
		return errors.New("fail")
	}
	return f.Persister.Load(name, v)
}

func TestRegistry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := &failStore{Persister: oidcflow.NewMemoryPersister()}
	reg, err := clients.New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Create("", "t", []string{"issuer-admin"}, nil); !errors.Is(err, clients.ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err := reg.Create("x", "t", nil, nil); !errors.Is(err, clients.ErrInvalid) {
		t.Fatal(err)
	}
	c, secret, err := reg.Create("robot", "t1", []string{"issuer-operator"}, nil)
	if err != nil || c.ID == "" || secret == "" || c.Prefix != secret[:8] || c.SecretHash == secret {
		t.Fatalf("create: %+v %q %v", c, secret, err)
	}
	got, err := reg.Authenticate(c.ID, secret)
	if err != nil || got.ID != c.ID || got.Roles[0] != "issuer-operator" {
		t.Fatalf("auth: %v", err)
	}
	if _, err := reg.Authenticate(c.ID, "wrong"); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatal("wrong secret")
	}
	if _, err := reg.Authenticate("nobody", secret); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatal("unknown id")
	}
	exp := now.Add(time.Hour)
	c2, s2, _ := reg.Create("temp", "t2", []string{"issuer-viewer"}, &exp)
	if len(reg.List("")) != 2 || len(reg.List("t2")) != 1 || reg.List("t2")[0].ID != c2.ID {
		t.Fatal("list")
	}
	now = now.Add(2 * time.Hour)
	if _, err := reg.Authenticate(c2.ID, s2); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatal("expired client accepted")
	}
	if err := reg.Revoke(c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Authenticate(c.ID, secret); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatal("revoked client accepted")
	}
	if err := reg.Revoke("nobody"); !errors.Is(err, clients.ErrNotFound) {
		t.Fatal(err)
	}
	// Persisted.
	reg2, _ := clients.New(store, clock)
	if len(reg2.List("")) != 2 || reg2.List("t1")[0].RevokedAt == nil {
		t.Fatal("not persisted")
	}
	// Save failures roll back.
	store.fail = true
	if _, _, err := reg.Create("y", "t", []string{"issuer-admin"}, nil); err == nil {
		t.Fatal("save error hidden")
	}
	if len(reg.List("")) != 2 {
		t.Fatal("create not rolled back")
	}
	if err := reg.Revoke(c2.ID); err == nil {
		t.Fatal("save error hidden")
	}
	if reg.List("t2")[0].RevokedAt != nil {
		t.Fatal("revoke not rolled back")
	}
	if _, err := clients.New(store, nil); err == nil {
		t.Fatal("load error hidden")
	}
	store.fail = false
	if _, err := clients.New(store, nil); err != nil {
		t.Fatal(err)
	}
}
