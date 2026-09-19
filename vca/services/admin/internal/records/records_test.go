// SPDX-License-Identifier: Apache-2.0

package records_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var at = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// newStore returns a store over memory with a fixed clock.
func newStore(t *testing.T) *records.Store {
	t.Helper()
	s, err := records.New(store.Memory(), func() time.Time { return at })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestNewNeedsAStore(t *testing.T) {
	if _, err := records.New(nil, nil); err == nil {
		t.Fatal("New accepted a nil store")
	}
	if _, err := records.New(store.Memory(), nil); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestTenantLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenant, err := s.CreateTenant(ctx, "  Ministry of Health  ")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if tenant.DisplayName != "Ministry of Health" || tenant.State != records.StateActive {
		t.Fatalf("tenant = %+v", tenant)
	}
	got, err := s.GetTenant(ctx, tenant.ID)
	if err != nil || got.ID != tenant.ID {
		t.Fatalf("GetTenant = %+v, %v", got, err)
	}
	updated, err := s.UpdateTenant(ctx, tenant.ID, "Health", records.StateSuspended)
	if err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}
	if updated.DisplayName != "Health" || updated.State != records.StateSuspended {
		t.Fatalf("updated = %+v", updated)
	}
	same, err := s.UpdateTenant(ctx, tenant.ID, "", "")
	if err != nil || same.DisplayName != "Health" || same.State != records.StateSuspended {
		t.Fatalf("empty update changed the record: %+v, %v", same, err)
	}
	if err := s.DeleteTenant(ctx, tenant.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := s.GetTenant(ctx, tenant.ID); !errors.Is(err, records.ErrNotFound) {
		t.Fatalf("GetTenant after delete: %v", err)
	}
}

func TestTenantValidation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, err := s.CreateTenant(ctx, "   "); !errors.Is(err, records.ErrInvalid) {
		t.Errorf("empty name: %v", err)
	}
	if _, err := s.CreateTenant(ctx, strings.Repeat("x", records.MaxDisplayName+1)); !errors.Is(err, records.ErrInvalid) {
		t.Errorf("long name: %v", err)
	}
	tenant, _ := s.CreateTenant(ctx, "Tenant")
	if _, err := s.UpdateTenant(ctx, tenant.ID, "", "gone"); !errors.Is(err, records.ErrInvalid) {
		t.Errorf("bad state: %v", err)
	}
	if _, err := s.UpdateTenant(ctx, tenant.ID, "   ", ""); !errors.Is(err, records.ErrInvalid) {
		t.Errorf("blank name: %v", err)
	}
	if _, err := s.UpdateTenant(ctx, "missing", "x", ""); !errors.Is(err, records.ErrNotFound) {
		t.Errorf("missing tenant: %v", err)
	}
	if err := s.DeleteTenant(ctx, "missing"); !errors.Is(err, records.ErrNotFound) {
		t.Errorf("delete missing: %v", err)
	}
}

func TestListTenantsSortsByCreationTime(t *testing.T) {
	ctx := context.Background()
	now := at
	s, err := records.New(store.Memory(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, _ := s.CreateTenant(ctx, "First")
	now = at.Add(time.Minute)
	second, _ := s.CreateTenant(ctx, "Second")
	list, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(list) != 2 || list[0].ID != first.ID || list[1].ID != second.ID {
		t.Fatalf("list = %+v", list)
	}
}

func TestListTenantsSortsEqualTimesByID(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	a, _ := s.CreateTenant(ctx, "A")
	b, _ := s.CreateTenant(ctx, "B")
	want := a.ID
	if b.ID < a.ID {
		want = b.ID
	}
	list, _ := s.ListTenants(ctx)
	if list[0].ID != want {
		t.Fatalf("first = %q, want %q", list[0].ID, want)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenant, _ := s.CreateTenant(ctx, "Tenant")
	key, secret, err := s.CreateKey(ctx, records.KeySpec{DisplayName: "CI", TenantID: tenant.ID, Roles: []string{"issuer"}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if !strings.HasPrefix(secret, records.SecretPrefix) {
		t.Errorf("secret = %q", secret)
	}
	if key.Prefix != secret[:8] || key.Hash != records.Hash(secret) {
		t.Errorf("key = %+v", key)
	}
	if !key.Active(at) {
		t.Error("new key is not active")
	}
	found, err := s.Authenticate(ctx, secret)
	if err != nil || found.ID != key.ID {
		t.Fatalf("Authenticate = %+v, %v", found, err)
	}
	revoked, err := s.RevokeKey(ctx, key.ID)
	if err != nil || revoked.RevokedAt.IsZero() {
		t.Fatalf("RevokeKey = %+v, %v", revoked, err)
	}
	again, err := s.RevokeKey(ctx, key.ID)
	if err != nil || !again.RevokedAt.Equal(revoked.RevokedAt) {
		t.Fatalf("second revoke changed the time: %+v", again)
	}
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, records.ErrNotFound) {
		t.Fatalf("revoked key still works: %v", err)
	}
}

func TestAPIKeyExpiry(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenant, _ := s.CreateTenant(ctx, "Tenant")
	_, secret, err := s.CreateKey(ctx, records.KeySpec{
		DisplayName: "Short", TenantID: tenant.ID, Roles: []string{"admin"}, ExpiresAt: at.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, records.ErrNotFound) {
		t.Fatalf("expired key works: %v", err)
	}
}

func TestAuthenticateRejectsUnknownSecrets(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, secret := range []string{"", "not-a-key", records.SecretPrefix + "unknown"} {
		if _, err := s.Authenticate(ctx, secret); !errors.Is(err, records.ErrNotFound) {
			t.Errorf("Authenticate(%q) = %v", secret, err)
		}
	}
}

func TestCreateKeyValidation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenant, _ := s.CreateTenant(ctx, "Tenant")
	cases := map[string]records.KeySpec{
		"no name":   {TenantID: tenant.ID, Roles: []string{"admin"}},
		"no tenant": {DisplayName: "k", Roles: []string{"admin"}},
		"no roles":  {DisplayName: "k", TenantID: tenant.ID},
	}
	for name, spec := range cases {
		if _, _, err := s.CreateKey(ctx, spec); !errors.Is(err, records.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := s.CreateKey(ctx, records.KeySpec{DisplayName: "k", TenantID: "missing", Roles: []string{"admin"}}); !errors.Is(err, records.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	if _, err := s.RevokeKey(ctx, "missing"); !errors.Is(err, records.ErrNotFound) {
		t.Errorf("revoke missing: %v", err)
	}
}

func TestListKeysFiltersByTenantAndDeleteRemovesThem(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	one, _ := s.CreateTenant(ctx, "One")
	two, _ := s.CreateTenant(ctx, "Two")
	_, secret, _ := s.CreateKey(ctx, records.KeySpec{DisplayName: "a", TenantID: one.ID, Roles: []string{"admin"}})
	if _, _, err := s.CreateKey(ctx, records.KeySpec{DisplayName: "b", TenantID: two.ID, Roles: []string{"admin"}}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	all, _ := s.ListKeys(ctx, "")
	if len(all) != 2 {
		t.Fatalf("all keys = %d", len(all))
	}
	mine, _ := s.ListKeys(ctx, one.ID)
	if len(mine) != 1 || mine[0].TenantID != one.ID {
		t.Fatalf("filtered keys = %+v", mine)
	}
	if err := s.DeleteTenant(ctx, one.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	left, _ := s.ListKeys(ctx, "")
	if len(left) != 1 || left[0].TenantID != two.ID {
		t.Fatalf("keys after delete = %+v", left)
	}
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, records.ErrNotFound) {
		t.Fatalf("key of the deleted tenant works: %v", err)
	}
}

func TestAdminBinding(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if n, err := s.CountAdmins(ctx); err != nil || n != 0 {
		t.Fatalf("CountAdmins = %d, %v", n, err)
	}
	if s.IsAdmin(ctx, "https://idp.example", "user-1") {
		t.Fatal("IsAdmin is true before a binding")
	}
	admin, err := s.BindAdmin(ctx, "https://idp.example/", "user-1")
	if err != nil || admin.BoundAt.IsZero() {
		t.Fatalf("BindAdmin = %+v, %v", admin, err)
	}
	if !s.IsAdmin(ctx, "https://idp.example/", "user-1") {
		t.Fatal("IsAdmin is false after a binding")
	}
	if _, err := s.BindAdmin(ctx, "", "user"); !errors.Is(err, records.ErrInvalid) {
		t.Errorf("empty issuer: %v", err)
	}
	if _, err := s.BindAdmin(ctx, "https://idp.example", " "); !errors.Is(err, records.ErrInvalid) {
		t.Errorf("empty subject: %v", err)
	}
	if _, err := s.BindAdmin(ctx, "https://idp.example", "user-2"); err != nil {
		t.Fatalf("BindAdmin: %v", err)
	}
	list, err := s.ListAdmins(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListAdmins = %+v, %v", list, err)
	}
	if list[0].Subject > list[1].Subject {
		t.Errorf("admins are not sorted: %+v", list)
	}
	if n, _ := s.CountAdmins(ctx); n != 2 {
		t.Errorf("CountAdmins = %d", n)
	}
}

func TestAdminKeyIgnoresATrailingSlash(t *testing.T) {
	if records.AdminKey("https://idp.example/", "s") != records.AdminKey("https://idp.example", "s") {
		t.Fatal("AdminKey depends on the trailing slash")
	}
}

func TestBootstrapTokenIsUsedOnce(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	token := records.NewBootstrapToken()
	if s.BootstrapPending(ctx) {
		t.Fatal("pending before SetBootstrap")
	}
	if err := s.ConsumeBootstrap(ctx, token); !errors.Is(err, records.ErrBootstrapToken) {
		t.Fatalf("consume without a token: %v", err)
	}
	if err := s.SetBootstrap(ctx, "short"); !errors.Is(err, records.ErrInvalid) {
		t.Fatalf("short token: %v", err)
	}
	if err := s.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	if !s.BootstrapPending(ctx) {
		t.Fatal("not pending after SetBootstrap")
	}
	if err := s.ConsumeBootstrap(ctx, "wrong-token-value-1234"); !errors.Is(err, records.ErrBootstrapToken) {
		t.Fatalf("wrong token: %v", err)
	}
	if err := s.ConsumeBootstrap(ctx, token); err != nil {
		t.Fatalf("ConsumeBootstrap: %v", err)
	}
	if s.BootstrapPending(ctx) {
		t.Fatal("still pending after the login")
	}
	if err := s.ConsumeBootstrap(ctx, token); !errors.Is(err, records.ErrBootstrapUsed) {
		t.Fatalf("second use: %v", err)
	}
	// A restart calls SetBootstrap again with the same value.
	if err := s.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap after use: %v", err)
	}
	if s.BootstrapPending(ctx) {
		t.Fatal("the spent token became pending again")
	}
	if err := s.SetBootstrap(ctx, records.NewBootstrapToken()); err != nil {
		t.Fatalf("SetBootstrap with a new token: %v", err)
	}
	if !s.BootstrapPending(ctx) {
		t.Fatal("a new token is not pending")
	}
}

func TestNewSecretAndIDAreRandom(t *testing.T) {
	if records.NewSecret() == records.NewSecret() || records.NewID() == records.NewID() {
		t.Fatal("two random values are equal")
	}
}

// failStore fails every operation the test names.
type failStore struct {
	store.KeyValue
	failPut  bool
	failList bool
	failDel  bool
	bad      string
}

func (f failStore) Put(ctx context.Context, key string, value []byte) error {
	if f.failPut {
		return errors.New("put failed")
	}
	return f.KeyValue.Put(ctx, key, value)
}

func (f failStore) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failList {
		return nil, errors.New("list failed")
	}
	return f.KeyValue.List(ctx, prefix)
}

func (f failStore) Delete(ctx context.Context, key string) error {
	if f.failDel {
		return errors.New("delete failed")
	}
	return f.KeyValue.Delete(ctx, key)
}

func TestStoreErrorsTravelToTheCaller(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	s, _ := records.New(failStore{KeyValue: kv, failPut: true}, nil)
	if _, err := s.CreateTenant(ctx, "Tenant"); err == nil {
		t.Error("CreateTenant hid a store error")
	}
	if _, err := s.BindAdmin(ctx, "https://idp.example", "s"); err == nil {
		t.Error("BindAdmin hid a store error")
	}
	if err := s.SetBootstrap(ctx, records.NewBootstrapToken()); err == nil {
		t.Error("SetBootstrap hid a store error")
	}
	listFail, _ := records.New(failStore{KeyValue: kv, failList: true}, nil)
	if _, err := listFail.ListTenants(ctx); err == nil {
		t.Error("ListTenants hid a store error")
	}
	if _, err := listFail.ListKeys(ctx, ""); err == nil {
		t.Error("ListKeys hid a store error")
	}
	if _, err := listFail.CountAdmins(ctx); err == nil {
		t.Error("CountAdmins hid a store error")
	}
	if _, err := listFail.ListAdmins(ctx); err == nil {
		t.Error("ListAdmins hid a store error")
	}
	good, _ := records.New(kv, nil)
	tenant, _ := good.CreateTenant(ctx, "Tenant")
	if _, _, err := good.CreateKey(ctx, records.KeySpec{DisplayName: "k", TenantID: tenant.ID, Roles: []string{"admin"}}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	delFail, _ := records.New(failStore{KeyValue: kv, failDel: true}, nil)
	if err := delFail.DeleteTenant(ctx, tenant.ID); err == nil {
		t.Error("DeleteTenant hid a store error")
	}
}

func TestBrokenDocumentsAreReported(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, "tenants/broken", []byte("{")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s, _ := records.New(kv, nil)
	if _, err := s.GetTenant(ctx, "broken"); err == nil {
		t.Error("GetTenant read a broken document")
	}
	if _, err := s.ListTenants(ctx); err == nil {
		t.Error("ListTenants read a broken document")
	}
	if err := kv.Put(ctx, "apikeys/broken", []byte("{")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.ListKeys(ctx, ""); err == nil {
		t.Error("ListKeys read a broken document")
	}
	if err := kv.Put(ctx, "admins/broken", []byte("{")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.ListAdmins(ctx); err == nil {
		t.Error("ListAdmins read a broken document")
	}
}

func TestGetTenantReportsAStoreFault(t *testing.T) {
	ctx := context.Background()
	s, _ := records.New(store.Memory(), nil)
	if _, err := s.GetTenant(ctx, "bad key"); err == nil {
		t.Fatal("GetTenant accepted a bad key")
	}
}
