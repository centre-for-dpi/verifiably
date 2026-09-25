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
	tenant, verr := s.CreateTenant(ctx, "Tenant")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	first, verr := s.CreateTenant(ctx, "First")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	now = at.Add(time.Minute)
	second, verr := s.CreateTenant(ctx, "Second")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	a, verr := s.CreateTenant(ctx, "A")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	b, verr := s.CreateTenant(ctx, "B")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	want := a.ID
	if b.ID < a.ID {
		want = b.ID
	}
	list, verr := s.ListTenants(ctx)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if list[0].ID != want {
		t.Fatalf("first = %q, want %q", list[0].ID, want)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenant, verr := s.CreateTenant(ctx, "Tenant")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	tenant, verr := s.CreateTenant(ctx, "Tenant")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	tenant, verr := s.CreateTenant(ctx, "Tenant")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	one, verr := s.CreateTenant(ctx, "One")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	two, verr := s.CreateTenant(ctx, "Two")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	_, secret, verr := s.CreateKey(ctx, records.KeySpec{DisplayName: "a", TenantID: one.ID, Roles: []string{"admin"}})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, _, err := s.CreateKey(ctx, records.KeySpec{DisplayName: "b", TenantID: two.ID, Roles: []string{"admin"}}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	all, verr := s.ListKeys(ctx, "")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if len(all) != 2 {
		t.Fatalf("all keys = %d", len(all))
	}
	mine, verr := s.ListKeys(ctx, one.ID)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if len(mine) != 1 || mine[0].TenantID != one.ID {
		t.Fatalf("filtered keys = %+v", mine)
	}
	if err := s.DeleteTenant(ctx, one.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	left, verr := s.ListKeys(ctx, "")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	if _, serr := s.BindAdmin(ctx, "", "user"); !errors.Is(serr, records.ErrInvalid) {
		t.Errorf("empty issuer: %v", serr)
	}
	if _, serr := s.BindAdmin(ctx, "https://idp.example", " "); !errors.Is(serr, records.ErrInvalid) {
		t.Errorf("empty subject: %v", serr)
	}
	if _, serr := s.BindAdmin(ctx, "https://idp.example", "user-2"); serr != nil {
		t.Fatalf("BindAdmin: %v", serr)
	}
	list, err := s.ListAdmins(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListAdmins = %+v, %v", list, err)
	}
	if list[0].Subject > list[1].Subject {
		t.Errorf("admins are not sorted: %+v", list)
	}
	n, cerr := s.CountAdmins(ctx)
	if cerr != nil || n != 2 {
		t.Errorf("CountAdmins = %d, %v", n, cerr)
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
	firstSecret, secondSecret := records.NewSecret(), records.NewSecret()
	firstID, secondID := records.NewID(), records.NewID()
	if firstSecret == secondSecret || firstID == secondID {
		t.Fatal("two random values are equal")
	}
}

// failStore fails every operation the test names.
type failStore struct {
	store.KeyValue
	failPut  bool
	failList bool
	failDel  bool
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
	s, verr := records.New(failStore{KeyValue: kv, failPut: true}, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := s.CreateTenant(ctx, "Tenant"); err == nil {
		t.Error("CreateTenant hid a store error")
	}
	if _, err := s.BindAdmin(ctx, "https://idp.example", "s"); err == nil {
		t.Error("BindAdmin hid a store error")
	}
	if err := s.SetBootstrap(ctx, records.NewBootstrapToken()); err == nil {
		t.Error("SetBootstrap hid a store error")
	}
	listFail, verr := records.New(failStore{KeyValue: kv, failList: true}, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	good, verr := records.New(kv, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	tenant, verr := good.CreateTenant(ctx, "Tenant")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, _, err := good.CreateKey(ctx, records.KeySpec{DisplayName: "k", TenantID: tenant.ID, Roles: []string{"admin"}}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	delFail, verr := records.New(failStore{KeyValue: kv, failDel: true}, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	s, verr := records.New(kv, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	s, verr := records.New(store.Memory(), nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if _, err := s.GetTenant(ctx, "bad key"); err == nil {
		t.Fatal("GetTenant accepted a bad key")
	}
}

// TestTenantBindings is ADR-037 decision 1: a tenant maps onto at most
// one tenant per stack, and the binding survives a reload.
func TestTenantBindings(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	tenant, err := s.CreateTenant(ctx, "Ministry of Health")
	if err != nil {
		t.Fatal(err)
	}
	b := records.Binding{
		Stack: "DPG_CREDEBL", StackName: "Tenancy stack", TenantID: "org-7", Name: "Ministry of Health",
		AgentType: "shared", DIDs: []string{"did:key:z6Mk"},
	}
	got, err := s.AddBinding(ctx, tenant.ID, b)
	if err != nil {
		t.Fatalf("AddBinding: %v", err)
	}
	if len(got.Bindings) != 1 || !got.Bindings[0].BoundAt.Equal(at) || got.Bindings[0].TenantID != "org-7" {
		t.Fatalf("bindings = %+v", got.Bindings)
	}
	if _, cerr := s.AddBinding(ctx, tenant.ID, b); !errors.Is(cerr, records.ErrExists) {
		t.Errorf("a second binding on one stack gave %v", cerr)
	}
	if _, cerr := s.AddBinding(ctx, tenant.ID, records.Binding{Stack: "DPG_INJI"}); !errors.Is(cerr, records.ErrInvalid) {
		t.Errorf("a binding without a stack tenant gave %v", cerr)
	}
	if _, cerr := s.AddBinding(ctx, "missing", b); !errors.Is(cerr, records.ErrNotFound) {
		t.Errorf("an unknown tenant gave %v", cerr)
	}
	reread, err := s.GetTenant(ctx, tenant.ID)
	if err != nil || len(reread.Bindings) != 1 || reread.Bindings[0].DIDs[0] != "did:key:z6Mk" {
		t.Fatalf("GetTenant = %+v, %v", reread, err)
	}
	if bound, ok := reread.Binding("DPG_CREDEBL"); !ok || bound.TenantID != "org-7" {
		t.Errorf("Binding = %+v, %v", bound, ok)
	}
	if _, ok := reread.Binding("DPG_INJI"); ok {
		t.Error("Binding found a stack without a binding")
	}
	removed, err := s.RemoveBinding(ctx, tenant.ID, "DPG_CREDEBL")
	if err != nil || len(removed.Bindings) != 0 {
		t.Fatalf("RemoveBinding = %+v, %v", removed, err)
	}
	if _, err := s.RemoveBinding(ctx, tenant.ID, "DPG_CREDEBL"); !errors.Is(err, records.ErrNotFound) {
		t.Errorf("a second removal gave %v", err)
	}
	if _, err := s.RemoveBinding(ctx, "missing", "DPG_CREDEBL"); !errors.Is(err, records.ErrNotFound) {
		t.Errorf("an unknown tenant gave %v", err)
	}
}
