// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

type failingPersister struct {
	oidcflow.Persister
	failSave bool
	failLoad bool
}

func (f *failingPersister) Save(name string, v any) error {
	if f.failSave {
		return errors.New("disk full")
	}
	return f.Persister.Save(name, v)
}

func (f *failingPersister) Load(name string, v any) error {
	if f.failLoad {
		return errors.New("corrupt")
	}
	return f.Persister.Load(name, v)
}

func TestRegistry(t *testing.T) {
	store := oidcflow.NewMemoryPersister()
	reg, err := oidcflow.NewRegistry(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Put(oidcflow.Provider{ID: "bad"}); !errors.Is(err, oidcflow.ErrInvalidProvider) {
		t.Fatalf("invalid: %v", err)
	}
	p, err := reg.Put(oidcflow.Provider{DisplayName: "A", DiscoveryURL: "https://a/.well-known/openid-configuration", ClientID: "c", Enabled: true})
	if err != nil || p.ID == "" || p.CreatedAt.IsZero() {
		t.Fatalf("put: %+v %v", p, err)
	}
	created := p.CreatedAt
	p.DisplayName = "B"
	p.CreatedAt = time.Time{}
	p2, _ := reg.Put(p)
	if !p2.CreatedAt.Equal(created) || p2.DisplayName != "B" {
		t.Fatalf("update kept created_at: %+v", p2)
	}
	if _, err := reg.Put(oidcflow.Provider{ID: "z", DiscoveryURL: "https://z/x", ClientID: "c", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if got := reg.List(); len(got) != 2 || got[1].ID != "z" {
		t.Fatalf("list: %+v", got)
	}
	if got := reg.Enabled(); len(got) != 1 || got[0].ID != p.ID {
		t.Fatalf("enabled: %+v", got)
	}
	if _, err := reg.Get("nope"); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("get: %v", err)
	}
	// A new registry on the same store sees the records.
	reg2, err := oidcflow.NewRegistry(store, nil)
	if err != nil || len(reg2.List()) != 2 {
		t.Fatalf("reload: %v", err)
	}
	if err := reg.Delete("z"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Delete("z"); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	// Persist failures roll back.
	fp := &failingPersister{Persister: store}
	reg3, _ := oidcflow.NewRegistry(fp, nil)
	fp.failSave = true
	if _, err := reg3.Put(oidcflow.Provider{ID: "new", DiscoveryURL: "https://n/x", ClientID: "c"}); err == nil {
		t.Fatal("save error hidden")
	}
	if _, err := reg3.Get("new"); err == nil {
		t.Fatal("rolled back create missing")
	}
	existing := reg3.List()[0]
	existing.DisplayName = "changed"
	if _, err := reg3.Put(existing); err == nil {
		t.Fatal("save error hidden on update")
	}
	if got, _ := reg3.Get(existing.ID); got.DisplayName == "changed" {
		t.Fatal("update not rolled back")
	}
	if err := reg3.Delete(existing.ID); err == nil {
		t.Fatal("delete save error hidden")
	}
	if _, err := reg3.Get(existing.ID); err != nil {
		t.Fatal("delete not rolled back")
	}
	fp.failLoad = true
	if _, err := oidcflow.NewRegistry(fp, nil); err == nil {
		t.Fatal("load error hidden")
	}
	if _, err := oidcflow.NewRegistry(nil, nil); err != nil {
		t.Fatal(err)
	}
	// Bad stored JSON.
	bad := oidcflow.NewMemoryPersister()
	_ = bad.Save("providers", "not a list")
	if _, err := oidcflow.NewRegistry(bad, nil); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestProtoConversion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := oidcflow.Provider{
		ID: "a", DisplayName: "A", DiscoveryURL: "https://a/x", ClientID: "c",
		ClientSecret:   oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "S"},
		Roles:          []string{"issuer", "holder", "verifier", "admin", "odd"},
		RolesClaimPath: "roles", Enabled: true, CreatedAt: now,
	}
	m := oidcflow.ToAdminProto(p)
	if m.GetClientSecret().GetStore() != commonv1.SecretRef_STORE_ENV || len(m.GetRoles()) != 5 || m.GetRoles()[4] != commonv1.Role_ROLE_UNSPECIFIED {
		t.Fatalf("to proto: %+v", m)
	}
	back := oidcflow.FromAdminProto(m)
	if back.ID != "a" || back.ClientSecret != p.ClientSecret || !back.CreatedAt.Equal(now) || len(back.Roles) != 5 || back.Roles[4] != "" {
		t.Fatalf("from proto: %+v", back)
	}
	for _, st := range []oidcflow.SecretStore{oidcflow.SecretFile, oidcflow.SecretKMS, oidcflow.SecretStore("odd")} {
		q := oidcflow.FromAdminProto(oidcflow.ToAdminProto(oidcflow.Provider{ClientSecret: oidcflow.SecretRef{Store: st, Name: "n"}}))
		want := st
		if st == "odd" {
			want = oidcflow.SecretNone
		}
		if q.ClientSecret.Store != want && !(want == oidcflow.SecretNone && q.ClientSecret.IsZero()) {
			t.Fatalf("store %s -> %s", st, q.ClientSecret.Store)
		}
	}
	if !oidcflow.FromAdminProto(&adminv1.AuthProvider{}).ClientSecret.IsZero() {
		t.Fatal("empty secret")
	}
}

func TestAdminProvidersRPC(t *testing.T) {
	reg, _ := oidcflow.NewRegistry(nil, nil)
	svc := oidcflow.AdminProviders{Registry: reg, Authorize: oidcflow.BearerAuthorizer("admin-token"), Roles: []string{"issuer"}}
	path, h := oidcflow.NewAdminHandler(svc)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := adminv1connect.NewAdminServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	withAuth := func(tok string) connect.ClientOption {
		return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				req.Header().Set("Authorization", "Bearer "+tok)
				return next(ctx, req)
			}
		}))
	}
	authed := adminv1connect.NewAdminServiceClient(srv.Client(), srv.URL, withAuth("admin-token"))
	wrong := adminv1connect.NewAdminServiceClient(srv.Client(), srv.URL, withAuth("nope"))

	prov := &adminv1.AuthProvider{DisplayName: "A", DiscoveryUrl: "https://a/.well-known/openid-configuration", ClientId: "c", Enabled: true, Roles: []commonv1.Role{commonv1.Role_ROLE_ADMIN}}
	if _, err := client.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: prov})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no auth: %v", err)
	}
	if _, err := wrong.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: prov})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong auth: %v", err)
	}
	if _, err := authed.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: prov, DynamicRegistration: true})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("dynamic: %v", err)
	}
	created, err := authed.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: prov}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetProvider().GetId()
	if id == "" || created.Msg.GetProvider().GetRoles()[0] != commonv1.Role_ROLE_ISSUER {
		t.Fatalf("created: %+v", created.Msg)
	}
	if _, err := authed.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: &adminv1.AuthProvider{}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid: %v", err)
	}
	got, err := authed.GetAuthProvider(ctx, connect.NewRequest(&adminv1.GetAuthProviderRequest{Id: id}))
	if err != nil || got.Msg.GetProvider().GetDisplayName() != "A" {
		t.Fatalf("get: %v", err)
	}
	if _, err := authed.GetAuthProvider(ctx, connect.NewRequest(&adminv1.GetAuthProviderRequest{Id: "x"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("get missing: %v", err)
	}
	list, err := authed.ListAuthProviders(ctx, connect.NewRequest(&adminv1.ListAuthProvidersRequest{}))
	if err != nil || len(list.Msg.GetProviders()) != 1 || list.Msg.GetPage().GetTotalSize() != 1 {
		t.Fatalf("list: %v", err)
	}
	upd := got.Msg.GetProvider()
	upd.DisplayName = "B"
	res, err := authed.UpdateAuthProvider(ctx, connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: upd}))
	if err != nil || res.Msg.GetProvider().GetDisplayName() != "B" {
		t.Fatalf("update: %v", err)
	}
	upd.ClientId = ""
	if _, err := authed.UpdateAuthProvider(ctx, connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: upd})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("update invalid: %v", err)
	}
	if _, err := authed.UpdateAuthProvider(ctx, connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: &adminv1.AuthProvider{Id: "x"}})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("update missing: %v", err)
	}
	if _, err := authed.DeleteAuthProvider(ctx, connect.NewRequest(&adminv1.DeleteAuthProviderRequest{Id: id})); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := authed.DeleteAuthProvider(ctx, connect.NewRequest(&adminv1.DeleteAuthProviderRequest{Id: id})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := authed.CreateTenant(ctx, connect.NewRequest(&adminv1.CreateTenantRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("other rpc: %v", err)
	}
	for _, m := range []func() error{
		func() error {
			_, err := wrong.GetAuthProvider(ctx, connect.NewRequest(&adminv1.GetAuthProviderRequest{}))
			return err
		},
		func() error {
			_, err := wrong.ListAuthProviders(ctx, connect.NewRequest(&adminv1.ListAuthProvidersRequest{}))
			return err
		},
		func() error {
			_, err := wrong.UpdateAuthProvider(ctx, connect.NewRequest(&adminv1.UpdateAuthProviderRequest{}))
			return err
		},
		func() error {
			_, err := wrong.DeleteAuthProvider(ctx, connect.NewRequest(&adminv1.DeleteAuthProviderRequest{}))
			return err
		},
	} {
		if err := m(); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("unauth: %v", err)
		}
	}
	// No authorizer at all denies everything.
	none := oidcflow.AdminProviders{Registry: reg}
	if _, err := none.ListAuthProviders(ctx, connect.NewRequest(&adminv1.ListAuthProvidersRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("nil authorizer: %v", err)
	}
}

func TestAuthorizers(t *testing.T) {
	h := http.Header{}
	if err := oidcflow.BearerAuthorizer("")(context.Background(), h); err == nil {
		t.Fatal("empty token allows")
	}
	h.Set("Authorization", "Bearer t")
	deny := oidcflow.BearerAuthorizer("x")
	allow := oidcflow.BearerAuthorizer("t")
	if err := oidcflow.AnyAuthorizer(deny, allow)(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := oidcflow.AnyAuthorizer(deny)(context.Background(), h); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := oidcflow.AnyAuthorizer()(context.Background(), h); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatal(err)
	}
}
