// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
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
	// The clock is fixed and both ids are explicit, so List gives the
	// same order on every run. A random id can start with "z" and sort
	// after the second provider.
	clock := func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	store := oidcflow.NewMemoryPersister()
	reg, regErr := oidcflow.NewRegistry(store, clock)
	if regErr != nil {
		t.Fatal(regErr)
	}
	if _, err := reg.Put(oidcflow.Provider{ID: "bad"}); !errors.Is(err, oidcflow.ErrInvalidProvider) {
		t.Fatalf("invalid: %v", err)
	}
	p, err := reg.Put(oidcflow.Provider{ID: "a", DisplayName: "A", DiscoveryURL: "https://a/.well-known/openid-configuration", ClientID: "c", Enabled: true})
	if err != nil || p.ID == "" || p.CreatedAt.IsZero() {
		t.Fatalf("put: %+v %v", p, err)
	}
	created := p.CreatedAt
	p.DisplayName = "B"
	p.CreatedAt = time.Time{}
	p2, err := reg.Put(p)
	if err != nil {
		t.Fatalf("reg.Put: %v", err)
	}
	if !p2.CreatedAt.Equal(created) || p2.DisplayName != "B" {
		t.Fatalf("update kept created_at: %+v", p2)
	}
	if _, gotErr := reg.Put(oidcflow.Provider{ID: "z", DiscoveryURL: "https://z/x", ClientID: "c", Enabled: false}); gotErr != nil {
		t.Fatal(err)
	}
	if got := reg.List(); len(got) != 2 || got[1].ID != "z" {
		t.Fatalf("list: %+v", got)
	}
	if got := reg.Enabled(); len(got) != 1 || got[0].ID != p.ID {
		t.Fatalf("enabled: %+v", got)
	}
	if _, gotErr := reg.Get("nope"); !errors.Is(gotErr, oidcflow.ErrProviderNotFound) {
		t.Fatalf("get: %v", gotErr)
	}
	// A new registry on the same store sees the records.
	reg2, err := oidcflow.NewRegistry(store, clock)
	if err != nil || len(reg2.List()) != 2 {
		t.Fatalf("reload: %v", err)
	}
	if gotErr := reg.Delete("z"); gotErr != nil {
		t.Fatal(gotErr)
	}
	if gotErr := reg.Delete("z"); !errors.Is(gotErr, oidcflow.ErrProviderNotFound) {
		t.Fatalf("delete twice: %v", gotErr)
	}
	// Persist failures roll back.
	fp := &failingPersister{Persister: store}
	reg3, err := oidcflow.NewRegistry(fp, clock)
	if err != nil {
		t.Fatalf("oidcflow.NewRegistry: %v", err)
	}
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
	stored, storedErr := reg3.Get(existing.ID)
	if storedErr != nil || stored.DisplayName == "changed" {
		t.Fatalf("update not rolled back: %v", storedErr)
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
	if err := bad.Save("providers", "not a list"); err != nil {
		t.Fatalf("bad.Save: %v", err)
	}
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
		if q.ClientSecret.Store != want && (want != oidcflow.SecretNone || !q.ClientSecret.IsZero()) {
			t.Fatalf("store %s -> %s", st, q.ClientSecret.Store)
		}
	}
	if !oidcflow.FromAdminProto(&adminv1.AuthProvider{}).ClientSecret.IsZero() {
		t.Fatal("empty secret")
	}
}

func TestAdminProvidersRPC(t *testing.T) {
	reg, regErr := oidcflow.NewRegistry(nil, nil)
	if regErr != nil {
		t.Fatalf("oidcflow.NewRegistry: %v", regErr)
	}
	svc := oidcflow.AdminProviders{Registry: reg, Authorize: oidcflow.BearerAuthorizer("admin-token"), Roles: []string{"issuer"}, InternalAuthority: "http://idp:8080"}
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
	created, createdErr := authed.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: prov}))
	if createdErr != nil {
		t.Fatal(createdErr)
	}
	id := created.Msg.GetProvider().GetId()
	if id == "" || created.Msg.GetProvider().GetRoles()[0] != commonv1.Role_ROLE_ISSUER {
		t.Fatalf("created: %+v", created.Msg)
	}
	p, pErr := reg.Get(id)
	if pErr != nil || p.InternalAuthority != "http://idp:8080" {
		t.Fatalf("internal authority: %+v %v", p, pErr)
	}
	if _, err := authed.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: &adminv1.AuthProvider{}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid: %v", err)
	}
	got, err := authed.GetAuthProvider(ctx, connect.NewRequest(&adminv1.GetAuthProviderRequest{Id: id}))
	if err != nil || got.Msg.GetProvider().GetDisplayName() != "A" {
		t.Fatalf("get: %v", err)
	}
	if _, gotErr := authed.GetAuthProvider(ctx, connect.NewRequest(&adminv1.GetAuthProviderRequest{Id: "x"})); connect.CodeOf(gotErr) != connect.CodeNotFound {
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

// fullProvider is a record with every field of ADR-035 decision 2 set.
func fullProvider() oidcflow.Provider {
	return oidcflow.Provider{
		ID: "kc", DisplayName: "Stack", DiscoveryURL: "https://kc.example/realms/vca-issuer-realm/.well-known/openid-configuration",
		ClientID: "vca-issuer", ClientSecret: oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "S"},
		Roles: []string{"issuer"}, Enabled: true,
		Profile: oidcflow.Profile{
			Kind:            oidcflow.KindKeycloak,
			Realm:           "vca-issuer-realm",
			Registration:    oidcflow.RegistrationKeycloakEndpoint,
			ConsoleURL:      "https://kc.example/admin/vca-issuer-realm/console/",
			Stacks:          []string{"waltid", "inji"},
			TokenAuthMethod: oidcflow.TokenAuthPrivateKeyJWT,
			PrivateKey:      oidcflow.SecretRef{Store: oidcflow.SecretFile, Name: "/run/secrets/client.pem"},
			IsDefault:       true,
		},
	}
}

// TestProviderRoundTripKeepsNewFields keeps the kind, the realm, the
// registration mode, the console, the stacks, the token authentication
// method, the key reference, and the default flag across the persister
// and across the admin proto (ADR-035 decisions 2 and 4).
func TestProviderRoundTripKeepsNewFields(t *testing.T) {
	store := oidcflow.NewMemoryPersister()
	reg, err := oidcflow.NewRegistry(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := fullProvider()
	if _, putErr := reg.Put(want); putErr != nil {
		t.Fatalf("Put: %v", putErr)
	}
	again, err := oidcflow.NewRegistry(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Get("kc")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Profile, want.Profile) {
		t.Errorf("persisted profile = %+v, want %+v", got.Profile, want.Profile)
	}
	m := oidcflow.ToAdminProto(want)
	if m.GetKind() != adminv1.ProviderKind_PROVIDER_KIND_KEYCLOAK || m.GetRealm() != "vca-issuer-realm" ||
		m.GetRegistration() != adminv1.Registration_REGISTRATION_KEYCLOAK_ENDPOINT ||
		m.GetConsoleUrl() != want.ConsoleURL || len(m.GetStacks()) != 2 ||
		m.GetStacks()[0] != configv1.Dpg_DPG_WALTID || m.GetStacks()[1] != configv1.Dpg_DPG_INJI ||
		m.GetTokenAuthMethod() != adminv1.TokenAuth_TOKEN_AUTH_PRIVATE_KEY_JWT ||
		m.GetPrivateKey().GetStore() != commonv1.SecretRef_STORE_FILE || m.GetPrivateKey().GetName() != "/run/secrets/client.pem" ||
		!m.GetIsDefault() {
		t.Errorf("to proto = %+v", m)
	}
	back := oidcflow.FromAdminProto(m)
	if !reflect.DeepEqual(back.Profile, want.Profile) {
		t.Errorf("from proto = %+v, want %+v", back.Profile, want.Profile)
	}
	// Every enum value survives the trip; an unknown string becomes the
	// unspecified value and comes back empty.
	for _, kind := range []oidcflow.Kind{oidcflow.KindGeneric, oidcflow.KindKeycloak, oidcflow.KindWSO2, oidcflow.KindESignet} {
		p := oidcflow.FromAdminProto(oidcflow.ToAdminProto(oidcflow.Provider{Profile: oidcflow.Profile{Kind: kind}}))
		if p.Kind != kind {
			t.Errorf("kind %s -> %s", kind, p.Kind)
		}
	}
	for _, mode := range []oidcflow.Registration{oidcflow.RegistrationNone, oidcflow.RegistrationPromptCreate, oidcflow.RegistrationKeycloakEndpoint} {
		p := oidcflow.FromAdminProto(oidcflow.ToAdminProto(oidcflow.Provider{Profile: oidcflow.Profile{Registration: mode}}))
		if p.Registration != mode {
			t.Errorf("registration %s -> %s", mode, p.Registration)
		}
	}
	for _, method := range []oidcflow.TokenAuth{oidcflow.TokenAuthClientSecretBasic, oidcflow.TokenAuthClientSecretPost, oidcflow.TokenAuthPrivateKeyJWT, oidcflow.TokenAuthNone} {
		p := oidcflow.FromAdminProto(oidcflow.ToAdminProto(oidcflow.Provider{Profile: oidcflow.Profile{TokenAuthMethod: method}}))
		if p.TokenAuthMethod != method {
			t.Errorf("token auth %s -> %s", method, p.TokenAuthMethod)
		}
	}
	odd := oidcflow.FromAdminProto(oidcflow.ToAdminProto(oidcflow.Provider{Profile: oidcflow.Profile{
		Kind: "odd", Registration: "odd", TokenAuthMethod: "odd", Stacks: []string{"odd", "credebl"},
	}}))
	if odd.Kind != "" || odd.Registration != "" || odd.TokenAuthMethod != "" || len(odd.Stacks) != 1 || odd.Stacks[0] != "credebl" {
		t.Errorf("odd values = %+v", odd.Profile)
	}
	if !oidcflow.FromAdminProto(&adminv1.AuthProvider{}).PrivateKey.IsZero() {
		t.Error("an empty message has a key reference")
	}
}

// TestSeedProviderIsKeycloakWithRealmAndConsole is ADR-035 decision 2:
// the provider that the setup CLI seeds is a record of kind keycloak
// with the realm of the role, the console of that realm, and the
// default flag, and no code path depends on the kind.
func TestSeedProviderIsKeycloakWithRealmAndConsole(t *testing.T) {
	seed := oidcflow.Seed{
		DiscoveryURL:      "http://waltid-keycloak:8080/realms/vca-issuer-realm/.well-known/openid-configuration",
		ClientID:          "vca-issuer",
		ClientSecretEnv:   "VCA_OIDC_CLIENT_SECRET",
		PublicURL:         "http://localhost:17010/",
		RolesClaimPath:    "realm_access.roles",
		Roles:             []string{"issuer"},
		InternalAuthority: "http://waltid-keycloak:8080",
	}
	p := oidcflow.SeedProvider(seed)
	if p.ID != oidcflow.SeedID || p.DisplayName == "" || !p.Enabled || !p.IsDefault {
		t.Errorf("seed = %+v", p)
	}
	if p.Kind != oidcflow.KindKeycloak || p.Realm != "vca-issuer-realm" ||
		p.ConsoleURL != "http://localhost:17010/admin/vca-issuer-realm/console/" {
		t.Errorf("seed profile = %+v", p.Profile)
	}
	// The chooser shows the product name beside the realm (board Signin).
	if p.DisplayName != "Keycloak" {
		t.Errorf("seed display name = %q, want Keycloak", p.DisplayName)
	}
	if p.Registration != "" {
		t.Errorf("the seed fixes the registration mode to %q; the metadata decides", p.Registration)
	}
	if p.ClientSecret != (oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "VCA_OIDC_CLIENT_SECRET"}) ||
		p.RolesClaimPath != "realm_access.roles" || len(p.Roles) != 1 || p.InternalAuthority != seed.InternalAuthority {
		t.Errorf("seed record = %+v", p)
	}
	// No public URL: the console sits at the authority of the discovery URL.
	seed.PublicURL = ""
	if p := oidcflow.SeedProvider(seed); p.ConsoleURL != "http://waltid-keycloak:8080/admin/vca-issuer-realm/console/" {
		t.Errorf("console without a public URL = %q", p.ConsoleURL)
	}
	// No secret variable: a public client.
	seed.ClientSecretEnv = ""
	if p := oidcflow.SeedProvider(seed); !p.ClientSecret.IsZero() {
		t.Errorf("a public client got a secret: %+v", p.ClientSecret)
	}
	// Another provider is generic, with no realm and no console.
	seed.DiscoveryURL = "https://idp.example/.well-known/openid-configuration"
	if p := oidcflow.SeedProvider(seed); p.Kind != oidcflow.KindGeneric || p.Realm != "" || p.ConsoleURL != "" || p.DisplayName != "Sign in" {
		t.Errorf("generic seed = %+v", p)
	}
	if realm, ok := oidcflow.KeycloakRealmOf("https://idp.example/realms/x/.well-known/openid-configuration"); !ok || realm != "x" {
		t.Errorf("KeycloakRealmOf = %q, %v", realm, ok)
	}
	for _, raw := range []string{"https://idp.example/realms//.well-known/openid-configuration", "https://idp.example/realms/x", "::bad", ""} {
		if _, ok := oidcflow.KeycloakRealmOf(raw); ok {
			t.Errorf("KeycloakRealmOf(%q) passed", raw)
		}
	}
	// The registry seeds once and keeps a stored record.
	reg, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seedErr := reg.Seed(oidcflow.SeedProvider(seed)); seedErr != nil {
		t.Fatalf("Seed: %v", seedErr)
	}
	kept, getErr := reg.Get(oidcflow.SeedID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	kept.DisplayName = "Kept"
	if _, putErr := reg.Put(kept); putErr != nil {
		t.Fatal(putErr)
	}
	if seedErr := reg.Seed(oidcflow.SeedProvider(seed)); seedErr != nil {
		t.Fatalf("second Seed: %v", seedErr)
	}
	if got, gotErr := reg.Get(oidcflow.SeedID); gotErr != nil || got.DisplayName != "Kept" {
		t.Errorf("the seed replaced the stored record: %v", gotErr)
	}
	fresh, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Seed(oidcflow.SeedProvider(oidcflow.Seed{})); !errors.Is(err, oidcflow.ErrInvalidProvider) {
		t.Errorf("an empty seed = %v", err)
	}
}
