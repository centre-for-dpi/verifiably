// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

func seedRecord(id string) oidcflow.Provider {
	return oidcflow.Provider{
		ID: id, DisplayName: "Keycloak", ClientID: "vca-inji-authz", Enabled: true, Roles: []string{"holder"},
		DiscoveryURL: "http://keycloak-inji:8080/realms/vca-holder-realm/.well-known/openid-configuration",
		Profile:      oidcflow.Profile{Kind: oidcflow.KindKeycloak, IsDefault: true},
	}
}

// TestSeedOnceKeepsTheRemovalOfTheAdmin: a seed stays the default until
// an admin changes it. Once an admin removes the seeded record, a later
// start does not write it again.
func TestSeedOnceKeepsTheRemovalOfTheAdmin(t *testing.T) {
	docs := oidcflow.NewMemoryPersister()
	reg, err := oidcflow.NewRegistry(docs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wrote, serr := reg.SeedOnce(seedRecord(oidcflow.SeedID)); serr != nil || !wrote {
		t.Fatalf("first seed = %v %v", wrote, serr)
	}
	if wrote, serr := reg.SeedOnce(seedRecord(oidcflow.SeedID)); serr != nil || wrote {
		t.Fatalf("second seed = %v %v", wrote, serr)
	}
	if derr := reg.Delete(oidcflow.SeedID); derr != nil {
		t.Fatal(derr)
	}
	again, err := oidcflow.NewRegistry(docs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wrote, serr := again.SeedOnce(seedRecord(oidcflow.SeedID)); serr != nil || wrote {
		t.Fatalf("a seed after the removal = %v %v", wrote, serr)
	}
	if _, gerr := again.Get(oidcflow.SeedID); gerr == nil {
		t.Fatal("the removed seed came back")
	}
	// A record from before the mark counts as seeded.
	old, err := oidcflow.NewRegistry(oidcflow.NewMemoryPersister(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, perr := old.Put(seedRecord("esignet")); perr != nil {
		t.Fatal(perr)
	}
	if wrote, serr := old.SeedOnce(seedRecord("esignet")); serr != nil || wrote {
		t.Fatalf("a record from before = %v %v", wrote, serr)
	}
	if derr := old.Delete("esignet"); derr != nil {
		t.Fatal(derr)
	}
	if wrote, serr := old.SeedOnce(seedRecord("esignet")); serr != nil || wrote {
		t.Fatalf("a seed after the removal of an old record = %v %v", wrote, serr)
	}
	// A seed that fails validation is an error, and so is a store that
	// keeps nothing.
	if _, serr := reg.SeedOnce(oidcflow.Provider{ID: "broken"}); serr == nil {
		t.Fatal("an invalid seed passed")
	}
	full := &failingPersister{Persister: oidcflow.NewMemoryPersister()}
	broken, err := oidcflow.NewRegistry(full, nil)
	if err != nil {
		t.Fatal(err)
	}
	full.failSave = true
	if _, serr := broken.SeedOnce(seedRecord(oidcflow.SeedID)); serr == nil {
		t.Fatal("a store that keeps nothing passed")
	}
	full.failLoad = true
	if _, serr := broken.SeedOnce(seedRecord(oidcflow.SeedID)); serr == nil {
		t.Fatal("a store that reads nothing passed")
	}
}

func allowAll(context.Context, http.Header) error { return nil }

// TestAdminProvidersKeepOneDefault: with OneDefault a record that an
// admin marks as the default takes the flag from every other record.
func TestAdminProvidersKeepOneDefault(t *testing.T) {
	reg, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, perr := reg.Put(seedRecord(oidcflow.SeedID)); perr != nil {
		t.Fatal(perr)
	}
	svc := oidcflow.AdminProviders{Registry: reg, Authorize: allowAll, Roles: []string{"holder"}, OneDefault: true}
	ctx := context.Background()
	record := &adminv1.AuthProvider{
		DisplayName: "eSignet", DiscoveryUrl: "https://esignet.gov.example/v1/esignet/oidc/.well-known/openid-configuration",
		ClientId: "vca-inji", Enabled: true,
	}
	created, err := svc.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: record}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetProvider().GetId()
	if seed := mustGet(t, reg, oidcflow.SeedID); !seed.IsDefault {
		t.Fatal("a record without the flag took the default")
	}
	record = created.Msg.GetProvider()
	record.IsDefault = true
	if _, err = svc.UpdateAuthProvider(ctx, connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		t.Fatal(err)
	}
	if seed := mustGet(t, reg, oidcflow.SeedID); seed.IsDefault {
		t.Fatal("the seed kept the default beside the choice of the admin")
	}
	if got := mustGet(t, reg, id); !got.IsDefault {
		t.Fatal("the choice of the admin lost the flag")
	}
	// A new default from a create moves the flag again.
	third := &adminv1.AuthProvider{
		DisplayName: "National ID", DiscoveryUrl: "https://id.gov.example/.well-known/openid-configuration",
		ClientId: "vca", Enabled: true, IsDefault: true,
	}
	if _, err = svc.CreateAuthProvider(ctx, connect.NewRequest(&adminv1.CreateAuthProviderRequest{Provider: third})); err != nil {
		t.Fatal(err)
	}
	defaults := 0
	for _, p := range reg.List() {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("defaults = %d", defaults)
	}
	// Without OneDefault several records may carry the flag.
	svc.OneDefault = false
	record.IsDefault = true
	if _, err = svc.UpdateAuthProvider(ctx, connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: record})); err != nil {
		t.Fatal(err)
	}
	defaults = 0
	for _, p := range reg.List() {
		if p.IsDefault {
			defaults++
		}
	}
	if defaults != 2 {
		t.Fatalf("defaults without OneDefault = %d", defaults)
	}
}

// TestAdminUpdateKeepsWhatTheMessageCannotCarry: the admin message has
// no scopes, no logo and no internal address. An update keeps those of
// the stored record, so an edit of the verified claims does not send
// the token call of the stack realm to its public address.
func TestAdminUpdateKeepsWhatTheMessageCannotCarry(t *testing.T) {
	reg, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedRecord(oidcflow.SeedID)
	seed.Scopes = []string{"openid", "email", "profile"}
	seed.InternalAuthority = "http://keycloak-inji:8080"
	seed.LogoURI = "https://id.gov.example/logo.svg"
	if _, perr := reg.Put(seed); perr != nil {
		t.Fatal(perr)
	}
	svc := oidcflow.AdminProviders{Registry: reg, Authorize: allowAll, Roles: []string{"holder"}}
	msg := oidcflow.ToAdminProto(seed)
	msg.VerifiedClaims = []string{"individual_id"}
	if _, err = svc.UpdateAuthProvider(context.Background(), connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: msg})); err != nil {
		t.Fatal(err)
	}
	got, err := reg.Get(oidcflow.SeedID)
	if err != nil || !slices.Equal(got.Scopes, seed.Scopes) || got.InternalAuthority != seed.InternalAuthority ||
		got.LogoURI != seed.LogoURI || !slices.Equal(got.VerifiedClaims, []string{"individual_id"}) {
		t.Fatalf("stored = %+v %v", got, err)
	}
	// Another provider behind the record keeps none of them.
	moved := oidcflow.ToAdminProto(seed)
	moved.DiscoveryUrl = "https://id.gov.example/.well-known/openid-configuration"
	if _, err = svc.UpdateAuthProvider(context.Background(), connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: moved})); err != nil {
		t.Fatal(err)
	}
	if got = mustGet(t, reg, oidcflow.SeedID); got.InternalAuthority != "" || len(got.Scopes) != 0 || got.LogoURI != "" {
		t.Fatalf("a new provider kept the old one's fields: %+v", got)
	}
	// A service with its own internal address still sets it.
	svc.InternalAuthority = "http://idp:8080"
	if _, err = svc.UpdateAuthProvider(context.Background(), connect.NewRequest(&adminv1.UpdateAuthProviderRequest{Provider: msg})); err != nil {
		t.Fatal(err)
	}
	if got = mustGet(t, reg, oidcflow.SeedID); got.InternalAuthority != "http://idp:8080" {
		t.Fatalf("internal authority = %q", got.InternalAuthority)
	}
}

// mustGet reads one record that must exist.
func mustGet(t *testing.T, reg *oidcflow.Registry, id string) oidcflow.Provider {
	t.Helper()
	p, err := reg.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
