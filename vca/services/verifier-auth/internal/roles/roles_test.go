// SPDX-License-Identifier: Apache-2.0

package roles_test

import (
	"errors"
	"strings"
	"testing"

	verifierauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/roles"
)

func TestNamesAndValues(t *testing.T) {
	all := []verifierauthv1.VerifierRole{verifierauthv1.VerifierRole_VERIFIER_ROLE_ADMIN, verifierauthv1.VerifierRole_VERIFIER_ROLE_OPERATOR, verifierauthv1.VerifierRole_VERIFIER_ROLE_VIEWER, verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED}
	names := roles.Names(all)
	if strings.Join(names, ",") != "verifier-admin,verifier-operator,verifier-viewer" {
		t.Fatal(names)
	}
	back := roles.Values(append(names, "other"))
	if len(back) != 3 || back[0] != verifierauthv1.VerifierRole_VERIFIER_ROLE_ADMIN {
		t.Fatal(back)
	}
}

func TestApply(t *testing.T) {
	m := roles.Default("")
	if m.ClaimPath != roles.DefaultClaimPath {
		t.Fatal(m.ClaimPath)
	}
	claims := map[string]any{"realm_access": map[string]any{"roles": []any{"verifier-viewer", "verifier-admin", "verifier-admin", "other"}}}
	got, err := roles.Apply(m, claims)
	if err != nil || strings.Join(got, ",") != "verifier-admin,verifier-viewer" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := roles.Apply(m, map[string]any{}); !errors.Is(err, oidcflow.ErrRoleDenied) {
		t.Fatalf("denied: %v", err)
	}
	m.DefaultRole = roles.Viewer
	if got, err := roles.Apply(m, map[string]any{}); err != nil || strings.Join(got, ",") != "verifier-viewer" {
		t.Fatalf("default: %v %v", got, err)
	}
	custom := roles.Mapping{ClaimPath: "groups", Rules: []roles.Rule{{ClaimValue: "staff", Role: roles.Operator}, {ClaimValue: "x", Role: "bogus"}}}
	if got, err := roles.Apply(custom, map[string]any{"groups": "staff"}); err != nil || strings.Join(got, ",") != "verifier-operator" {
		t.Fatalf("custom: %v %v", got, err)
	}
	if _, err := roles.Apply(custom, map[string]any{"groups": "x"}); !errors.Is(err, oidcflow.ErrRoleDenied) {
		t.Fatalf("bogus role granted: %v", err)
	}
}

func TestProtoAndValidate(t *testing.T) {
	m := roles.Default("roles")
	m.DefaultRole = roles.Viewer
	p := roles.ToProto(m)
	if p.GetClaimPath() != "roles" || len(p.GetRules()) != 3 || p.GetDefaultRole() != verifierauthv1.VerifierRole_VERIFIER_ROLE_VIEWER {
		t.Fatalf("%+v", p)
	}
	back := roles.FromProto(p)
	if back.ClaimPath != m.ClaimPath || len(back.Rules) != 3 || back.Rules[0] != m.Rules[0] || back.DefaultRole != roles.Viewer {
		t.Fatalf("%+v", back)
	}
	if err := back.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []roles.Mapping{
		{},
		{ClaimPath: "r", Rules: []roles.Rule{{ClaimValue: "", Role: roles.Admin}}},
		{ClaimPath: "r", Rules: []roles.Rule{{ClaimValue: "a", Role: "nope"}}},
	}
	for i, b := range bad {
		if err := b.Validate(); !errors.Is(err, oidcflow.ErrInvalidProvider) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

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

func TestMappings(t *testing.T) {
	store := &failStore{Persister: oidcflow.NewMemoryPersister()}
	ms, err := roles.NewMappings(store)
	if err != nil {
		t.Fatal(err)
	}
	if got := ms.Get("idp", "custom.path"); got.ClaimPath != "custom.path" {
		t.Fatalf("default: %+v", got)
	}
	custom := roles.Mapping{ClaimPath: "groups", Rules: []roles.Rule{{ClaimValue: "g", Role: roles.Admin}}}
	if err := ms.Set("idp", custom); err != nil {
		t.Fatal(err)
	}
	if err := ms.Set("idp", roles.Mapping{}); !errors.Is(err, oidcflow.ErrInvalidProvider) {
		t.Fatal(err)
	}
	if got := ms.Get("idp", ""); got.ClaimPath != "groups" {
		t.Fatalf("%+v", got)
	}
	ms2, verr := roles.NewMappings(store)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if got := ms2.Get("idp", ""); got.ClaimPath != "groups" {
		t.Fatal("not persisted")
	}
	store.fail = true
	if err := ms.Set("other", custom); err == nil {
		t.Fatal("save error hidden")
	}
	if got := ms.Get("other", "p"); got.ClaimPath != "p" {
		t.Fatal("not rolled back")
	}
	custom.ClaimPath = "changed"
	if err := ms.Set("idp", custom); err == nil {
		t.Fatal("save error hidden")
	}
	if got := ms.Get("idp", ""); got.ClaimPath != "groups" {
		t.Fatal("update not rolled back")
	}
	if _, err := roles.NewMappings(store); err == nil {
		t.Fatal("load error hidden")
	}
}
