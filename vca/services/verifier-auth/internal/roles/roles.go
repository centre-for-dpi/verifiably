// SPDX-License-Identifier: Apache-2.0

// Package roles maps IdP claims to verifier roles (ADR-036 decision 1,
// ADR-012 decision 3).
package roles

import (
	"sort"
	"sync"

	verifierauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// Role names as they appear in session tokens.
const (
	Admin    = "verifier-admin"
	Operator = "verifier-operator"
	Viewer   = "verifier-viewer"
)

// DefaultClaimPath is the claim path when neither the mapping nor the
// provider names one.
const DefaultClaimPath = "realm_access.roles"

// Name returns the token name of a proto role, or "" for unspecified.
func Name(r verifierauthv1.VerifierRole) string {
	switch r {
	case verifierauthv1.VerifierRole_VERIFIER_ROLE_ADMIN:
		return Admin
	case verifierauthv1.VerifierRole_VERIFIER_ROLE_OPERATOR:
		return Operator
	case verifierauthv1.VerifierRole_VERIFIER_ROLE_VIEWER:
		return Viewer
	}
	return ""
}

// Value returns the proto role of a token name.
func Value(name string) verifierauthv1.VerifierRole {
	switch name {
	case Admin:
		return verifierauthv1.VerifierRole_VERIFIER_ROLE_ADMIN
	case Operator:
		return verifierauthv1.VerifierRole_VERIFIER_ROLE_OPERATOR
	case Viewer:
		return verifierauthv1.VerifierRole_VERIFIER_ROLE_VIEWER
	}
	return verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED
}

// Names converts proto roles to token names and drops unspecified ones.
func Names(rs []verifierauthv1.VerifierRole) []string {
	var out []string
	for _, r := range rs {
		if n := Name(r); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// Values converts token names to proto roles and drops unknown ones.
func Values(names []string) []verifierauthv1.VerifierRole {
	var out []verifierauthv1.VerifierRole
	for _, n := range names {
		if v := Value(n); v != verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED {
			out = append(out, v)
		}
	}
	return out
}

// Rule maps one claim value to one role.
type Rule struct {
	ClaimValue string `json:"claim_value"`
	Role       string `json:"role"`
}

// Mapping is the stored form of vca.verifierauth.v1.RoleMapping.
type Mapping struct {
	ClaimPath   string `json:"claim_path"`
	Rules       []Rule `json:"rules"`
	DefaultRole string `json:"default_role,omitempty"`
}

// Default returns the mapping a provider gets before an admin sets one.
// The claim values equal the role names.
func Default(claimPath string) Mapping {
	if claimPath == "" {
		claimPath = DefaultClaimPath
	}
	return Mapping{
		ClaimPath: claimPath,
		Rules: []Rule{
			{ClaimValue: Admin, Role: Admin},
			{ClaimValue: Operator, Role: Operator},
			{ClaimValue: Viewer, Role: Viewer},
		},
	}
}

// Apply returns the roles of claims under m, sorted and without
// duplicates. It returns ErrRoleDenied when no rule matches and the
// mapping has no default role.
func Apply(m Mapping, claims map[string]any) ([]string, error) {
	values := oidcflow.ClaimPath(claims, m.ClaimPath)
	set := map[string]bool{}
	for _, r := range m.Rules {
		if Value(r.Role) == verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED {
			continue
		}
		for _, v := range values {
			if v == r.ClaimValue {
				set[r.Role] = true
			}
		}
	}
	if len(set) == 0 {
		if Value(m.DefaultRole) == verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED {
			return nil, oidcflow.ErrRoleDenied
		}
		set[m.DefaultRole] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

// FromProto converts a proto mapping.
func FromProto(m *verifierauthv1.RoleMapping) Mapping {
	out := Mapping{ClaimPath: m.GetClaimPath(), DefaultRole: Name(m.GetDefaultRole())}
	for _, r := range m.GetRules() {
		out.Rules = append(out.Rules, Rule{ClaimValue: r.GetClaimValue(), Role: Name(r.GetRole())})
	}
	return out
}

// ToProto converts a mapping to its proto form.
func ToProto(m Mapping) *verifierauthv1.RoleMapping {
	out := &verifierauthv1.RoleMapping{ClaimPath: m.ClaimPath, DefaultRole: Value(m.DefaultRole)}
	for _, r := range m.Rules {
		out.Rules = append(out.Rules, &verifierauthv1.RoleMapping_Rule{ClaimValue: r.ClaimValue, Role: Value(r.Role)})
	}
	return out
}

// Validate checks that a mapping can grant a role.
func (m Mapping) Validate() error {
	if m.ClaimPath == "" {
		return oidcflow.ErrInvalidProvider
	}
	for _, r := range m.Rules {
		if r.ClaimValue == "" || Value(r.Role) == verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED {
			return oidcflow.ErrInvalidProvider
		}
	}
	return nil
}

const mappingsDoc = "role_mappings"

// Mappings stores one mapping per provider id.
type Mappings struct {
	store oidcflow.Persister
	mu    sync.RWMutex
	m     map[string]Mapping
}

// NewMappings loads the mappings from store.
func NewMappings(store oidcflow.Persister) (*Mappings, error) {
	m := map[string]Mapping{}
	if err := store.Load(mappingsDoc, &m); err != nil {
		return nil, err
	}
	return &Mappings{store: store, m: m}, nil
}

// Get returns the mapping of a provider, or Default(claimPath).
func (s *Mappings) Get(providerID, claimPath string) Mapping {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.m[providerID]; ok {
		return m
	}
	return Default(claimPath)
}

// Set replaces the mapping of a provider.
func (s *Mappings) Set(providerID string, m Mapping) error {
	if err := m.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.m[providerID]
	s.m[providerID] = m
	if err := s.store.Save(mappingsDoc, s.m); err != nil {
		if had {
			s.m[providerID] = prev
		} else {
			delete(s.m, providerID)
		}
		return err
	}
	return nil
}
