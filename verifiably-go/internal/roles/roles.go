package roles

import (
	"log/slog"
	"os"
	"sort"
	"strings"
)

// Role constants for use in Has() calls and feature guards.
const (
	Issuer   = "issuer"
	Holder   = "holder"
	Verifier = "verifier"
	Trust    = "trust"
	Schemas  = "schemas"
	Hub      = "hub"
)

// Set holds the active deployment roles parsed from VERIFIABLY_ROLES.
// A nil Set means no restriction was configured — all roles are active.
// This preserves backwards-compatibility: deployments without VERIFIABLY_ROLES
// behave identically to the current codebase.
type Set map[string]struct{}

// Parse converts a comma-separated role list into a Set.
// Returns nil when s is empty (all roles active).
func Parse(s string) Set {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	set := make(Set)
	for _, r := range strings.Split(s, ",") {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" {
			set[r] = struct{}{}
		}
	}
	// hub implies trust + schemas; issuer, holder, verifier are independent
	if _, ok := set[Hub]; ok {
		set[Trust] = struct{}{}
		set[Schemas] = struct{}{}
	}
	return set
}

// FromEnv reads VERIFIABLY_ROLES and returns the parsed Set.
func FromEnv() Set {
	return Parse(os.Getenv("VERIFIABLY_ROLES"))
}

// Has reports whether role is active.
// A nil Set (VERIFIABLY_ROLES not set) always returns true.
func (s Set) Has(role string) bool {
	if s == nil {
		return true
	}
	_, ok := s[role]
	return ok
}

// Log emits a startup slog line listing the active roles.
func (s Set) Log() {
	slog.Info("roles activos", "roles", s.names())
}

func (s Set) names() []string {
	if s == nil {
		return []string{"all"}
	}
	out := make([]string, 0, len(s))
	for r := range s {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
