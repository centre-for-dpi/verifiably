package handlers

import (
	"sort"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// The verifier credential grid must be scoped to the active verifier's own
// ecosystem: Inji Verify ↔ the two Inji Certify issuers; walt.id and CREDEBL
// each to themselves. An empty verifier DPG (none picked / the public verify
// page) applies no scope. Stock (non-custom) schemas are always excluded.
func TestVerifierPresentableSchemas_ScopedByDPG(t *testing.T) {
	all := []vctypes.Schema{
		{Name: "WaltCard", Custom: true, DPGs: []string{"Walt Community Stack"}},
		{Name: "InjiPreCard", Custom: true, DPGs: []string{"Inji Certify · Pre-Auth"}},
		{Name: "InjiAuthCard", Custom: true, DPGs: []string{"Inji Certify · Auth-Code"}},
		{Name: "CredeblCard", Custom: true, DPGs: []string{"CREDEBL"}},
		{Name: "StockCard", Custom: false, DPGs: []string{"Walt Community Stack"}},
	}
	names := func(ss []vctypes.Schema) []string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, s.Name)
		}
		sort.Strings(out)
		return out
	}
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	cases := []struct {
		dpg  string
		want []string
	}{
		{"Inji Verify", []string{"InjiAuthCard", "InjiPreCard"}},
		{"Walt Community Stack", []string{"WaltCard"}},
		{"CREDEBL", []string{"CredeblCard"}},
		{"", []string{"CredeblCard", "InjiAuthCard", "InjiPreCard", "WaltCard"}}, // no scope, stock still excluded
	}
	for _, c := range cases {
		got := names(verifierPresentableSchemas(all, c.dpg))
		if !eq(got, c.want) {
			t.Errorf("verifier %q: grid = %v, want %v", c.dpg, got, c.want)
		}
	}
}
