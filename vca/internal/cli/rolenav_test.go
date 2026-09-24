// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
)

// TestRoleNavPathsAreRoutedPages binds the side navigation of every role
// to the route table: each path the rolenav package lists sits under a
// route of the pair that carries a Page, so the side navigation and the
// reverse proxy cannot drift (ADR-044 decision 5).
func TestRoleNavPathsAreRoutedPages(t *testing.T) {
	for _, role := range Roles() {
		p := Pair{Role: role, Dpg: configv1.Dpg_DPG_WALTID}
		routes := PairRoutes(p, nil)
		paths := rolenav.Paths(role)
		if len(paths) == 0 {
			t.Errorf("%s: rolenav lists no page", p.Name())
			continue
		}
		for _, path := range paths {
			found := ""
			for _, sr := range routes {
				if sr.Route.Page == "" || !strings.HasPrefix(path, sr.Route.Path()) {
					continue
				}
				if len(sr.Route.Path()) > len(found) {
					found = sr.Route.Path()
				}
			}
			if found == "" {
				t.Errorf("%s: the page %s of the side navigation matches no page route", p.Name(), path)
			}
		}
	}
}
