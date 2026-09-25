// SPDX-License-Identifier: Apache-2.0

// Package rolenav lists the pages of every role portal in the order of
// the side navigation (ADR-044 decision 5). The shell of each portal
// draws its side navigation from this table, and a test in the CLI
// checks that every path sits under a page route of the pair, so the
// navigation and the reverse proxy cannot drift.
//
// A page can carry a feature gate: the portal shows it only when a live
// pair of the role lists that feature (ADR-034 decision 5). The labels
// are keys of the message catalogue.
package rolenav

import (
	"strings"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Page is one page of a role portal.
type Page struct {
	// Path is the path of the page under the public URL of the pair, for
	// example /admin/trust.
	Path string
	// Key is the catalogue key of the label.
	Key string
	// Feature, when set, hides the page until a live pair of the role
	// lists the feature.
	Feature backendv1.Feature
}

// Label returns the label of the page from the catalogue.
func (p Page) Label() string { return msg.T(p.Key) }

// Section is one group of pages under one heading.
type Section struct {
	// Key is the catalogue key of the heading. Empty means no heading.
	Key string
	// Pages are the pages of the group, in order.
	Pages []Page
}

// Label returns the heading of the section, or "" without one.
func (s Section) Label() string {
	if s.Key == "" {
		return ""
	}
	return msg.T(s.Key)
}

// Has reports whether a deployment offers a feature. A nil predicate
// offers none.
type Has func(backendv1.Feature) bool

// Sections returns the full navigation of a role, in order. The first
// page is the home of the role. An unknown role gives nil.
func Sections(role commonv1.Role) []Section {
	switch role {
	case commonv1.Role_ROLE_ADMIN:
		return []Section{
			{Pages: []Page{{Path: "/admin/", Key: "common.overview.label"}}},
			{Key: "admin.nav.section.trust.label", Pages: []Page{
				{Path: "/admin/trust", Key: "admin.nav.trust_lists.label"},
				{Path: "/admin/trust/registries", Key: "admin.nav.trust_registries.label"},
			}},
			{Key: "admin.nav.section.access.label", Pages: []Page{
				{Path: "/admin/providers", Key: "admin.nav.providers.label"},
				{Path: "/admin/tenants", Key: "admin.nav.tenants.label"},
				{Path: "/admin/keys", Key: "admin.nav.api_keys.label"},
			}},
			{Key: "admin.nav.section.records.label", Pages: []Page{
				{Path: "/admin/audit", Key: "admin.nav.audit.label"},
				{Path: "/admin/notifications", Key: "common.notifications.label"},
			}},
			{Pages: []Page{{Path: "/admin/help", Key: "common.help.label"}}},
		}
	case commonv1.Role_ROLE_ISSUER:
		// Board Issuer-Portal. The issuance service serves the overview,
		// the identity, the issue, the notifications, and the help pages;
		// the schema registry and the builder serve theirs (ADR-044
		// decision 1).
		return []Section{{Pages: []Page{
			{Path: "/issuer/", Key: "common.overview.label"},
			{Path: "/identity/", Key: "issuer.nav.identity.label"},
			{Path: "/portal/", Key: "issuer.nav.schemas.label"},
			{Path: "/builder/", Key: "issuer.nav.builder.label"},
			{Path: "/issue/", Key: "issuer.nav.issue.label"},
			{Path: "/notifications/", Key: "common.notifications.label"},
			{Path: "/help/", Key: "common.help.label"},
		}}}
	case commonv1.Role_ROLE_HOLDER:
		return []Section{{Pages: []Page{
			{Path: "/wallet/", Key: "holder.nav.credentials.label"},
			{Path: "/wallet/discover", Key: "holder.nav.discover.label"},
			{Path: "/wallet/claimable", Key: "holder.nav.claim.label"},
			{Path: "/wallet/present", Key: "holder.nav.present.label"},
		}}}
	case commonv1.Role_ROLE_VERIFIER:
		return []Section{{Pages: []Page{
			{Path: "/portal/", Key: "verifier.nav.results.label"},
			{Path: "/discovery/", Key: "verifier.nav.discover.label"},
			{Path: "/scan/", Key: "verifier.nav.requests.label"},
		}}}
	default:
		return nil
	}
}

// Paths returns every page path of a role, in navigation order.
func Paths(role commonv1.Role) []string {
	var out []string
	for _, s := range Sections(role) {
		for _, p := range s.Pages {
			out = append(out, p.Path)
		}
	}
	return out
}

// Visible returns the navigation of a role without the gated pages the
// deployment lacks, and without a section that lost every page.
func Visible(role commonv1.Role, has Has) []Section {
	return visible(Sections(role), has)
}

// visible filters one table.
func visible(sections []Section, has Has) []Section {
	var out []Section
	for _, s := range sections {
		kept := Section{Key: s.Key}
		for _, p := range s.Pages {
			if p.Feature == backendv1.Feature_FEATURE_UNSPECIFIED || (has != nil && has(p.Feature)) {
				kept.Pages = append(kept.Pages, p)
			}
		}
		if len(kept.Pages) > 0 {
			out = append(out, kept)
		}
	}
	return out
}

// Nav builds the side navigation of the shell for a role: the visible
// sections with their labels, and the link of the page that current
// falls under marked as current. The longest page path that prefixes
// current wins, so /admin/providers/new marks the providers page. An
// unknown role gives nil.
func Nav(role commonv1.Role, has Has, current string) []components.NavSection {
	sections := Visible(role, has)
	if sections == nil {
		return nil
	}
	match := ""
	for _, s := range sections {
		for _, p := range s.Pages {
			if underPage(current, p.Path) && len(p.Path) > len(match) {
				match = p.Path
			}
		}
	}
	out := make([]components.NavSection, 0, len(sections))
	for _, s := range sections {
		sec := components.NavSection{Label: s.Label()}
		for _, p := range s.Pages {
			sec.Links = append(sec.Links, components.Link{Href: p.Path, Text: p.Label(), Current: p.Path == match})
		}
		out = append(out, sec)
	}
	return out
}

// underPage reports whether current is the page path or a path below
// it. A page path with a trailing slash prefixes its children; any
// other page path needs a slash or a query after it.
func underPage(current, page string) bool {
	if current == page {
		return true
	}
	if strings.HasSuffix(page, "/") {
		return strings.HasPrefix(current, page)
	}
	return strings.HasPrefix(current, page+"/") || strings.HasPrefix(current, page+"?")
}
