// SPDX-License-Identifier: Apache-2.0

package rolenav

import (
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

func roles() []commonv1.Role {
	return []commonv1.Role{
		commonv1.Role_ROLE_ADMIN, commonv1.Role_ROLE_ISSUER, commonv1.Role_ROLE_HOLDER, commonv1.Role_ROLE_VERIFIER,
	}
}

func TestEveryRoleHasSectionsAndUniquePaths(t *testing.T) {
	for _, role := range roles() {
		sections := Sections(role)
		if len(sections) == 0 {
			t.Errorf("%s: no section", role)
			continue
		}
		seen := map[string]bool{}
		var first string
		for _, s := range sections {
			if len(s.Pages) == 0 {
				t.Errorf("%s: section %q has no page", role, s.Key)
			}
			if s.Key != "" {
				if _, ok := msg.Lookup(s.Key); !ok {
					t.Errorf("%s: section key %q is not in the catalogue", role, s.Key)
				}
			}
			for _, p := range s.Pages {
				if first == "" {
					first = p.Path
				}
				if !strings.HasPrefix(p.Path, "/") {
					t.Errorf("%s: path %q does not start with a slash", role, p.Path)
				}
				if seen[p.Path] {
					t.Errorf("%s: path %q appears twice", role, p.Path)
				}
				seen[p.Path] = true
				if _, ok := msg.Lookup(p.Key); !ok {
					t.Errorf("%s: page key %q is not in the catalogue", role, p.Key)
				}
				if p.Label() == "" || p.Label() == p.Key {
					t.Errorf("%s: page %q has no label", role, p.Path)
				}
			}
		}
		// The first page of a role is its home, so the shell and the CLI
		// agree on where a sign in returns (ADR-044 decision 5).
		if home := topology.HomePath(role); first != home {
			t.Errorf("%s: first page %q, want the home %q", role, first, home)
		}
		if paths := Paths(role); len(paths) != len(seen) {
			t.Errorf("%s: Paths returns %d paths, want %d", role, len(paths), len(seen))
		}
	}
	if Sections(commonv1.Role_ROLE_UNSPECIFIED) != nil {
		t.Error("an unknown role has sections")
	}
}

func TestVisibleDropsGatedPages(t *testing.T) {
	sections := []Section{
		{Pages: []Page{{Path: "/wallet/", Key: "holder.nav.credentials.label"}}},
		{Key: "admin.nav.trust_lists.label", Pages: []Page{
			{Path: "/wallet/keys", Key: "holder.nav.claim.label", Feature: backendv1.Feature_FEATURE_WALLET_KEYS},
		}},
	}
	none := visible(sections, func(backendv1.Feature) bool { return false })
	if len(none) != 1 || len(none[0].Pages) != 1 || none[0].Pages[0].Path != "/wallet/" {
		t.Fatalf("without the feature: %+v", none)
	}
	all := visible(sections, func(f backendv1.Feature) bool { return f == backendv1.Feature_FEATURE_WALLET_KEYS })
	if len(all) != 2 || all[1].Pages[0].Path != "/wallet/keys" {
		t.Fatalf("with the feature: %+v", all)
	}
	// A nil predicate shows only the pages without a gate.
	if got := visible(sections, nil); len(got) != 1 {
		t.Fatalf("nil predicate: %+v", got)
	}
	// Visible reads the table of the role.
	if got := Visible(commonv1.Role_ROLE_ADMIN, nil); len(got) == 0 {
		t.Fatal("the admin has no visible section")
	}
}

func TestNavMarksCurrentLongestMatch(t *testing.T) {
	nav := Nav(commonv1.Role_ROLE_ADMIN, nil, "/admin/providers/new")
	var current []string
	for _, s := range nav {
		if s.Label != "" {
			if _, ok := msg.Lookup(s.Label); ok {
				t.Errorf("section label %q is a key, want the sentence", s.Label)
			}
		}
		for _, l := range s.Links {
			if l.Current {
				current = append(current, l.Href)
			}
		}
	}
	if len(current) != 1 || current[0] != "/admin/providers" {
		t.Fatalf("current links %v, want /admin/providers only", current)
	}
	// The overview is current only on its own path, never as the prefix
	// of every other page.
	nav = Nav(commonv1.Role_ROLE_ADMIN, nil, "/admin/")
	current = nil
	for _, s := range nav {
		for _, l := range s.Links {
			if l.Current {
				current = append(current, l.Href)
			}
		}
	}
	if len(current) != 1 || current[0] != "/admin/" {
		t.Fatalf("current links %v, want /admin/ only", current)
	}
	if got := Nav(commonv1.Role_ROLE_UNSPECIFIED, nil, "/"); got != nil {
		t.Fatal("an unknown role has a nav")
	}
}

// TestIssuerNavFollowsTheBoard lists the issuer pages in the order of
// board Issuer-Portal: overview, identity, schemas, builder, issue,
// the bulk issuance sources, issued credentials, notifications, help
// (ADR-044 decisions 1 and 2).
func TestIssuerNavFollowsTheBoard(t *testing.T) {
	want := []string{"/issuer/", "/identity/", "/portal/", "/builder/", "/issue/", "/sources/", "/issued/", "/notifications/", "/help/"}
	got := Paths(commonv1.Role_ROLE_ISSUER)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("issuer paths %v, want %v", got, want)
	}
	nav := Nav(commonv1.Role_ROLE_ISSUER, nil, "/identity/")
	var current []string
	for _, s := range nav {
		for _, l := range s.Links {
			if l.Current {
				current = append(current, l.Href)
			}
		}
	}
	if len(current) != 1 || current[0] != "/identity/" {
		t.Fatalf("current %v, want /identity/", current)
	}
}

// TestHolderNavFollowsTheBoard lists the wallet pages in the order of
// board Holder-Portal: my credentials, discover, claim, present, then
// keys and identifiers when the wallet of the stack manages keys, then
// help.
func TestHolderNavFollowsTheBoard(t *testing.T) {
	want := []string{"/wallet/", "/wallet/discover", "/wallet/claim", "/wallet/present", "/wallet/keys", "/wallet/help"}
	if got := Paths(commonv1.Role_ROLE_HOLDER); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("holder paths %v, want %v", got, want)
	}
	labels := func(has Has) []string {
		var out []string
		for _, s := range Nav(commonv1.Role_ROLE_HOLDER, has, "/wallet/claim?offer=1") {
			for _, l := range s.Links {
				text := l.Text
				if l.Current {
					text += "*"
				}
				out = append(out, text)
			}
		}
		return out
	}
	if got := strings.Join(labels(nil), ", "); got != "My credentials, Discover, Claim*, Present, Help" {
		t.Fatalf("holder nav without keys: %s", got)
	}
	keys := func(f backendv1.Feature) bool { return f == backendv1.Feature_FEATURE_WALLET_KEYS }
	if got := strings.Join(labels(keys), ", "); got != "My credentials, Discover, Claim*, Present, Keys and identifiers, Help" {
		t.Fatalf("holder nav with keys: %s", got)
	}
}

// TestVerifierNavFollowsTheBoard pins the side navigation of board
// Verifier-Portal (P5-01): the overview, the schemas, the query pages,
// the requests, the results, the caching, and the help. A result detail
// marks Results, not the overview.
func TestVerifierNavFollowsTheBoard(t *testing.T) {
	var got []string
	for _, s := range Nav(commonv1.Role_ROLE_VERIFIER, nil, "/portal/results/abc") {
		for _, l := range s.Links {
			text := l.Text
			if l.Current {
				text += "*"
			}
			got = append(got, text)
		}
	}
	want := "Overview, Discover schemas, DCQL builder, DIF PE queries, Requests, Results*, Caching, Help"
	if strings.Join(got, ", ") != want {
		t.Fatalf("verifier nav %s, want %s", strings.Join(got, ", "), want)
	}
}
