// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

// offerView is what the offer page shows of an issuer before the holder
// accepts: the display name of the issuer, the display of each offered
// credential, and the display names of their claims.
type offerView struct {
	// read is true when the wallet read the issuer metadata.
	read bool
	// name is the display name of the issuer.
	name string
	// displays holds the display of each offered configuration.
	displays []*schemav1.Display
	// claims holds the display names of the claims.
	claims []string
}

// displayEntry is one entry of an OID4VCI display array.
type displayEntry struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

// configurationView is the part of one credential configuration the
// offer page reads. OID4VCI 1.0 nests the display and the claims under
// credential_metadata (section 12.2.4); draft 13 keeps them at the top.
type configurationView struct {
	Format     string          `json:"format"`
	Display    []displayEntry  `json:"display"`
	Claims     json.RawMessage `json:"claims"`
	Metadata   *nestedMetadata `json:"credential_metadata"`
	Definition struct {
		Subject map[string]struct {
			Display []displayEntry `json:"display"`
		} `json:"credentialSubject"`
	} `json:"credential_definition"`
}

// nestedMetadata is the credential_metadata object of OID4VCI 1.0.
type nestedMetadata struct {
	Display []displayEntry  `json:"display"`
	Claims  json.RawMessage `json:"claims"`
}

// display returns the display entries, from the top or else from
// credential_metadata.
func (c configurationView) display() []displayEntry {
	if firstName(c.Display) == "" && c.Metadata != nil {
		return c.Metadata.Display
	}
	return c.Display
}

// claims returns the claims, from the top or else from
// credential_metadata.
func (c configurationView) claims() json.RawMessage {
	if len(c.Claims) == 0 && c.Metadata != nil {
		return c.Metadata.Claims
	}
	return c.Claims
}

// offerMetadata is the part of the issuer metadata the offer page reads
// (OID4VCI 1.0 section 12.2, draft 13 section 11.2).
type offerMetadata struct {
	Display        []displayEntry               `json:"display"`
	Configurations map[string]configurationView `json:"credential_configurations_supported"`
}

// offerDetails reads the issuer metadata of an offer for the offer page.
// A wallet that cannot read it says so, and the page names the address.
// A generic entry with no display gives way to the configuration the
// schema registry publishes under hint, when its format is the same.
func (s *Service) offerDetails(ctx context.Context, issuer string, ids []string, hint string) offerView {
	if s.opts.Fetch == nil || strings.TrimSpace(issuer) == "" {
		return offerView{}
	}
	raw, err := s.guardedFetch(ctx, strings.TrimRight(issuer, "/")+issuerMetadataPath)
	var meta offerMetadata
	if err != nil || json.Unmarshal(raw, &meta) != nil {
		return offerView{}
	}
	view := offerView{read: true, name: firstName(meta.Display)}
	for _, id := range ids {
		cfg, ok := meta.Configurations[id]
		if !ok {
			continue
		}
		if firstName(cfg.display()) == "" {
			cfg = s.published(ctx, hint, cfg)
		}
		name := firstName(cfg.display())
		if name == "" {
			name = id
		}
		view.displays = append(view.displays, &schemav1.Display{Name: name, Locale: firstLocale(cfg.display())})
		names := claimDisplayNames(cfg.claims())
		for claim, d := range cfg.Definition.Subject {
			names = append(names, orName(firstName(d.Display), claim))
		}
		for _, n := range names {
			if !slices.Contains(view.claims, n) {
				view.claims = append(view.claims, n)
			}
		}
	}
	return view
}

// published returns the configuration the schema registry publishes
// under hint when it has the format of the stack entry, else the entry.
func (s *Service) published(ctx context.Context, hint string, entry configurationView) configurationView {
	if hint == "" || s.opts.Published == nil {
		return entry
	}
	raw, ok := s.opts.Published(ctx, hint)
	if !ok {
		return entry
	}
	var cfg configurationView
	if json.Unmarshal(raw, &cfg) != nil || cfg.Format != entry.Format {
		return entry
	}
	return cfg
}

// claimDisplayNames reads the claims of a configuration: the list of
// OID4VCI 1.0 with a path per claim, or the map of draft 13, which nests
// an mDoc claim under its namespace.
func claimDisplayNames(raw json.RawMessage) []string {
	var list []struct {
		Path    []any          `json:"path"`
		Display []displayEntry `json:"display"`
	}
	if json.Unmarshal(raw, &list) == nil {
		var out []string
		for _, c := range list {
			last := ""
			if n := len(c.Path); n > 0 {
				if segment, ok := c.Path[n-1].(string); ok {
					last = segment
				}
			}
			if name := orName(firstName(c.Display), last); name != "" {
				out = append(out, name)
			}
		}
		return out
	}
	var tree map[string]json.RawMessage
	if json.Unmarshal(raw, &tree) != nil {
		return nil
	}
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []string
	for _, k := range keys {
		var leaf struct {
			Display []displayEntry `json:"display"`
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(tree[k], &leaf) == nil && len(leaf.Display) > 0 {
			out = append(out, orName(firstName(leaf.Display), k))
			continue
		}
		if json.Unmarshal(tree[k], &nested) == nil && len(nested) > 0 && !hasLeafKeys(nested) {
			out = append(out, claimDisplayNames(tree[k])...)
			continue
		}
		out = append(out, k)
	}
	return out
}

// hasLeafKeys reports whether a claim description holds the keys of a
// claim, not the claims of a namespace.
func hasLeafKeys(m map[string]json.RawMessage) bool {
	for _, k := range []string{"display", "mandatory", "value_type"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// firstName returns the name of the first display entry.
func firstName(d []displayEntry) string {
	for _, e := range d {
		if strings.TrimSpace(e.Name) != "" {
			return strings.TrimSpace(e.Name)
		}
	}
	return ""
}

// firstLocale returns the locale of the first display entry.
func firstLocale(d []displayEntry) string {
	if len(d) > 0 {
		return d[0].Locale
	}
	return ""
}

// orName returns name, or fallback when name is empty.
func orName(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}
