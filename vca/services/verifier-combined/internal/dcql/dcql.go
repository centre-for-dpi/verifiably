// SPDX-License-Identifier: Apache-2.0

// Package dcql builds a Digital Credentials Query Language query with
// credential sets (ADR-026 decision 1). The query is the request a
// DCQL capable wallet answers.
//
// The package follows OpenID for Verifiable Presentations 1.0 section 6
// (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
// It keeps the JSON shape local to this service. A shared core/dcql
// package can replace it later without a change to the API.
package dcql

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Claim is one claim path of a credential query.
type Claim struct {
	// Path is the claim path, one element per level.
	Path []string `json:"path"`
}

// Meta narrows the credential type of a query.
type Meta struct {
	// VctValues are the accepted SD-JWT VC type identifiers.
	VctValues []string `json:"vct_values,omitempty"`
	// TypeValues are the accepted W3C type arrays.
	TypeValues [][]string `json:"type_values,omitempty"`
}

// Authority names the issuers a query accepts.
type Authority struct {
	// Type is the authority type. This service uses "aki" only for
	// x509, so it writes "openid_federation" for a URL list.
	Type string `json:"type"`
	// Values are the accepted authority values.
	Values []string `json:"values"`
}

// Credential is one credential query.
type Credential struct {
	// ID is the query id. It is unique in the query.
	ID string `json:"id"`
	// Format is the wire format, for example dc+sd-jwt.
	Format string `json:"format"`
	// Meta narrows the credential type.
	Meta *Meta `json:"meta,omitempty"`
	// Claims lists the claims the verifier asks for.
	Claims []Claim `json:"claims,omitempty"`
	// TrustedAuthorities narrows the issuers.
	TrustedAuthorities []Authority `json:"trusted_authorities,omitempty"`
}

// Set is one credential_sets entry. Each option is a list of query ids.
type Set struct {
	// Options are the alternatives. The wallet answers one of them.
	Options [][]string `json:"options"`
	// Required marks a set the wallet must answer.
	Required bool `json:"required"`
}

// Query is a whole DCQL query.
type Query struct {
	// Credentials are the credential queries.
	Credentials []Credential `json:"credentials"`
	// CredentialSets group the queries into alternatives.
	CredentialSets []Set `json:"credential_sets,omitempty"`
}

// Member is one presentation template in a combination.
type Member struct {
	// Group is the alternative group. Members with the same group form
	// one credential_sets option each. An empty group is mandatory.
	Group string
	// Queries are the credential queries of the template.
	Queries []Credential
}

// ErrNoQuery reports a combination with no credential query.
var ErrNoQuery = errors.New("dcql: the combination has no credential query")

// Build merges the members into one query with credential sets.
// A mandatory member becomes a required set with one option. Members of
// one alternative group become one required set with one option each.
func Build(members []Member) (Query, error) {
	out := Query{}
	seen := map[string]bool{}
	groups := map[string][][]string{}
	var order []string
	for _, m := range members {
		ids := make([]string, 0, len(m.Queries))
		for _, q := range m.Queries {
			if q.ID == "" {
				return Query{}, errors.New("dcql: a credential query has no id")
			}
			if seen[q.ID] {
				return Query{}, fmt.Errorf("dcql: the query id %q is used twice", q.ID)
			}
			seen[q.ID] = true
			out.Credentials = append(out.Credentials, q)
			ids = append(ids, q.ID)
		}
		if len(ids) == 0 {
			continue
		}
		group := m.Group
		if group == "" {
			group = "\x00" + strings.Join(ids, ",")
		}
		if _, known := groups[group]; !known {
			order = append(order, group)
		}
		groups[group] = append(groups[group], ids)
	}
	if len(out.Credentials) == 0 {
		return Query{}, ErrNoQuery
	}
	for _, group := range order {
		out.CredentialSets = append(out.CredentialSets, Set{Options: groups[group], Required: true})
	}
	return out, nil
}

// JSON returns the query as a JSON document.
func (q Query) JSON() (string, error) {
	raw, err := json.Marshal(q)
	if err != nil {
		return "", fmt.Errorf("dcql: %w", err)
	}
	return string(raw), nil
}

// Parse reads a DCQL query from JSON. The service reads the query of a
// stored presentation template with it.
func Parse(raw string) (Query, error) {
	var q Query
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return Query{}, fmt.Errorf("dcql: parse: %w", err)
	}
	return q, nil
}

// QueryIDs returns the query ids of a query in order.
func (q Query) QueryIDs() []string {
	out := make([]string, 0, len(q.Credentials))
	for _, c := range q.Credentials {
		out = append(out, c.ID)
	}
	return out
}

// SortedIDs returns the query ids in order, for a stable page or log.
func SortedIDs(q Query) []string {
	out := q.QueryIDs()
	sort.Strings(out)
	return out
}
