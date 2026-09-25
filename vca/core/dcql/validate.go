// SPDX-License-Identifier: Apache-2.0

package dcql

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// MaxCredentials caps the credential queries of one query.
const MaxCredentials = 32

// MaxClaims caps the claims of one credential query.
const MaxClaims = 128

// Validate checks a query against the rules of OpenID for Verifiable
// Presentations 1.0. It returns one error that names the first problem.
func Validate(q Query) error {
	if len(q.Credentials) == 0 {
		return fmt.Errorf("dcql: the query has no credential query")
	}
	if len(q.Credentials) > MaxCredentials {
		return fmt.Errorf("dcql: the query has %d credential queries, the limit is %d", len(q.Credentials), MaxCredentials)
	}
	seen := map[string]bool{}
	for _, c := range q.Credentials {
		if err := validateCredential(c); err != nil {
			return err
		}
		if seen[c.ID] {
			return fmt.Errorf("dcql: the credential query id %q is used twice", c.ID)
		}
		seen[c.ID] = true
	}
	return validateSets(q, seen)
}

// validateCredential checks one credential query.
func validateCredential(c CredentialQuery) error {
	if err := validID(c.ID, "credential query id"); err != nil {
		return err
	}
	if !known(Formats, c.Format) {
		return fmt.Errorf("dcql: the credential query %q has the unknown format %q", c.ID, c.Format)
	}
	if err := validateMeta(c); err != nil {
		return err
	}
	for _, a := range c.TrustedAuthorities {
		if a.Type == "" {
			return fmt.Errorf("dcql: a trusted authority of %q has no type", c.ID)
		}
		if len(a.Values) == 0 {
			return fmt.Errorf("dcql: the trusted authority %q of %q has no value", a.Type, c.ID)
		}
	}
	if len(c.Claims) > MaxClaims {
		return fmt.Errorf("dcql: the credential query %q has %d claims, the limit is %d", c.ID, len(c.Claims), MaxClaims)
	}
	claims, err := validateClaims(c)
	if err != nil {
		return err
	}
	return validateClaimSets(c, claims)
}

// validateMeta checks that the metadata matches the format.
func validateMeta(c CredentialQuery) error {
	if c.Meta.Empty() {
		return nil
	}
	switch c.Format {
	case FormatSDJWT, FormatSDJWTLegacy:
		if len(c.Meta.VctValues) == 0 {
			return fmt.Errorf("dcql: the credential query %q needs meta.vct_values for the format %q", c.ID, c.Format)
		}
	case FormatMdoc:
		if c.Meta.DoctypeValue == "" {
			return fmt.Errorf("dcql: the credential query %q needs meta.doctype_value for the format %q", c.ID, c.Format)
		}
	default:
		if len(c.Meta.TypeValues) == 0 {
			return fmt.Errorf("dcql: the credential query %q needs meta.type_values for the format %q", c.ID, c.Format)
		}
		for _, set := range c.Meta.TypeValues {
			if len(set) == 0 {
				return fmt.Errorf("dcql: a meta.type_values entry of %q is empty", c.ID)
			}
		}
	}
	return nil
}

// validateClaims checks the claims and returns the claim ids it saw.
func validateClaims(c CredentialQuery) (map[string]bool, error) {
	ids := map[string]bool{}
	for i, cl := range c.Claims {
		if len(cl.Path) == 0 {
			return nil, fmt.Errorf("dcql: claim %d of %q has an empty path", i+1, c.ID)
		}
		if c.Format == FormatMdoc && len(cl.Path) != 2 {
			return nil, fmt.Errorf("dcql: claim %d of %q needs a namespace and a name, mdoc paths have two segments", i+1, c.ID)
		}
		for _, s := range cl.Path {
			if s.Kind == KindName && s.Name == "" {
				return nil, fmt.Errorf("dcql: claim %d of %q has an empty name segment", i+1, c.ID)
			}
			if s.Kind == KindIndex && s.Index < 0 {
				return nil, fmt.Errorf("dcql: claim %d of %q has the negative array index %d", i+1, c.ID, s.Index)
			}
		}
		if err := validateValues(c.ID, i, cl.Values); err != nil {
			return nil, err
		}
		if cl.ID == "" {
			continue
		}
		if err := validID(cl.ID, "claim id"); err != nil {
			return nil, err
		}
		if ids[cl.ID] {
			return nil, fmt.Errorf("dcql: the claim id %q of %q is used twice", cl.ID, c.ID)
		}
		ids[cl.ID] = true
	}
	return ids, nil
}

// validateClaimSets checks the claim sets against the claim ids.
func validateClaimSets(c CredentialQuery, ids map[string]bool) error {
	if len(c.ClaimSets) == 0 {
		return nil
	}
	if len(c.Claims) == 0 {
		return fmt.Errorf("dcql: the credential query %q has claim sets but no claim", c.ID)
	}
	for _, set := range c.ClaimSets {
		if len(set) == 0 {
			return fmt.Errorf("dcql: a claim set of %q is empty", c.ID)
		}
		seen := map[string]bool{}
		for _, id := range set {
			if !ids[id] {
				return fmt.Errorf("dcql: the claim set of %q names the unknown claim id %q", c.ID, id)
			}
			if seen[id] {
				return fmt.Errorf("dcql: a claim set of %q names the claim id %q twice", c.ID, id)
			}
			seen[id] = true
		}
	}
	return nil
}

// validateValues checks the accepted values of one claim. The
// specification allows strings, integers, and booleans, and a list that
// is present holds at least one value.
func validateValues(credential string, index int, values []any) error {
	if values == nil {
		return nil
	}
	if len(values) == 0 {
		return fmt.Errorf("dcql: claim %d of %q has an empty value list", index+1, credential)
	}
	for _, v := range values {
		if !scalar(v) {
			return fmt.Errorf("dcql: claim %d of %q has the value %v, use a string, a whole number, or a boolean", index+1, credential, v)
		}
	}
	return nil
}

// scalar reports whether v is a string, a whole number, or a boolean.
func scalar(v any) bool {
	switch x := v.(type) {
	case string, bool, int, int64:
		return true
	case float64:
		return x == math.Trunc(x)
	case json.Number:
		_, err := x.Int64()
		return err == nil
	}
	return false
}

// validateSets checks the credential sets against the credential ids.
func validateSets(q Query, ids map[string]bool) error {
	for i, set := range q.CredentialSets {
		if len(set.Options) == 0 {
			return fmt.Errorf("dcql: credential set %d has no option", i+1)
		}
		for _, option := range set.Options {
			if len(option) == 0 {
				return fmt.Errorf("dcql: an option of credential set %d is empty", i+1)
			}
			seen := map[string]bool{}
			for _, id := range option {
				if !ids[id] {
					return fmt.Errorf("dcql: credential set %d names the unknown credential query id %q", i+1, id)
				}
				if seen[id] {
					return fmt.Errorf("dcql: an option of credential set %d names %q twice", i+1, id)
				}
				seen[id] = true
			}
		}
	}
	return nil
}

// validID checks the syntax of an id. The specification allows letters,
// digits, the underscore, and the hyphen.
func validID(id, what string) error {
	if id == "" {
		return fmt.Errorf("dcql: a %s is empty", what)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("dcql: the %s %q has the character %q, use letters, digits, %q, and %q", what, id, string(r), "_", "-")
		}
	}
	return nil
}

// known reports whether list holds value.
func known(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// SelectiveDisclosure reports whether the format discloses single claims.
func SelectiveDisclosure(format string) bool {
	switch format {
	case FormatSDJWT, FormatSDJWTLegacy, FormatMdoc:
		return true
	}
	return false
}

// ClaimPrefix returns the prefix of a claim inside the credential of one
// format. Presentation Exchange paths need it.
func ClaimPrefix(format string) string {
	switch format {
	case FormatSDJWT, FormatSDJWTLegacy, FormatMdoc:
		return ""
	case FormatLDPVC:
		return "credentialSubject"
	default:
		return "vc.credentialSubject"
	}
}

// TypePath returns the path of the type filter of one format.
func TypePath(format string) string {
	switch format {
	case FormatSDJWT, FormatSDJWTLegacy:
		return "$.vct"
	case FormatMdoc:
		return "$.docType"
	case FormatLDPVC:
		return "$.type"
	default:
		return "$.vc.type"
	}
}

// quoted returns the mdoc JSONPath of a namespace and a name.
func quoted(parts ...string) string {
	var b strings.Builder
	b.WriteString("$")
	for _, p := range parts {
		b.WriteString("['" + p + "']")
	}
	return b.String()
}
