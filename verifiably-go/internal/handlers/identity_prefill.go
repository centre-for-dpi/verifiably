package handlers

import "strings"

// identityPrefill maps a citizen's verified OIDC claims (captured at login in
// sess.UserClaims) onto issuance-form field names. It returns only the fields
// it could resolve, so callers overlay the result on top of adapter-provided
// demo prefill — real identity wins for the fields it covers, demo data fills
// the rest. This is the National ID Nivel 2 claim-mapping step; see
// docs/credential-delivery.md (identity-bound quadrant).
//
// Matching is tolerant of naming style: schema fields "dateOfBirth",
// "date_of_birth" and "dob" all resolve to the OIDC `birthdate` claim. A field
// is matched first by normalized key (lowercased, non-alphanumeric stripped)
// against the claim names, then through a small alias table for the common
// identity attributes whose schema names diverge from the OIDC claim names.
func identityPrefill(fields []string, claims map[string]string) map[string]string {
	if len(fields) == 0 || len(claims) == 0 {
		return nil
	}
	byNorm := normalizeClaims(claims)
	out := map[string]string{}
	for _, f := range fields {
		if v, ok := resolveClaim(f, byNorm); ok {
			out[f] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeClaims indexes a citizen's claims by their normalized key, dropping
// empty values. Build it ONCE and reuse it across many field lookups — callers
// matching a list of fields (eligibility over a catalog) must not rebuild it
// per field/credential.
func normalizeClaims(claims map[string]string) map[string]string {
	byNorm := make(map[string]string, len(claims))
	for k, v := range claims {
		if v == "" {
			continue
		}
		byNorm[normIdentityKey(k)] = v
	}
	return byNorm
}

// resolveClaim finds the value for a schema field name in a normalized claim
// index, trying a direct normalized match first, then the alias table. This is
// the single source of truth for field↔claim matching, shared by prefill and
// eligibility so the two never drift.
func resolveClaim(field string, byNorm map[string]string) (string, bool) {
	nf := normIdentityKey(field)
	if v, ok := byNorm[nf]; ok {
		return v, true
	}
	for _, cand := range identityAliases[nf] {
		if v, ok := byNorm[cand]; ok {
			return v, true
		}
	}
	return "", false
}

// identityAliases maps a normalized schema-field key to the ordered list of
// normalized OIDC claim keys to try when there is no direct match. Order
// matters: the first claim present wins. Covers the common national-id
// attribute names in English and Spanish since the federation spans
// Spanish-speaking organismos.
var identityAliases = map[string][]string{
	"firstname":       {"givenname"},
	"givennames":      {"givenname"},
	"nombre":          {"givenname"},
	"nombres":         {"givenname"},
	"lastname":        {"familyname"},
	"surname":         {"familyname"},
	"apellido":        {"familyname"},
	"apellidos":       {"familyname"},
	"fullname":        {"name"},
	"nombrecompleto":  {"name"},
	"dateofbirth":     {"birthdate"},
	"dob":             {"birthdate"},
	"fechanacimiento": {"birthdate"},
	"nationalid":      {"nationalid", "cedula", "dni"},
	"cedula":          {"cedula", "nationalid", "dni"},
	"dni":             {"dni", "nationalid", "cedula"},
	"documentnumber":  {"nationalid", "cedula", "dni"},
	"documentid":      {"nationalid", "cedula", "dni"},
	"idnumber":        {"nationalid", "cedula"},
	"phone":           {"phonenumber"},
	"mobile":          {"phonenumber"},
	"telefono":        {"phonenumber"},
	"nationality":     {"nationality"},
	"nacionalidad":    {"nationality"},
}

// normIdentityKey lowercases and strips every non-alphanumeric rune, so
// "given_name", "givenName", "given-name" and "Given Name" all collapse to
// "givenname".
func normIdentityKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
