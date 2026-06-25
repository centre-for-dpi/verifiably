package delegation

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
)

// findDelegation returns the index of the first credential carrying a delegation
// capability, with the parsed capability. Returns (-1, _) when none is present.
func findDelegation(creds []backend.NormalizedCredential) (int, Capability) {
	for i, c := range creds {
		if cap, ok := extractCapability(c); ok {
			return i, cap
		}
	}
	return -1, Capability{}
}

// findIdentity picks the subject identity credential to pair with the delegation.
// It prefers a non-delegation credential whose subject anchor matches onBehalfOf;
// otherwise the first non-delegation credential.
func findIdentity(creds []backend.NormalizedCredential, delegIdx int, onBehalfOf string) (backend.NormalizedCredential, bool) {
	var first *backend.NormalizedCredential
	for i := range creds {
		if i == delegIdx {
			continue
		}
		c := creds[i]
		if first == nil {
			cc := c
			first = &cc
		}
		if onBehalfOf != "" && sameRef(subjectAnchor(c), onBehalfOf) {
			return c, true
		}
	}
	if first != nil {
		return *first, true
	}
	return backend.NormalizedCredential{}, false
}

// extractCapability normalizes the delegation capability from either the SD-JWT
// `delegation` claim or a JSON-LD `termsOfUse` entry of type DelegationCapability.
// Returns ok=false when the credential carries no capability.
func extractCapability(c backend.NormalizedCredential) (Capability, bool) {
	// SD-JWT / JOSE: a top-level `delegation` object — or a JSON-encoded string
	// (selective disclosure stringifies object claims).
	if d, ok := asMapOrJSON(c.Raw["delegation"]); ok {
		cap := Capability{
			Controller:             firstNonEmpty(mapStr(d, "controller"), c.Issuer),
			OnBehalfOf:             firstNonEmpty(mapStr(d, "on_behalf_of"), mapStr(d, "onBehalfOf"), refID(c.Raw["credentialSubject"], "onBehalfOf")),
			Delegate:               firstNonEmpty(mapStr(d, "delegate"), c.SubjectID),
			AllowedAction:          mapStrSlice(d, "allowed_action", "allowedAction"),
			ValidUntil:             firstNonEmpty(mapStr(d, "valid_until"), mapStr(d, "validUntil")),
			AllowFurtherDelegation: mapBool(d, "allow_further_delegation") || mapBool(d, "allowFurtherDelegation"),
		}
		_, cap.HasChain = d["parent_capability"]
		return cap, true
	}
	// JSON-LD: a termsOfUse entry of type DelegationCapability.
	for _, tou := range asSlice(c.Raw["termsOfUse"]) {
		m, ok := asMap(tou)
		if !ok || !typeContains(m["type"], "DelegationCapability") {
			continue
		}
		cap := Capability{
			Controller:             firstNonEmpty(mapStr(m, "controller"), c.Issuer),
			OnBehalfOf:             firstNonEmpty(mapStr(m, "invocationTarget"), mapStr(m, "onBehalfOf"), refID(c.Raw["credentialSubject"], "onBehalfOf")),
			Delegate:               firstNonEmpty(mapStr(m, "delegate"), c.SubjectID),
			AllowedAction:          mapStrSlice(m, "allowedAction", "allowed_action"),
			ValidUntil:             firstNonEmpty(mapStr(m, "validUntil"), caveatValidUntil(m["caveat"])),
			AllowFurtherDelegation: mapBool(m, "allowFurtherDelegation"),
		}
		_, cap.HasChain = m["parentCapability"]
		return cap, true
	}
	// SD-JWT flat claims (e.g. Inji Certify, whose flat credential template cannot
	// carry a nested `delegation` object): the capability is expressed as top-level
	// claims — onBehalfOf + allowedAction (+ validUntil). Recognised by allowedAction.
	if aa := flatClaim(c, "allowedAction", "allowed_action"); aa != "" {
		cap := Capability{
			Controller:    c.Issuer,
			OnBehalfOf:    firstNonEmpty(flatClaim(c, "onBehalfOf", "on_behalf_of"), refID(c.Raw["credentialSubject"], "onBehalfOf")),
			Delegate:      c.SubjectID,
			AllowedAction: splitActions(aa),
			ValidUntil:    flatClaim(c, "validUntil", "valid_until"),
		}
		return cap, true
	}
	return Capability{}, false
}

// flatClaim reads a top-level string claim from the decoded payload or the
// normalized claims map (SD-JWT flat claims may surface in either).
func flatClaim(c backend.NormalizedCredential, keys ...string) string {
	for _, k := range keys {
		if v := mapStr(c.Raw, k); v != "" {
			return v
		}
		if c.Claims != nil {
			if v := c.Claims[k]; v != "" {
				return v
			}
		}
	}
	return ""
}

// splitActions splits a comma/space-separated action list (the flat-claim
// encoding of allowedAction) into a slice.
func splitActions(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// subjectAnchor returns the stable, non-pairwise linkage anchor of an identity
// credential: an explicit subjectRef claim when present (per ADR Q6), else the
// credential subject id.
func subjectAnchor(c backend.NormalizedCredential) string {
	if cs, ok := asMap(c.Raw["credentialSubject"]); ok {
		if v := mapStr(cs, "subjectRef"); v != "" {
			return v
		}
	}
	if v := mapStr(c.Raw, "subjectRef"); v != "" {
		return v
	}
	if v := c.Claims["subjectRef"]; v != "" {
		return v
	}
	return c.SubjectID
}

// statusRef extracts a revocation pointer from a credential, supporting both the
// JSON-LD BitstringStatusListEntry and the SD-JWT IETF Token Status List shapes.
func statusRef(c backend.NormalizedCredential) (StatusRef, bool) {
	// Verifiably-hosted FLAT status (statusUri + statusIdx top-level claims) is
	// preferred when present: it is the delegation's OWN revocable, publicly
	// dereferenceable status list. Checked FIRST because Inji's auth-code Certify
	// also stamps a credentialStatus pointing at its INTERNAL status list
	// (certify-nginx) that the verifier can't reach and we don't control.
	if uri := flatClaim(c, "statusUri"); uri != "" {
		idx, _ := strconv.ParseInt(strings.TrimSpace(flatClaim(c, "statusIdx")), 10, 64)
		// statusType distinguishes the list kind so the checker decodes correctly:
		// bitstring (W3C VCDM, ldp_vc) vs the IETF Token Status List (SD-JWT).
		typ := "TokenStatusList"
		if strings.Contains(strings.ToLower(flatClaim(c, "statusType")), "bitstring") {
			typ = "BitstringStatusListEntry"
		}
		return StatusRef{Type: typ, URI: uri, Index: idx, Purpose: "revocation", Issuer: c.Issuer}, true
	}
	if cs, ok := asMap(c.Raw["credentialStatus"]); ok {
		return StatusRef{
			Type:    firstNonEmpty(mapStr(cs, "type"), "BitstringStatusListEntry"),
			URI:     mapStr(cs, "statusListCredential"),
			Index:   mapInt(cs, "statusListIndex"),
			Purpose: firstNonEmpty(mapStr(cs, "statusPurpose"), "revocation"),
			Issuer:  c.Issuer,
		}, true
	}
	if st, ok := asMap(c.Raw["status"]); ok {
		if sl, ok := asMap(st["status_list"]); ok {
			return StatusRef{
				Type:    "TokenStatusList",
				URI:     mapStr(sl, "uri"),
				Index:   mapInt(sl, "idx"),
				Purpose: "revocation",
				Issuer:  c.Issuer,
			}, true
		}
	}
	return StatusRef{}, false
}

// --- small helpers ---------------------------------------------------------

func sameRef(a, b string) bool { return strings.TrimSpace(a) == strings.TrimSpace(b) && a != "" }

func holderRef(h *backend.HolderBinding) string {
	if h == nil {
		return ""
	}
	if h.ID != "" {
		return h.ID
	}
	return h.KeyThumbprint
}

func primaryType(types []string) string {
	for _, t := range types {
		if !strings.EqualFold(t, "VerifiableCredential") {
			return t
		}
	}
	if len(types) > 0 {
		return types[0]
	}
	return ""
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised time %q", s)
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// refID returns the `id` of an object-valued field on a parent map, e.g.
// credentialSubject.onBehalfOf.id. parent may be a map[string]any.
func refID(parent any, field string) string {
	m, ok := asMap(parent)
	if !ok {
		return ""
	}
	switch v := m[field].(type) {
	case string:
		return v
	case map[string]any:
		return mapStr(v, "id")
	}
	return ""
}

func caveatValidUntil(v any) string {
	for _, c := range asSlice(v) {
		if m, ok := asMap(c); ok {
			if vu := mapStr(m, "validUntil"); vu != "" {
				return vu
			}
		}
	}
	return ""
}

func typeContains(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return strings.EqualFold(t, want)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && strings.EqualFold(s, want) {
				return true
			}
		}
	case []string:
		for _, s := range t {
			if strings.EqualFold(s, want) {
				return true
			}
		}
	}
	return false
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// asMapOrJSON returns v as a map whether it is already a map[string]any or a
// JSON-encoded object string (SD-JWT selective disclosure renders object claims
// as strings).
func asMapOrJSON(v any) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}
	if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			return m, true
		}
	}
	return nil, false
}

func asSlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		return []any{t} // a single object is treated as a one-element list
	}
	return nil
}

func mapStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// mapStrSlice reads the first present key as a []string, accepting a JSON array
// of strings or a single string.
func mapStrSlice(m map[string]any, keys ...string) []string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []any:
			out := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		case []string:
			return t
		case string:
			return []string{t}
		}
	}
	return nil
}

func mapBool(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// mapInt reads an integer that may arrive as a JSON number (float64),
// json.Number, or a string.
func mapInt(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	}
	return 0
}
