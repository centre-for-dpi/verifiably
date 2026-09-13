// SPDX-License-Identifier: Apache-2.0

package delegation

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// findDelegation returns the index of the first credential that carries a
// capability. It returns -1 when none does.
func findDelegation(creds []vc.Credential) (int, Capability) {
	for i, c := range creds {
		if cap, ok := ExtractCapability(c); ok {
			return i, cap
		}
	}
	return -1, Capability{}
}

// findIdentity picks the subject identity credential: the first non
// delegation credential whose anchor matches onBehalfOf, else the first
// non delegation credential.
func findIdentity(creds []vc.Credential, delegIdx int, onBehalfOf string) (int, vc.Credential, bool) {
	firstIdx := -1
	for i := range creds {
		if i == delegIdx {
			continue
		}
		if firstIdx < 0 {
			firstIdx = i
		}
		if onBehalfOf != "" && sameRef(subjectAnchor(creds[i]), onBehalfOf) {
			return i, creds[i], true
		}
	}
	if firstIdx >= 0 {
		return firstIdx, creds[firstIdx], true
	}
	return -1, vc.Credential{}, false
}

// ExtractCapability reads the capability from the SD-JWT "delegation"
// claim, a JSON-LD termsOfUse entry of type DelegationCapability, or the
// flat claim form (allowedAction plus onBehalfOf). ok is false when the
// credential carries no capability.
func ExtractCapability(c vc.Credential) (Capability, bool) {
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
	for _, tou := range asSlice(c.Raw["termsOfUse"]) {
		m, ok := tou.(map[string]any)
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
	if aa := flatClaim(c, "allowedAction", "allowed_action"); aa != "" {
		return Capability{
			Controller:    c.Issuer,
			OnBehalfOf:    firstNonEmpty(flatClaim(c, "onBehalfOf", "on_behalf_of"), refID(c.Raw["credentialSubject"], "onBehalfOf")),
			Delegate:      c.SubjectID,
			AllowedAction: splitActions(aa),
			ValidUntil:    flatClaim(c, "validUntil", "valid_until"),
		}, true
	}
	return Capability{}, false
}

// flatClaim reads a top level string claim from Raw or Claims.
func flatClaim(c vc.Credential, keys ...string) string {
	for _, k := range keys {
		if v := mapStr(c.Raw, k); v != "" {
			return v
		}
		if v := c.Claims[k]; v != "" {
			return v
		}
	}
	return ""
}

// splitActions splits a comma or space separated action list.
func splitActions(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

// subjectAnchor returns the stable linkage anchor of an identity
// credential: subjectRef when present, else the subject id.
func subjectAnchor(c vc.Credential) string {
	if cs, ok := c.Raw["credentialSubject"].(map[string]any); ok {
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

// subjectIdentifiers lists the unique identifiers of an identity
// credential: subjectRef, subject DID and identifier named fields.
// Names and other attributes are not linkage anchors.
func subjectIdentifiers(c vc.Credential) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if cs, ok := c.Raw["credentialSubject"].(map[string]any); ok {
		add(mapStr(cs, "subjectRef"))
	}
	add(mapStr(c.Raw, "subjectRef"))
	add(c.Claims["subjectRef"])
	add(c.SubjectID)
	for k, v := range c.Claims {
		if isIdentifierFieldName(k) {
			add(v)
		}
	}
	return out
}

// isIdentifierFieldName reports whether a field name denotes a unique
// identifier: an explicit id token or an id, number or ref suffix.
func isIdentifierFieldName(name string) bool {
	n := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(name))
	switch n {
	case "subjectref", "id", "identifier", "uin", "nin", "did", "msisdn":
		return true
	}
	return strings.HasSuffix(n, "id") || strings.HasSuffix(n, "number") || strings.HasSuffix(n, "ref")
}

func subjectIdentifies(c vc.Credential, onBehalfOf string) bool {
	for _, id := range subjectIdentifiers(c) {
		if sameRef(id, onBehalfOf) {
			return true
		}
	}
	return false
}

// StatusRefOf extracts the status pointer of a credential: the flat
// statusUri and statusIdx claims, a credentialStatus object, or the
// SD-JWT status.status_list claim.
func StatusRefOf(c vc.Credential) (StatusRef, bool) {
	if uri := flatClaim(c, "statusUri"); uri != "" {
		idx, _ := strconv.ParseInt(strings.TrimSpace(flatClaim(c, "statusIdx")), 10, 64)
		typ := "TokenStatusList"
		if strings.Contains(strings.ToLower(flatClaim(c, "statusType")), "bitstring") {
			typ = "BitstringStatusListEntry"
		}
		return StatusRef{Type: typ, URI: uri, Index: idx, Purpose: "revocation", Issuer: c.Issuer}, true
	}
	if cs, ok := c.Raw["credentialStatus"].(map[string]any); ok {
		return StatusRef{
			Type:    firstNonEmpty(mapStr(cs, "type"), "BitstringStatusListEntry"),
			URI:     mapStr(cs, "statusListCredential"),
			Index:   mapInt(cs, "statusListIndex"),
			Purpose: firstNonEmpty(mapStr(cs, "statusPurpose"), "revocation"),
			Issuer:  c.Issuer,
		}, true
	}
	if st, ok := c.Raw["status"].(map[string]any); ok {
		if sl, ok := st["status_list"].(map[string]any); ok {
			return StatusRef{
				Type: "TokenStatusList", URI: mapStr(sl, "uri"), Index: mapInt(sl, "idx"),
				Purpose: "revocation", Issuer: c.Issuer,
			}, true
		}
	}
	return StatusRef{}, false
}

func sameRef(a, b string) bool { return strings.TrimSpace(a) == strings.TrimSpace(b) && a != "" }

func holderRef(h *vc.HolderBinding) string {
	if h.ID != "" {
		return h.ID
	}
	return h.KeyThumbprint
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("delegation: unrecognised time %q", s)
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

// refID returns parent[field] as a string or parent[field].id.
func refID(parent any, field string) string {
	m, ok := parent.(map[string]any)
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
		if m, ok := c.(map[string]any); ok {
			if vu := mapStr(m, "validUntil"); vu != "" {
				return vu
			}
		}
	}
	return ""
}

func typeContains(v any, want string) bool {
	for _, s := range vc.AsStringSlice(v) {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// asMapOrJSON returns v as a map when it is a map or a JSON object string.
func asMapOrJSON(v any) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}
	if s, ok := v.(string); ok {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil && m != nil {
			return m, true
		}
	}
	return nil, false
}

// asSlice returns v as a list. A single object is a one element list.
func asSlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		return []any{t}
	}
	return nil
}

func mapStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// mapStrSlice reads the first present key as a string list.
func mapStrSlice(m map[string]any, keys ...string) []string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return vc.AsStringSlice(v)
		}
	}
	return nil
}

func mapBool(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// mapInt reads an integer that may be a JSON number or a string.
func mapInt(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	}
	return 0
}
