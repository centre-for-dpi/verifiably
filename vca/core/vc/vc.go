// SPDX-License-Identifier: Apache-2.0

// Package vc holds the format independent view of credentials and
// presentations, and detects the wire format of a credential.
//
// Standards covered by the normalised view:
//   - W3C Verifiable Credentials Data Model 2.0 (https://www.w3.org/TR/vc-data-model-2.0/)
//   - W3C VC Data Model 1.1 (https://www.w3.org/TR/vc-data-model/)
//   - IETF SD-JWT VC (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
//   - ISO/IEC 18013-5 mdoc (format detection only)
//
// Lifted from the legacy backend/normalized.go, internal/vp and vctypes.
package vc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
)

// Format is a credential wire format.
type Format string

// Known formats. The values follow the OpenID4VCI format identifiers.
const (
	FormatSDJWT   Format = "dc+sd-jwt"
	FormatJWT     Format = "jwt_vc_json"
	FormatJSONLD  Format = "ldp_vc"
	FormatMdoc    Format = "mso_mdoc"
	FormatJSON    Format = "json"
	FormatUnknown Format = ""
)

// Data model identifiers used in Credential.Format for decoded objects.
const (
	ModelVCDM2 = "w3c_vcdm_2"
	ModelVCDM1 = "w3c_vcdm_1"
)

// DetectFormat classifies raw credential bytes.
//
//	SD-JWT: a compact JWS followed by "~"
//	JWT:    three base64url segments separated by "."
//	JSON-LD: a JSON object with "@context"
//	JSON:   any other JSON object
//	mdoc:   a CBOR map or tag as the first byte (binary), or its base64url form
func DetectFormat(raw []byte) Format {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return FormatUnknown
	}
	if b[0] == '{' {
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return FormatUnknown
		}
		if _, ok := m["@context"]; ok {
			return FormatJSONLD
		}
		return FormatJSON
	}
	if isCBORMapOrTag(b[0]) {
		return FormatMdoc
	}
	s := string(b)
	if i := strings.IndexByte(s, '~'); i > 0 {
		if isCompactJWS(s[:i]) {
			return FormatSDJWT
		}
		return FormatUnknown
	}
	if isCompactJWS(s) {
		return FormatJWT
	}
	if dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil && len(dec) > 0 && isCBORMapOrTag(dec[0]) {
		return FormatMdoc
	}
	return FormatUnknown
}

func isCBORMapOrTag(b byte) bool {
	major := b >> 5
	return major == 5 || major == 6 // map or tag
}

func isCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for i, p := range parts {
		if p == "" && i != 2 {
			return false
		}
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return false
		}
	}
	_, err := jose.PeekHeader(s)
	return err == nil
}

// Credential is one credential from a presentation, in a format
// independent shape. Raw is the decoded credential object (a VCDM object
// or an SD-JWT payload with disclosures resolved). Claims is the
// stringified view for display and simple policy.
type Credential struct {
	Types     []string          // VCDM type array or the SD-JWT vct
	SubjectID string            // credentialSubject.id or sub
	Issuer    string            // issuer DID or URL
	Format    string            // ModelVCDM2, ModelVCDM1, FormatJWT or FormatSDJWT
	Claims    map[string]string // visible claims, nested values as JSON
	Raw       map[string]any    // decoded credential object
	// HostStatus is the backend verifier's per credential verdict, when any.
	HostStatus string
}

// HolderBinding describes the key the presenter proved control of.
type HolderBinding struct {
	ID            string // holder DID, when present
	KeyThumbprint string // JWK thumbprint of the cnf or holder key
	Confirmed     bool   // the verifier asserted the binding
}

// Presentation is the normalised view of a verified presentation.
type Presentation struct {
	Credentials []Credential
	Holder      *HolderBinding
}

// Check is one policy outcome shown on a credential card.
// Status is "pass", "fail" or "na".
type Check struct {
	Label  string
	Status string
	Note   string
}

// CredentialView is the per credential card of a presentation result.
// Role is "subject", "delegation" or "".
type CredentialView struct {
	Title      string
	Role       string
	Issuer     string
	Format     string
	HostStatus string
	Claims     map[string]string
	Checks     []Check
}

// reserved lists JWT and SD-JWT control claims that are not display claims.
var reserved = map[string]bool{
	"_sd": true, "_sd_alg": true, "cnf": true, "iss": true, "iat": true,
	"exp": true, "nbf": true, "sub": true, "vct": true, "status": true,
}

// FromObject normalises a decoded VCDM credential object. The object may
// be a JWT claim set that carries the credential under "vc".
func FromObject(obj map[string]any) Credential {
	inner, isObject := obj["vc"].(map[string]any)
	if !isObject || inner == nil {
		inner = obj
	}
	claims := map[string]string{}
	subject := ""
	if cs, ok := inner["credentialSubject"].(map[string]any); ok {
		if id, isString := cs["id"].(string); isString {
			subject = id
		}
		for k, v := range cs {
			if k != "id" {
				claims[k] = Stringify(v)
			}
		}
	}
	if subject == "" {
		subject = str(obj, "sub")
	}
	issuer := IssuerID(inner["issuer"])
	if issuer == "" {
		issuer = str(obj, "iss")
	}
	return Credential{
		Types:     AsStringSlice(inner["type"]),
		SubjectID: subject,
		Issuer:    issuer,
		Format:    modelOf(inner),
		Claims:    claims,
		Raw:       inner,
	}
}

// FromJWT decodes the payload of a compact VC-JWT without verification and
// normalises it. Callers verify the signature before they trust the result.
func FromJWT(tok string) (Credential, error) {
	payload, err := jose.PeekPayload(strings.TrimSpace(tok))
	if err != nil {
		return Credential{}, err
	}
	return FromObject(payload), nil
}

// FromSDJWT parses a compact SD-JWT without signature verification,
// resolves its disclosures and normalises the result. Disclosures that
// match no digest are rejected. Callers verify with core/sdjwt before
// they trust the result.
func FromSDJWT(tok string) (Credential, error) {
	p, err := sdjwt.Parse(tok)
	if err != nil {
		return Credential{}, err
	}
	payload, err := jose.PeekPayload(p.IssuerJWT)
	if err != nil {
		return Credential{}, err
	}
	resolved, err := sdjwt.Resolve(payload, p.Disclosures)
	if err != nil {
		return Credential{}, err
	}
	return FromResolvedSDJWT(resolved), nil
}

// FromResolvedSDJWT normalises an SD-JWT payload whose disclosures are
// already resolved, for example the Claims of a core/sdjwt Result.
func FromResolvedSDJWT(resolved map[string]any) Credential {
	claims := map[string]string{}
	for k, v := range resolved {
		if !reserved[k] {
			claims[k] = Stringify(v)
		}
	}
	var types []string
	if vct := str(resolved, "vct"); vct != "" {
		types = []string{vct}
	}
	return Credential{
		Types:     types,
		SubjectID: str(resolved, "sub"),
		Issuer:    str(resolved, "iss"),
		Format:    string(FormatSDJWT),
		Claims:    claims,
		Raw:       resolved,
	}
}

// Parse detects the format of raw and normalises it. mdoc is not decoded.
func Parse(raw []byte) (Credential, error) {
	switch DetectFormat(raw) {
	case FormatSDJWT:
		return FromSDJWT(string(raw))
	case FormatJWT:
		return FromJWT(string(raw))
	case FormatJSONLD, FormatJSON:
		var m map[string]any
		// DetectFormat already parsed these bytes, so err is always nil.
		err := json.Unmarshal(bytes.TrimSpace(raw), &m)
		return FromObject(m), err
	case FormatMdoc:
		return Credential{}, fmt.Errorf("vc: mdoc credentials are not decoded by this package")
	}
	return Credential{}, fmt.Errorf("vc: unknown credential format")
}

// PrimaryType returns the first type that is not "VerifiableCredential".
func (c Credential) PrimaryType() string {
	for _, t := range c.Types {
		if !strings.EqualFold(t, "VerifiableCredential") {
			return t
		}
	}
	if len(c.Types) > 0 {
		return c.Types[0]
	}
	return ""
}

// TemporalBounds returns the validity window read from Raw:
// VCDM 2.0 validFrom and validUntil, VCDM 1.1 issuanceDate and
// expirationDate, JWT nbf and exp, and the flat valid_from and
// valid_until convention. A zero time means no bound on that side.
func (c Credential) TemporalBounds() (notBefore, notAfter time.Time) {
	notBefore = firstTime(c.Raw, "validFrom", "issuanceDate", "nbf", "valid_from")
	notAfter = firstTime(c.Raw, "validUntil", "expirationDate", "exp", "valid_until")
	// A VCDM credential may carry the flat policy keys inside
	// credentialSubject. Only the underscore keys are read there, so a
	// subject's own date attribute never bounds the credential.
	if notBefore.IsZero() {
		notBefore = subjectTime(c.Raw, "valid_from")
	}
	if notAfter.IsZero() {
		notAfter = subjectTime(c.Raw, "valid_until")
	}
	return notBefore, notAfter
}

func subjectTime(raw map[string]any, key string) time.Time {
	cs, ok := raw["credentialSubject"].(map[string]any)
	if !ok {
		return time.Time{}
	}
	return firstTime(cs, key)
}

func firstTime(raw map[string]any, keys ...string) time.Time {
	for _, k := range keys {
		switch t := raw[k].(type) {
		case string:
			if ts, err := time.Parse(time.RFC3339, t); err == nil {
				return ts.UTC()
			}
		case float64:
			if t > 0 {
				return time.Unix(int64(t), 0).UTC()
			}
		}
	}
	return time.Time{}
}

// IssuerID returns the issuer identifier from a string or an object with id.
func IssuerID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		return str(t, "id")
	}
	return ""
}

// AsStringSlice coerces a string, []any of strings or []string to []string.
func AsStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
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
	}
	return nil
}

// Stringify renders a claim value: scalars as text, structures as JSON.
func Stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case float64, bool:
		return fmt.Sprintf("%v", t)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func str(m map[string]any, key string) string {
	s, isString := m[key].(string)
	if !isString {
		return ""
	}
	return s
}

func modelOf(obj map[string]any) string {
	for _, c := range AsStringSlice(obj["@context"]) {
		if strings.Contains(c, "/ns/credentials/v2") {
			return ModelVCDM2
		}
		if strings.Contains(c, "/2018/credentials/v1") {
			return ModelVCDM1
		}
	}
	return string(FormatJWT)
}
