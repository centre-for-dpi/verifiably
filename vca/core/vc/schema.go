// SPDX-License-Identifier: Apache-2.0

package vc

import "strings"

// Schema describes a credential type an issuer can issue.
// Lifted from the legacy vctypes.Schema without the UI and vendor fields.
type Schema struct {
	ID     string
	Name   string
	Std    string // data model label, for example ModelVCDM2 or "sd_jwt_vc"
	Desc   string
	Custom bool // true for user built schemas

	// OwnerKey scopes a custom schema to the operator who saved it.
	OwnerKey string
	// IssuerDisplayName is the human readable issuer attribution.
	IssuerDisplayName string

	AdditionalTypes []string
	Fields          []FieldSpec

	// Expires marks a schema whose credentials carry a validity window.
	Expires bool

	// SourceIssuerDID and SourceDeployment identify where a federated
	// schema came from.
	SourceIssuerDID  string `json:"sourceIssuerDid,omitempty"`
	SourceDeployment string `json:"sourceDeployment,omitempty"`

	// Variants lists every wire format this type is available in.
	Variants []SchemaVariant
	// Vct is the SD-JWT VC type identifier of the selected variant.
	Vct string
}

// SchemaVariant is one wire format of a credential type.
type SchemaVariant struct {
	ID     string
	Format string // wire format key, for example "dc+sd-jwt"
	Std    string
	Label  string
	Vct    string
	// CanPresent is false when the backend can issue the format but its
	// verifier cannot request it.
	CanPresent bool
}

// FieldSpec describes one claim of a schema.
type FieldSpec struct {
	Name     string
	Datatype string // "string", "number", "integer" or "boolean"
	Format   string // optional: "date", "uri"
	Required bool
}

// PresentationTemplate is a preset presentation request.
type PresentationTemplate struct {
	Title          string
	Fields         []string
	Format         string // data model label
	Disclosure     string // plain language summary shown to the operator
	CredentialType string // type filter for VCDM requests
	Vct            string // vct filter for SD-JWT VC requests
	WireFormat     string // exact wire format key for the request
}

// HasVariantID reports whether id is the schema id or one of its variants.
func (s Schema) HasVariantID(id string) bool {
	if s.ID == id {
		return true
	}
	for _, v := range s.Variants {
		if v.ID == id {
			return true
		}
	}
	return false
}

// ApplyVariant returns a copy of s with ID, Std and Vct set from the
// variant named id. It returns s unchanged when no variant matches.
func (s Schema) ApplyVariant(id string) Schema {
	for _, v := range s.Variants {
		if v.ID == id {
			s.ID = v.ID
			s.Std = v.Std
			s.Vct = v.Vct
			return s
		}
	}
	return s
}

// formatSuffixes are the wire format suffixes a backend may append to a
// configuration id. Longer suffixes come first.
var formatSuffixes = []string{
	"_jwt_vc_json-ld", "_jwt_vp_json-ld", "_jwt_vc_json", "_jwt_vp_json",
	"_vc+sd-jwt", "_dc+sd-jwt", "_mso_mdoc", "_ldp_vc", "_ldp_vp", "_jwt_vc", "_jwt_vp",
}

// BaseType strips a known wire format suffix from the schema id.
func (s Schema) BaseType() string {
	for _, suf := range formatSuffixes {
		if strings.HasSuffix(s.ID, suf) {
			return strings.TrimSuffix(s.ID, suf)
		}
	}
	return s.ID
}

// CustomTypeName returns the credential type identifier of a custom
// schema: AdditionalTypes[0] when set, else the CamelCased Name.
func (s Schema) CustomTypeName() string {
	if len(s.AdditionalTypes) > 0 {
		if t := strings.TrimSpace(s.AdditionalTypes[0]); t != "" {
			return t
		}
	}
	return TypeName(s.Name)
}

// ExpiresWithWindow reports whether credentials of this schema carry a
// validity window. A legacy "valid_until" claim field also opts in.
func (s Schema) ExpiresWithWindow() bool {
	if s.Expires {
		return true
	}
	for _, f := range s.Fields {
		if strings.EqualFold(strings.TrimSpace(f.Name), "valid_until") {
			return true
		}
	}
	return false
}

// CredentialVct returns the SD-JWT VC vct of the schema: the explicit Vct
// when set, else "<publicBaseURL>/credentials/<ID>".
func (s Schema) CredentialVct(publicBaseURL string) string {
	if v := strings.TrimSpace(s.Vct); v != "" {
		return v
	}
	base := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if base == "" {
		base = "http://localhost:8080"
	}
	return base + "/credentials/" + s.ID
}

// TypeName CamelCases a human readable name into a type identifier.
// Letter runs are title cased and other characters are dropped.
// An empty result becomes "CustomCredential".
func TypeName(name string) string {
	var b strings.Builder
	capNext := true
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			capNext = false
		case r >= 'a' && r <= 'z':
			if capNext {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
			capNext = false
		default:
			capNext = true
		}
	}
	if b.Len() == 0 {
		return "CustomCredential"
	}
	return b.String()
}
