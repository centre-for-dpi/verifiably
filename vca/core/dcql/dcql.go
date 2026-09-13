// SPDX-License-Identifier: Apache-2.0

// Package dcql is the typed model of a Digital Credentials Query Language
// query (ADR-022 decision 3). OpenID for Verifiable Presentations 1.0
// defines DCQL in the section "Digital Credentials Query Language".
//
// A query holds credential queries. Each credential query names a format,
// the metadata that selects the credential type, and the claims the
// verifier asks for. Credential sets say which combinations satisfy the
// request.
//
// The package is pure. It parses, builds, validates, and serialises a
// query. It never performs input or output.
package dcql

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Format identifiers of OpenID for Verifiable Credential Issuance 1.0.
const (
	FormatSDJWTLegacy = "vc+sd-jwt"
	FormatSDJWT       = "dc+sd-jwt"
	FormatJWTVCJSON   = "jwt_vc_json"
	FormatLDPVC       = "ldp_vc"
	FormatMdoc        = "mso_mdoc"
)

// Formats lists every format the package accepts.
var Formats = []string{FormatSDJWTLegacy, FormatSDJWT, FormatJWTVCJSON, FormatLDPVC, FormatMdoc}

// MdocNamespace is the namespace of an ISO/IEC 18013-5 mobile document.
const MdocNamespace = "org.iso.18013.5.1"

// Query is a complete DCQL query.
type Query struct {
	// Credentials holds one entry for each credential the verifier asks
	// for. The list has at least one entry.
	Credentials []CredentialQuery `json:"credentials"`
	// CredentialSets says which combinations satisfy the request. An
	// empty list means the wallet must return every credential.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// CredentialQuery asks for one credential.
type CredentialQuery struct {
	// ID names the query. It is unique in the query.
	ID string `json:"id"`
	// Format is the credential format, for example dc+sd-jwt.
	Format string `json:"format"`
	// Multiple allows more than one matching credential in the response.
	Multiple bool `json:"multiple,omitempty"`
	// Meta selects the credential type. The fields depend on the format.
	Meta *Meta `json:"meta,omitempty"`
	// TrustedAuthorities limits the issuers the wallet may use.
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty"`
	// RequireCryptographicHolderBinding asks for a key bound credential.
	// Nil means the default of the specification, which is true.
	RequireCryptographicHolderBinding *bool `json:"require_cryptographic_holder_binding,omitempty"`
	// Claims lists the claims the verifier asks for. An empty list asks
	// for every claim of the credential.
	Claims []ClaimQuery `json:"claims,omitempty"`
	// ClaimSets lists the acceptable combinations of claim ids, in order
	// of preference.
	ClaimSets [][]string `json:"claim_sets,omitempty"`
}

// Meta selects the credential type inside one format.
type Meta struct {
	// VctValues lists the accepted vct values of an SD-JWT VC.
	VctValues []string `json:"vct_values,omitempty"`
	// TypeValues lists the accepted type combinations of a W3C
	// credential. Each inner list is one acceptable set of types.
	TypeValues [][]string `json:"type_values,omitempty"`
	// DoctypeValue is the accepted doctype of a mobile document.
	DoctypeValue string `json:"doctype_value,omitempty"`
}

// Empty reports whether the metadata selects nothing.
func (m *Meta) Empty() bool {
	if m == nil {
		return true
	}
	return len(m.VctValues) == 0 && len(m.TypeValues) == 0 && m.DoctypeValue == ""
}

// TrustedAuthority names an accepted issuer authority.
type TrustedAuthority struct {
	// Type is the authority type, for example aki, etsi_tl, or openid_federation.
	Type string `json:"type"`
	// Values holds the accepted authority values.
	Values []string `json:"values"`
}

// Authority types of OpenID for Verifiable Presentations 1.0.
const (
	AuthorityAKI              = "aki"
	AuthorityETSITrustedList  = "etsi_tl"
	AuthorityOpenIDFederation = "openid_federation"
)

// ClaimQuery asks for one claim.
type ClaimQuery struct {
	// ID names the claim inside the credential query. It is required
	// when the credential query has claim sets.
	ID string `json:"id,omitempty"`
	// Path points at the claim in the credential.
	Path Path `json:"path"`
	// Values limits the accepted claim values.
	Values []any `json:"values,omitempty"`
}

// CredentialSetQuery is one acceptable combination of credential queries.
type CredentialSetQuery struct {
	// Options lists the acceptable id combinations, in order of preference.
	Options [][]string `json:"options"`
	// Required says whether the wallet must satisfy the set. Nil means
	// the default of the specification, which is true.
	Required *bool `json:"required,omitempty"`
	// Purpose is the reason the verifier gives for the set.
	Purpose string `json:"purpose,omitempty"`
}

// IsRequired reports whether the set is required.
func (c CredentialSetQuery) IsRequired() bool { return c.Required == nil || *c.Required }

// Kind names the sort of one path segment.
type Kind int

const (
	// KindName selects a member of an object by name.
	KindName Kind = iota
	// KindIndex selects one element of an array by position.
	KindIndex
	// KindAll selects every element of an array.
	KindAll
)

// Segment is one element of a claims path.
type Segment struct {
	// Kind names the sort of the segment.
	Kind Kind
	// Name is the member name when Kind is KindName.
	Name string
	// Index is the array position when Kind is KindIndex.
	Index int
}

// Name returns a member segment.
func Name(name string) Segment { return Segment{Kind: KindName, Name: name} }

// Index returns an array position segment.
func Index(i int) Segment { return Segment{Kind: KindIndex, Index: i} }

// All returns the segment that selects every element of an array.
func All() Segment { return Segment{Kind: KindAll} }

// String returns the segment as text. An index becomes [n] and the all
// segment becomes [].
func (s Segment) String() string {
	switch s.Kind {
	case KindIndex:
		return "[" + strconv.Itoa(s.Index) + "]"
	case KindAll:
		return "[]"
	default:
		return s.Name
	}
}

// MarshalJSON writes the segment as a string, a number, or null.
func (s Segment) MarshalJSON() ([]byte, error) {
	switch s.Kind {
	case KindIndex:
		return json.Marshal(s.Index)
	case KindAll:
		return []byte("null"), nil
	default:
		return json.Marshal(s.Name)
	}
}

// UnmarshalJSON reads a string, a number, or null.
func (s *Segment) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "null" {
		*s = All()
		return nil
	}
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		*s = Name(name)
		return nil
	}
	var index int
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("dcql: a path segment must be a string, a number, or null, got %s", text)
	}
	*s = Index(index)
	return nil
}

// Path points at a claim inside a credential.
type Path []Segment

// ParsePath reads a dotted path such as address.street or list[0].name.
// The segment [] selects every element of an array.
func ParsePath(text string) (Path, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("dcql: the claim path is empty")
	}
	var out Path
	for _, part := range strings.Split(text, ".") {
		name, rest, err := splitBrackets(part)
		if err != nil {
			return nil, err
		}
		if name != "" {
			out = append(out, Name(name))
		}
		out = append(out, rest...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dcql: the claim path %q has no segment", text)
	}
	return out, nil
}

// splitBrackets splits one dotted part into its name and its brackets.
func splitBrackets(part string) (string, Path, error) {
	open := strings.IndexByte(part, '[')
	if open < 0 {
		if strings.ContainsAny(part, "]") {
			return "", nil, fmt.Errorf("dcql: the claim path part %q has a stray bracket", part)
		}
		return part, nil, nil
	}
	name := part[:open]
	var out Path
	for rest := part[open:]; rest != ""; {
		if rest[0] != '[' {
			return "", nil, fmt.Errorf("dcql: the claim path part %q is not valid", part)
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", nil, fmt.Errorf("dcql: the claim path part %q has an unclosed bracket", part)
		}
		inner := rest[1:end]
		switch {
		case inner == "":
			out = append(out, All())
		default:
			i, err := strconv.Atoi(inner)
			if err != nil || i < 0 {
				return "", nil, fmt.Errorf("dcql: the array index %q of %q must be a whole number that is zero or more", inner, part)
			}
			out = append(out, Index(i))
		}
		rest = rest[end+1:]
	}
	return name, out, nil
}

// String returns the path as a dotted path.
func (p Path) String() string {
	var b strings.Builder
	for _, s := range p {
		if s.Kind == KindName && b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s.String())
	}
	return b.String()
}

// JSONPath returns the path as a JSONPath expression, as Presentation
// Exchange 2.0 needs it.
func (p Path) JSONPath(prefix string) string {
	var b strings.Builder
	b.WriteString("$")
	if prefix != "" {
		b.WriteString("." + prefix)
	}
	for _, s := range p {
		switch s.Kind {
		case KindIndex:
			b.WriteString("[" + strconv.Itoa(s.Index) + "]")
		case KindAll:
			b.WriteString("[*]")
		default:
			b.WriteString("." + s.Name)
		}
	}
	return b.String()
}

// Parse reads a DCQL query from JSON and validates it. It ignores
// members the model does not know, as the specification asks.
func Parse(data []byte) (Query, error) {
	var q Query
	if err := json.Unmarshal(data, &q); err != nil {
		return Query{}, fmt.Errorf("dcql: read the query: %w", err)
	}
	if err := Validate(q); err != nil {
		return Query{}, err
	}
	return q, nil
}

// Marshal validates the query and writes it as JSON.
func Marshal(q Query) ([]byte, error) {
	if err := Validate(q); err != nil {
		return nil, err
	}
	return json.Marshal(q)
}

// IDs returns the credential query ids in order.
func (q Query) IDs() []string {
	out := make([]string, 0, len(q.Credentials))
	for _, c := range q.Credentials {
		out = append(out, c.ID)
	}
	return out
}

// Find returns the credential query with the id.
func (q Query) Find(id string) (CredentialQuery, bool) {
	for _, c := range q.Credentials {
		if c.ID == id {
			return c, true
		}
	}
	return CredentialQuery{}, false
}

// Type returns the credential type the query selects. It reads the vct,
// the last W3C type, or the doctype, whichever the format uses.
func (c CredentialQuery) Type() string {
	if c.Meta == nil {
		return ""
	}
	if len(c.Meta.VctValues) > 0 {
		return c.Meta.VctValues[0]
	}
	if len(c.Meta.TypeValues) > 0 {
		types := c.Meta.TypeValues[0]
		if len(types) > 0 {
			return types[len(types)-1]
		}
	}
	return c.Meta.DoctypeValue
}

// ClaimPaths returns the dotted claim paths of the credential query.
func (c CredentialQuery) ClaimPaths() []string {
	out := make([]string, 0, len(c.Claims))
	for _, cl := range c.Claims {
		out = append(out, cl.Path.String())
	}
	return out
}

// Selection describes one credential a verifier asks for. The portal
// builds it from the pages and Build turns it into a query.
type Selection struct {
	// ID names the credential query. Build cleans it.
	ID string
	// Format is the credential format.
	Format string
	// Type is the vct, the W3C type, or the mdoc doctype.
	Type string
	// Claims holds the dotted claim paths.
	Claims []string
	// Issuers limits the accepted issuers. Empty accepts every trusted
	// issuer.
	Issuers []string
	// Optional makes the credential optional in the credential set.
	Optional bool
}

// Build turns selections into a query. purpose is the reason the verifier
// shows the citizen. Build validates the result.
func Build(selections []Selection, purpose string) (Query, error) {
	if len(selections) == 0 {
		return Query{}, fmt.Errorf("dcql: the request selects no credential")
	}
	var q Query
	var required, optional []string
	for i, sel := range selections {
		c, err := buildCredential(sel, i)
		if err != nil {
			return Query{}, err
		}
		q.Credentials = append(q.Credentials, c)
		if sel.Optional {
			optional = append(optional, c.ID)
			continue
		}
		required = append(required, c.ID)
	}
	no := false
	if len(required) > 0 {
		q.CredentialSets = append(q.CredentialSets, CredentialSetQuery{Options: [][]string{required}, Purpose: purpose})
	}
	for _, id := range optional {
		q.CredentialSets = append(q.CredentialSets, CredentialSetQuery{Options: [][]string{{id}}, Required: &no, Purpose: purpose})
	}
	if err := Validate(q); err != nil {
		return Query{}, err
	}
	return q, nil
}

// buildCredential turns one selection into a credential query.
func buildCredential(sel Selection, position int) (CredentialQuery, error) {
	id := CleanID(sel.ID)
	if id == "" {
		id = CleanID(sel.Type)
	}
	if id == "" {
		id = "credential" + strconv.Itoa(position+1)
	}
	c := CredentialQuery{ID: id, Format: sel.Format, Meta: metaFor(sel.Format, sel.Type)}
	for _, value := range sel.Claims {
		path, err := parseClaim(sel.Format, value)
		if err != nil {
			return CredentialQuery{}, err
		}
		c.Claims = append(c.Claims, ClaimQuery{ID: CleanID(path.String()), Path: path})
	}
	if len(sel.Issuers) > 0 {
		c.TrustedAuthorities = []TrustedAuthority{{Type: AuthorityETSITrustedList, Values: sel.Issuers}}
	}
	return c, nil
}

// parseClaim reads one selected claim. A mobile document claim needs a
// namespace and a name, so the last dot splits the two. Every other
// format reads a dotted path.
func parseClaim(format, value string) (Path, error) {
	if format != FormatMdoc {
		return ParsePath(value)
	}
	value = strings.TrimSpace(value)
	namespace, name := MdocNamespace, value
	if cut := strings.LastIndex(value, "."); cut > 0 {
		namespace, name = value[:cut], value[cut+1:]
	}
	if name == "" {
		return nil, fmt.Errorf("dcql: the mdoc claim %q has no name", value)
	}
	return Path{Name(namespace), Name(name)}, nil
}

// metaFor returns the metadata of one format and type.
func metaFor(format, credentialType string) *Meta {
	if credentialType == "" {
		return nil
	}
	switch format {
	case FormatSDJWT, FormatSDJWTLegacy:
		return &Meta{VctValues: []string{credentialType}}
	case FormatMdoc:
		return &Meta{DoctypeValue: credentialType}
	default:
		return &Meta{TypeValues: [][]string{{"VerifiableCredential", credentialType}}}
	}
}

// CleanID turns text into an id the syntax rules accept. It keeps
// letters, digits, the underscore, and the hyphen, and turns every other
// character into an underscore.
func CleanID(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
