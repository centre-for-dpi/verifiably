// SPDX-License-Identifier: Apache-2.0

// Package catalog holds the records of the crawled catalogue and the
// pure readers that build them (ADR-022 decisions 1, 2, and 5).
//
// One reader turns the OpenID4VCI credential issuer metadata into
// credential type records. Another reader turns a published JSON Schema
// into field records. Both readers are pure: they take bytes and return
// records.
package catalog

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
)

// MetadataPath is the well known path of the issuer metadata.
const MetadataPath = "/.well-known/openid-credential-issuer"

// SchemasPath is the path of the published schema list of a VCA issuer.
const SchemasPath = "/api/schemas"

// Issuer is one crawled issuer.
type Issuer struct {
	// CredentialIssuer is the issuer URL of the metadata.
	CredentialIssuer string `json:"credential_issuer"`
	// DID is the issuer identifier of the trust list.
	DID string `json:"did,omitempty"`
	// DisplayName is the name the pages show.
	DisplayName string `json:"display_name,omitempty"`
	// Trust is the trust outcome at the time of the crawl.
	Trust string `json:"trust,omitempty"`
	// Types holds the credential types of the issuer.
	Types []CredentialType `json:"types,omitempty"`
	// CrawledAt is the time of the last successful crawl.
	CrawledAt time.Time `json:"crawled_at"`
	// LastError is the error of the last crawl, when it failed.
	LastError string `json:"last_error,omitempty"`
}

// CredentialType is one type an issuer offers.
type CredentialType struct {
	// Type is the vct of an SD-JWT VC or the last VCDM type name.
	Type string `json:"type"`
	// ConfigurationID is the OpenID4VCI configuration id.
	ConfigurationID string `json:"configuration_id"`
	// Format is the wire format identifier, for example dc+sd-jwt.
	Format string `json:"format"`
	// Display holds the display metadata of the type.
	Display []Display `json:"display,omitempty"`
	// SchemaID is the schema id at the issuer, when it publishes one.
	SchemaID string `json:"schema_id,omitempty"`
	// SchemaVersion is the schema version at the issuer.
	SchemaVersion int32 `json:"schema_version,omitempty"`
	// Fields holds the claims of the type.
	Fields []Field `json:"fields,omitempty"`
	// JSONSchema is the JSON Schema document the fields came from.
	JSONSchema string `json:"json_schema,omitempty"`
}

// Display is the display metadata of a credential type.
type Display struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	Locale          string `json:"locale,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// Field is one claim of a credential type.
type Field struct {
	// Path is the claim path, for example given_name or address.street.
	Path string `json:"path"`
	// Type is the JSON Schema type.
	Type string `json:"type,omitempty"`
	// Format is the JSON Schema format, when any.
	Format string `json:"format,omitempty"`
	// Title is the title of the claim, when any.
	Title string `json:"title,omitempty"`
	// Mandatory reports that the schema lists the claim as required.
	Mandatory bool `json:"mandatory,omitempty"`
	// SelectivelyDisclosable reports that the holder can disclose the
	// claim on its own.
	SelectivelyDisclosable bool `json:"selectively_disclosable,omitempty"`
}

// Trust outcome names the catalogue stores.
const (
	TrustUnspecified = ""
	TrustTrusted     = "trusted"
	TrustUntrusted   = "untrusted"
	TrustUnknown     = "unknown"
	TrustUnavailable = "unavailable"
)

// TrustName returns the catalogue name of a trust lookup outcome.
func TrustName(outcome trustv1.TrustLookupResponse_Outcome) string {
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return TrustTrusted
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return TrustUntrusted
	case trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:
		return TrustUnknown
	case trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE:
		return TrustUnavailable
	}
	return TrustUnspecified
}

// TrustOutcome returns the lookup outcome of a catalogue name.
func TrustOutcome(name string) trustv1.TrustLookupResponse_Outcome {
	switch name {
	case TrustTrusted:
		return trustv1.TrustLookupResponse_OUTCOME_TRUSTED
	case TrustUntrusted:
		return trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED
	case TrustUnknown:
		return trustv1.TrustLookupResponse_OUTCOME_UNKNOWN
	case TrustUnavailable:
		return trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE
	}
	return trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED
}

// FormatOf returns the proto format of a format identifier.
func FormatOf(name string) commonv1.Format {
	switch name {
	case "vc+sd-jwt":
		return commonv1.Format_FORMAT_VC_SD_JWT
	case "dc+sd-jwt":
		return commonv1.Format_FORMAT_DC_SD_JWT
	case "jwt_vc_json":
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case "ldp_vc":
		return commonv1.Format_FORMAT_LDP_VC
	case "mso_mdoc":
		return commonv1.Format_FORMAT_MSO_MDOC
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// FormatName returns the format identifier of a proto format.
func FormatName(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt"
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return "dc+sd-jwt"
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return "jwt_vc_json"
	case commonv1.Format_FORMAT_LDP_VC:
		return "ldp_vc"
	case commonv1.Format_FORMAT_MSO_MDOC:
		return "mso_mdoc"
	}
	return ""
}

// Name returns the display name of an issuer, or its URL.
func (i Issuer) Name() string {
	if i.DisplayName != "" {
		return i.DisplayName
	}
	return i.CredentialIssuer
}

// Find returns the credential type with the type name.
func (i Issuer) Find(typeName string) (CredentialType, bool) {
	for _, t := range i.Types {
		if t.Type == typeName {
			return t, true
		}
	}
	return CredentialType{}, false
}

// Name returns the first display name of a type, or the type name.
func (t CredentialType) Name() string {
	if len(t.Display) > 0 && t.Display[0].Name != "" {
		return t.Display[0].Name
	}
	return t.Type
}

// ToProto turns an issuer record into its proto message.
func (i Issuer) ToProto() *discoveryv1.Issuer {
	out := &discoveryv1.Issuer{
		CredentialIssuer: i.CredentialIssuer,
		Did:              i.DID,
		DisplayName:      i.DisplayName,
		Trust:            TrustOutcome(i.Trust),
		TypeCount:        toInt32(int64(len(i.Types))),
		LastError:        i.LastError,
	}
	if !i.CrawledAt.IsZero() {
		out.CrawledAt = timestamppb.New(i.CrawledAt)
	}
	return out
}

// ToProto turns a credential type record into its proto message.
func (t CredentialType) ToProto(issuer string) *discoveryv1.CredentialType {
	out := &discoveryv1.CredentialType{
		CredentialIssuer: issuer,
		Type:             t.Type,
		ConfigurationId:  t.ConfigurationID,
		Format:           FormatOf(t.Format),
		SchemaId:         t.SchemaID,
		SchemaVersion:    t.SchemaVersion,
	}
	for _, d := range t.Display {
		out.Display = append(out.Display, &schemav1.Display{
			Name: d.Name, Description: d.Description, Locale: d.Locale,
			LogoUri: d.LogoURI, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
		})
	}
	return out
}

// ToProto turns a field record into its proto message.
func (f Field) ToProto() *discoveryv1.Field {
	return &discoveryv1.Field{
		Path: f.Path, Type: f.Type, Format: f.Format, Title: f.Title,
		Mandatory: f.Mandatory, SelectivelyDisclosable: f.SelectivelyDisclosable,
	}
}

// metadata is the part of the issuer metadata the crawler reads.
type metadata struct {
	CredentialIssuer              string                     `json:"credential_issuer"`
	Display                       []Display                  `json:"display"`
	CredentialConfigurationsSuppo map[string]json.RawMessage `json:"credential_configurations_supported"`
	CredentialsSupported          map[string]json.RawMessage `json:"credentials_supported"`
}

// configuration is one credential configuration of the metadata.
type configuration struct {
	Format                 string          `json:"format"`
	Vct                    string          `json:"vct"`
	Scope                  string          `json:"scope"`
	Doctype                string          `json:"doctype"`
	Display                []Display       `json:"display"`
	CredentialDefinition   json.RawMessage `json:"credential_definition"`
	CredentialSchemaID     string          `json:"credential_schema_id"`
	CredentialSchemaVersio int32           `json:"credential_schema_version"`
}

// definition is the credential definition of a W3C configuration.
type definition struct {
	Type []string `json:"type"`
}

// ReadMetadata reads the OpenID4VCI credential issuer metadata. It
// returns the issuer URL, the display metadata, and the credential
// types in a stable order.
func ReadMetadata(data []byte) (string, []Display, []CredentialType, error) {
	var m metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return "", nil, nil, fmt.Errorf("catalog: read the issuer metadata: %w", err)
	}
	configs := m.CredentialConfigurationsSuppo
	if len(configs) == 0 {
		configs = m.CredentialsSupported
	}
	ids := make([]string, 0, len(configs))
	for id := range configs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var types []CredentialType
	for _, id := range ids {
		t, ok := readConfiguration(id, configs[id])
		if !ok {
			continue
		}
		types = append(types, t)
	}
	return m.CredentialIssuer, m.Display, types, nil
}

// readConfiguration turns one credential configuration into a record.
func readConfiguration(id string, raw json.RawMessage) (CredentialType, bool) {
	var c configuration
	if json.Unmarshal(raw, &c) != nil {
		return CredentialType{}, false
	}
	t := CredentialType{
		ConfigurationID: id, Format: c.Format, Display: c.Display,
		SchemaID: c.CredentialSchemaID, SchemaVersion: c.CredentialSchemaVersio,
	}
	t.Type = typeNameOf(c, id)
	if t.Type == "" || t.Format == "" {
		return CredentialType{}, false
	}
	return t, true
}

// typeNameOf reads the credential type of one configuration.
func typeNameOf(c configuration, id string) string {
	if c.Vct != "" {
		return c.Vct
	}
	if c.Doctype != "" {
		return c.Doctype
	}
	if len(c.CredentialDefinition) > 0 {
		var d definition
		if json.Unmarshal(c.CredentialDefinition, &d) == nil && len(d.Type) > 0 {
			return d.Type[len(d.Type)-1]
		}
	}
	if c.Scope != "" {
		return c.Scope
	}
	return id
}

// schemaList is the published schema list of a VCA issuer.
type schemaList struct {
	Schemas []publishedSchema `json:"schemas"`
}

// publishedSchema is one entry of the published schema list.
type publishedSchema struct {
	ID         string          `json:"id"`
	Version    int32           `json:"version"`
	Type       string          `json:"type"`
	Vct        string          `json:"vct"`
	Formats    []string        `json:"formats"`
	Display    []Display       `json:"display"`
	JSONSchema json.RawMessage `json:"json_schema"`
}

// ReadSchemas reads the published schema list of an issuer. It returns
// the fields and the schema document of each credential type it names.
// The list is either a bare array or an object with a schemas member.
func ReadSchemas(data []byte) (map[string]CredentialType, error) {
	var list schemaList
	if err := json.Unmarshal(data, &list); err != nil {
		var bare []publishedSchema
		if err2 := json.Unmarshal(data, &bare); err2 != nil {
			return nil, fmt.Errorf("catalog: read the schema list: %w", err)
		}
		list.Schemas = bare
	}
	out := map[string]CredentialType{}
	for _, s := range list.Schemas {
		name := s.Vct
		if name == "" {
			name = s.Type
		}
		if name == "" {
			continue
		}
		t := CredentialType{Type: name, SchemaID: s.ID, SchemaVersion: s.Version, Display: s.Display}
		if len(s.Formats) > 0 {
			t.Format = s.Formats[0]
		}
		if len(s.JSONSchema) > 0 {
			t.JSONSchema = string(s.JSONSchema)
			t.Fields = ReadFields(s.JSONSchema, t.Format)
		}
		out[name] = t
	}
	return out, nil
}

// jsonSchema is the part of a JSON Schema document the reader uses.
type jsonSchema struct {
	Type       string                `json:"type"`
	Title      string                `json:"title"`
	Format     string                `json:"format"`
	Required   []string              `json:"required"`
	Properties map[string]jsonSchema `json:"properties"`
	Items      *jsonSchema           `json:"items"`
}

// MaxFieldDepth bounds the depth the field reader follows.
const MaxFieldDepth = 6

// ReadFields turns a JSON Schema 2020-12 document into field records in
// schema order. The reader follows nested objects and writes a dotted
// path for each leaf claim.
func ReadFields(data []byte, format string) []Field {
	var s jsonSchema
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	root := s
	// A credential schema often wraps the claims in credentialSubject.
	if inner, ok := s.Properties["credentialSubject"]; ok && len(inner.Properties) > 0 {
		root = inner
	}
	selective := format == "dc+sd-jwt" || format == "vc+sd-jwt" || format == "mso_mdoc"
	var out []Field
	walk(root, "", selective, 0, &out)
	return out
}

// walk adds one field for each leaf claim of a schema.
func walk(s jsonSchema, prefix string, selective bool, depth int, out *[]Field) {
	if depth > MaxFieldDepth || len(s.Properties) == 0 {
		return
	}
	required := map[string]bool{}
	for _, name := range s.Required {
		required[name] = true
	}
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := s.Properties[name]
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if p.Type == "object" && len(p.Properties) > 0 {
			walk(p, path, selective, depth+1, out)
			continue
		}
		*out = append(*out, Field{
			Path: path, Type: p.Type, Format: p.Format, Title: p.Title,
			Mandatory: required[name], SelectivelyDisclosable: selective,
		})
	}
}

// Merge adds the schema records to the metadata records. A schema record
// fills the fields, the schema id, and the schema version of the type
// with the same name.
func Merge(types []CredentialType, schemas map[string]CredentialType) []CredentialType {
	out := make([]CredentialType, 0, len(types)+len(schemas))
	seen := map[string]bool{}
	for _, t := range types {
		if s, ok := schemas[t.Type]; ok {
			t.Fields, t.JSONSchema = s.Fields, s.JSONSchema
			if t.SchemaID == "" {
				t.SchemaID, t.SchemaVersion = s.SchemaID, s.SchemaVersion
			}
			if len(t.Display) == 0 {
				t.Display = s.Display
			}
		}
		seen[t.Type] = true
		out = append(out, t)
	}
	names := make([]string, 0, len(schemas))
	for name := range schemas {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, schemas[name])
	}
	return out
}

// URLFor joins a service endpoint and a path.
func URLFor(endpoint, path string) string {
	return strings.TrimRight(endpoint, "/") + path
}

// toInt32 converts n to int32. A value out of range clamps to the limit.
func toInt32(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
