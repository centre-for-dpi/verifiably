// SPDX-License-Identifier: Apache-2.0

// Package record holds the canonical schema version, its validation, its
// life cycle rules, and the conversion to and from the proto message
// (ADR-013 decisions 1 and 2).
package record

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
)

// State is the life cycle state of a version.
type State string

// The three states of ADR-013 decision 2.
const (
	StateDraft     State = "draft"
	StatePublished State = "published"
	StateRetired   State = "retired"
)

// States lists every state in life cycle order.
var States = []State{StateDraft, StatePublished, StateRetired}

// Format identifiers of OpenID for Verifiable Credential Issuance 1.0.
const (
	FormatVcSdJwt   = "vc+sd-jwt"
	FormatDcSdJwt   = "dc+sd-jwt"
	FormatJwtVcJSON = "jwt_vc_json"
	FormatLdpVc     = "ldp_vc"
	FormatMsoMdoc   = "mso_mdoc"
)

// Formats lists every format a schema can offer, in enum order.
var Formats = []string{FormatVcSdJwt, FormatDcSdJwt, FormatJwtVcJSON, FormatLdpVc, FormatMsoMdoc}

// MaxTypeLength caps the credential type.
const MaxTypeLength = 200

// MaxSchemaSize caps the JSON Schema document in bytes.
const MaxSchemaSize = 256 << 10

var (
	typeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/+#?=&%-]*$`)
	idRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// Display is the OID4VCI display metadata of one locale.
type Display struct {
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	Locale          string `json:"locale"`
	LogoURI         string `json:"logo_uri,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// Record is one version of one schema.
type Record struct {
	ID               string            `json:"id"`
	Version          int               `json:"version"`
	Type             string            `json:"type"`
	JSONSchema       string            `json:"json_schema"`
	State            State             `json:"state"`
	Display          []Display         `json:"display,omitempty"`
	SDClaims         []string          `json:"sd_claims,omitempty"`
	Formats          []string          `json:"formats"`
	Expires          bool              `json:"expires,omitempty"`
	SearchableClaims []string          `json:"searchable_claims,omitempty"`
	TenantID         string            `json:"tenant_id,omitempty"`
	CreatedBy        string            `json:"created_by,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	PublishedAt      time.Time         `json:"published_at,omitempty"`
	RetiredAt        time.Time         `json:"retired_at,omitempty"`
	RetentionDays    int               `json:"retention_days,omitempty"`
	ConfigurationIDs map[string]string `json:"configuration_ids,omitempty"`
}

// Validate checks the fields a caller sets. It parses the JSON Schema.
func (r Record) Validate() error {
	if len(r.Type) == 0 || len(r.Type) > MaxTypeLength || !typeRE.MatchString(r.Type) {
		return errors.New("record: the type must be 1 to 200 characters with no space")
	}
	if len(r.JSONSchema) > MaxSchemaSize {
		return fmt.Errorf("record: the JSON Schema is larger than %d bytes", MaxSchemaSize)
	}
	parsed, err := jsonschema.Parse([]byte(r.JSONSchema))
	if err != nil {
		return fmt.Errorf("record: %w", err)
	}
	if len(r.Formats) == 0 {
		return errors.New("record: the schema needs at least one format")
	}
	for _, f := range r.Formats {
		if !contains(Formats, f) {
			return fmt.Errorf("record: the format %q is not supported", f)
		}
	}
	for i, d := range r.Display {
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("record: display entry %d has no name", i+1)
		}
		if strings.TrimSpace(d.Locale) == "" {
			return fmt.Errorf("record: display entry %d has no locale", i+1)
		}
	}
	for _, claim := range r.SDClaims {
		if _, ok := parsed.Property(claim); !ok {
			return fmt.Errorf("record: the selectively disclosable claim %q is not a property", claim)
		}
	}
	for _, claim := range r.SearchableClaims {
		if _, ok := parsed.Property(claim); !ok {
			return fmt.Errorf("record: the searchable claim %q is not a property", claim)
		}
	}
	if r.RetentionDays < 0 {
		return errors.New("record: retention days must be zero or more")
	}
	return nil
}

// ValidID reports whether id has the shape the store assigns.
func ValidID(id string) bool {
	return len(id) <= 80 && idRE.MatchString(id)
}

// Name returns the first display name, or the type.
func (r Record) Name() string {
	if len(r.Display) > 0 {
		return r.Display[0].Name
	}
	return r.Type
}

// Description returns the first display description.
func (r Record) Description() string {
	if len(r.Display) > 0 {
		return r.Display[0].Description
	}
	return ""
}

// Matches reports whether the free text query matches the name, the
// description, the type, or the id. An empty query matches everything.
func (r Record) Matches(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	for _, s := range []string{r.Type, r.ID} {
		if strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	for _, d := range r.Display {
		if strings.Contains(strings.ToLower(d.Name), q) || strings.Contains(strings.ToLower(d.Description), q) {
			return true
		}
	}
	return false
}

// Offers reports whether the version lists format.
func (r Record) Offers(format string) bool {
	return contains(r.Formats, format)
}

// Publish returns the version in the published state.
func (r Record) Publish(now time.Time, configurationIDs map[string]string) (Record, error) {
	if r.State != StateDraft {
		return Record{}, fmt.Errorf("record: version %d of %s is %s, only a draft can publish", r.Version, r.ID, r.State)
	}
	r.State = StatePublished
	r.PublishedAt = now.UTC()
	r.ConfigurationIDs = configurationIDs
	return r, nil
}

// Retire returns the version in the retired state.
func (r Record) Retire(now time.Time) (Record, error) {
	if r.State != StatePublished {
		return Record{}, fmt.Errorf("record: version %d of %s is %s, only a published version can retire", r.Version, r.ID, r.State)
	}
	r.State = StateRetired
	r.RetiredAt = now.UTC()
	return r, nil
}

// CanDelete reports whether the version can go. Only a draft can: a
// published version retires, and a retired version stays for verifiers.
func (r Record) CanDelete() error {
	switch r.State {
	case StateDraft:
		return nil
	case StatePublished:
		return fmt.Errorf("record: version %d of %s is published: %s", r.Version, r.ID, msg.T("schema.delete.published"))
	}
	return fmt.Errorf("record: version %d of %s is %s: %s", r.Version, r.ID, r.State, msg.T("schema.delete.retired"))
}

// ConfigurationID returns the OID4VCI credential configuration id of one
// format: the type with unsafe characters replaced, then the format.
func ConfigurationID(typ, format string) string {
	var b strings.Builder
	for _, c := range typ {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			b.WriteRune(c)
		default:
			if !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	return strings.Trim(b.String(), "-") + "_" + format
}

// Sorted returns records ordered by id, then by version.
func Sorted(list []Record) []Record {
	out := append([]Record(nil), list...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// FormatFromProto maps the enum to the format identifier.
func FormatFromProto(f commonv1.Format) (string, error) {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return FormatVcSdJwt, nil
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return FormatDcSdJwt, nil
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return FormatJwtVcJSON, nil
	case commonv1.Format_FORMAT_LDP_VC:
		return FormatLdpVc, nil
	case commonv1.Format_FORMAT_MSO_MDOC:
		return FormatMsoMdoc, nil
	}
	return "", fmt.Errorf("record: the format %s is not supported", f)
}

// FormatToProto maps the format identifier to the enum.
func FormatToProto(f string) commonv1.Format {
	switch f {
	case FormatVcSdJwt:
		return commonv1.Format_FORMAT_VC_SD_JWT
	case FormatDcSdJwt:
		return commonv1.Format_FORMAT_DC_SD_JWT
	case FormatJwtVcJSON:
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case FormatLdpVc:
		return commonv1.Format_FORMAT_LDP_VC
	case FormatMsoMdoc:
		return commonv1.Format_FORMAT_MSO_MDOC
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// StateFromProto maps the enum to the state. Unspecified maps to "".
func StateFromProto(s schemav1.State) State {
	switch s {
	case schemav1.State_STATE_DRAFT:
		return StateDraft
	case schemav1.State_STATE_PUBLISHED:
		return StatePublished
	case schemav1.State_STATE_RETIRED:
		return StateRetired
	}
	return ""
}

// StateToProto maps the state to the enum.
func StateToProto(s State) schemav1.State {
	switch s {
	case StateDraft:
		return schemav1.State_STATE_DRAFT
	case StatePublished:
		return schemav1.State_STATE_PUBLISHED
	case StateRetired:
		return schemav1.State_STATE_RETIRED
	}
	return schemav1.State_STATE_UNSPECIFIED
}

// FromProto reads the caller set fields of a Schema message. It ignores
// id, version, state, and the timestamps, and it validates the result.
func FromProto(m *schemav1.Schema) (Record, error) {
	if m == nil {
		return Record{}, errors.New("record: the request has no schema")
	}
	r := Record{
		Type:             strings.TrimSpace(m.GetType()),
		JSONSchema:       m.GetJsonSchema(),
		SDClaims:         append([]string(nil), m.GetSdClaims()...),
		Expires:          m.GetExpires(),
		SearchableClaims: append([]string(nil), m.GetSearchableClaims()...),
		TenantID:         m.GetTenantId(),
		CreatedBy:        m.GetCreatedBy(),
		RetentionDays:    int(m.GetRetentionDays()),
	}
	for _, d := range m.GetDisplay() {
		r.Display = append(r.Display, Display{
			Name: d.GetName(), Description: d.GetDescription(), Locale: d.GetLocale(),
			LogoURI: d.GetLogoUri(), BackgroundColor: d.GetBackgroundColor(), TextColor: d.GetTextColor(),
		})
	}
	for _, f := range m.GetFormats() {
		name, err := FormatFromProto(f)
		if err != nil {
			return Record{}, err
		}
		if !contains(r.Formats, name) {
			r.Formats = append(r.Formats, name)
		}
	}
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// ToProto renders the version as a Schema message.
func ToProto(r Record) *schemav1.Schema {
	m := &schemav1.Schema{
		Id: r.ID, Version: toInt32(int64(r.Version)), Type: r.Type, JsonSchema: r.JSONSchema, State: StateToProto(r.State),
		SdClaims: append([]string(nil), r.SDClaims...), Expires: r.Expires,
		SearchableClaims: append([]string(nil), r.SearchableClaims...), TenantId: r.TenantID, CreatedBy: r.CreatedBy,
		RetentionDays: toInt32(int64(r.RetentionDays)), Display: DisplayToProto(r.Display),
	}
	for _, f := range r.Formats {
		m.Formats = append(m.Formats, FormatToProto(f))
	}
	m.CreatedAt = stamp(r.CreatedAt)
	m.PublishedAt = stamp(r.PublishedAt)
	m.RetiredAt = stamp(r.RetiredAt)
	return m
}

// DisplayToProto renders display entries as messages.
func DisplayToProto(list []Display) []*schemav1.Display {
	var out []*schemav1.Display
	for _, d := range list {
		out = append(out, &schemav1.Display{
			Name: d.Name, Description: d.Description, Locale: d.Locale,
			LogoUri: d.LogoURI, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
		})
	}
	return out
}

// ToPublicProto renders the wallet and verifier view of a version.
func ToPublicProto(r Record) *schemav1.PublicSchema {
	m := &schemav1.PublicSchema{
		Id: r.ID, Version: toInt32(int64(r.Version)), Type: r.Type, JsonSchema: r.JSONSchema,
		Display: DisplayToProto(r.Display), SdClaims: append([]string(nil), r.SDClaims...),
		ConfigurationIds: map[string]string{},
	}
	for _, f := range r.Formats {
		m.Formats = append(m.Formats, FormatToProto(f))
		if id, ok := r.ConfigurationIDs[f]; ok {
			m.ConfigurationIds[f] = id
		}
	}
	return m
}

func stamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
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
