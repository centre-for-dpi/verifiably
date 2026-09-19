// SPDX-License-Identifier: Apache-2.0

// Package template holds the presentation template record and its pure
// rules (ADR-022 decisions 3 and 4). A template stores the request as a
// DCQL query. The package also generates a Presentation Exchange 2.0
// definition for a Digital Public Good that needs the older language.
package template

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
)

// MaxNameLength caps the display name and the purpose.
const MaxNameLength = 200

// MaxIDLength caps a template id.
const MaxIDLength = 64

// Template is one stored version of a presentation request.
type Template struct {
	// ID is stable across versions.
	ID string `json:"id"`
	// Version starts at 1 and increases by 1.
	Version int32 `json:"version"`
	// DisplayName is the name the pages show.
	DisplayName string `json:"display_name"`
	// DCQL is the query as a JSON string. It is the request the wallet
	// gets.
	DCQL string `json:"dcql"`
	// Queries is the structured view of the same request.
	Queries []Query `json:"queries,omitempty"`
	// Purpose is the reason the citizen sees.
	Purpose string `json:"purpose,omitempty"`
	// TenantID is the tenant that owns the template.
	TenantID string `json:"tenant_id,omitempty"`
	// CreatedBy is the staff subject that created this version.
	CreatedBy string `json:"created_by,omitempty"`
	// CreatedAt is the creation time of this version.
	CreatedAt time.Time `json:"created_at"`
}

// Query is one credential the template asks for.
type Query struct {
	// QueryID is the DCQL credential query id.
	QueryID string `json:"query_id"`
	// Type is the credential type.
	Type string `json:"type"`
	// Format is the wire format identifier. Empty accepts every format.
	Format string `json:"format,omitempty"`
	// Claims holds the dotted claim paths.
	Claims []string `json:"claims,omitempty"`
	// Issuers holds the issuer URLs to accept. Empty accepts every
	// trusted issuer.
	Issuers []string `json:"issuers,omitempty"`
}

// ValidID reports whether the id is a safe store key segment.
func ValidID(id string) bool {
	if id == "" || len(id) > MaxIDLength {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return id != "." && id != ".."
}

// IDFrom turns a display name into a template id.
func IDFrom(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == ' ':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	if len(id) > MaxIDLength {
		id = id[:MaxIDLength]
	}
	return id
}

// Build fills the DCQL of a template from its queries, or reads the DCQL
// the caller sent. It validates the result.
func Build(t Template) (Template, error) {
	if strings.TrimSpace(t.DisplayName) == "" {
		return Template{}, errors.New("template: the display name is required")
	}
	if len(t.DisplayName) > MaxNameLength {
		return Template{}, fmt.Errorf("template: the display name is longer than %d characters", MaxNameLength)
	}
	if len(t.Purpose) > MaxNameLength {
		return Template{}, fmt.Errorf("template: the purpose is longer than %d characters", MaxNameLength)
	}
	if strings.TrimSpace(t.DCQL) != "" {
		q, err := dcql.Parse([]byte(t.DCQL))
		if err != nil {
			return Template{}, err
		}
		data, err := dcql.Marshal(q)
		if err != nil {
			return Template{}, err
		}
		t.DCQL = string(data)
		t.Queries = QueriesOf(q)
		return t, nil
	}
	if len(t.Queries) == 0 {
		return Template{}, errors.New("template: the template asks for no credential")
	}
	selections := make([]dcql.Selection, 0, len(t.Queries))
	for _, q := range t.Queries {
		selections = append(selections, dcql.Selection{
			ID: q.QueryID, Format: formatOrDefault(q.Format), Type: q.Type, Claims: q.Claims, Issuers: q.Issuers,
		})
	}
	q, err := dcql.Build(selections, t.Purpose)
	if err != nil {
		return Template{}, err
	}
	data, err := dcql.Marshal(q)
	if err != nil {
		return Template{}, err
	}
	t.DCQL = string(data)
	t.Queries = QueriesOf(q)
	return t, nil
}

// formatOrDefault returns the format, or the SD-JWT VC format when the
// caller named none.
func formatOrDefault(format string) string {
	if format == "" {
		return dcql.FormatSDJWT
	}
	return format
}

// QueriesOf returns the structured view of a DCQL query.
func QueriesOf(q dcql.Query) []Query {
	out := make([]Query, 0, len(q.Credentials))
	for _, c := range q.Credentials {
		item := Query{QueryID: c.ID, Type: c.Type(), Format: c.Format, Claims: c.ClaimPaths()}
		for _, a := range c.TrustedAuthorities {
			item.Issuers = append(item.Issuers, a.Values...)
		}
		out = append(out, item)
	}
	return out
}

// PresentationExchange generates the Presentation Exchange 2.0
// definition of a template.
func (t Template) PresentationExchange() ([]byte, error) {
	q, err := dcql.Parse([]byte(t.DCQL))
	if err != nil {
		return nil, err
	}
	id := t.ID
	if id == "" {
		id = "presentation-request"
	}
	return dcql.MarshalPresentationExchange(q, id, t.Purpose)
}

// Query returns the parsed DCQL query of a template.
func (t Template) Query() (dcql.Query, error) {
	return dcql.Parse([]byte(t.DCQL))
}

// FromProto reads a template message. It ignores the version and the
// timestamps, which the service assigns.
func FromProto(m *discoveryv1.PresentationTemplate) Template {
	t := Template{
		ID:          m.GetId(),
		DisplayName: m.GetDisplayName(),
		DCQL:        m.GetDcql(),
		Purpose:     m.GetPurpose(),
		TenantID:    m.GetTenantId(),
		CreatedBy:   m.GetCreatedBy(),
	}
	for _, q := range m.GetQueries() {
		t.Queries = append(t.Queries, Query{
			QueryID: q.GetQueryId(), Type: q.GetType(), Format: formatName(q.GetFormat()),
			Claims: q.GetClaims(), Issuers: q.GetIssuers(),
		})
	}
	return t
}

// ToProto turns a template record into its proto message.
func (t Template) ToProto() *discoveryv1.PresentationTemplate {
	out := &discoveryv1.PresentationTemplate{
		Id: t.ID, Version: t.Version, DisplayName: t.DisplayName, Dcql: t.DCQL,
		Purpose: t.Purpose, TenantId: t.TenantID, CreatedBy: t.CreatedBy,
	}
	if !t.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(t.CreatedAt)
	}
	for _, q := range t.Queries {
		out.Queries = append(out.Queries, &discoveryv1.PresentationTemplate_CredentialQuery{
			QueryId: q.QueryID, Type: q.Type, Format: formatOf(q.Format), Claims: q.Claims, Issuers: q.Issuers,
		})
	}
	return out
}

// formatOf returns the proto format of a format identifier.
func formatOf(name string) commonv1.Format {
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

// formatName returns the format identifier of a proto format.
func formatName(f commonv1.Format) string {
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
