// SPDX-License-Identifier: Apache-2.0

// Package wire converts between the builder draft, the preview input, and
// the schema registry messages. Every function here is pure.
package wire

import (
	"github.com/centre-for-dpi/vc-adapters/core/preview"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/draft"
)

// formats maps the OID4VCI identifier of a format to its enum value.
var formats = map[string]commonv1.Format{
	preview.FormatVcSdJwt:   commonv1.Format_FORMAT_VC_SD_JWT,
	preview.FormatDcSdJwt:   commonv1.Format_FORMAT_DC_SD_JWT,
	preview.FormatJwtVcJSON: commonv1.Format_FORMAT_JWT_VC_JSON,
	preview.FormatLdpVc:     commonv1.Format_FORMAT_LDP_VC,
	preview.FormatMsoMdoc:   commonv1.Format_FORMAT_MSO_MDOC,
}

// FormatToProto returns the enum value of an OID4VCI format identifier.
// An unknown identifier returns FORMAT_UNSPECIFIED.
func FormatToProto(id string) commonv1.Format { return formats[id] }

// FormatFromProto returns the OID4VCI identifier of an enum value.
// FORMAT_UNSPECIFIED returns the empty string.
func FormatFromProto(f commonv1.Format) string {
	for id, v := range formats {
		if v == f {
			return id
		}
	}
	return ""
}

// FormatsToProto maps a list of identifiers and drops the unknown ones.
func FormatsToProto(ids []string) []commonv1.Format {
	var out []commonv1.Format
	for _, id := range ids {
		if f := FormatToProto(id); f != commonv1.Format_FORMAT_UNSPECIFIED {
			out = append(out, f)
		}
	}
	return out
}

// FormatsFromProto maps a list of enum values and drops the unknown ones.
func FormatsFromProto(list []commonv1.Format) []string {
	var out []string
	for _, f := range list {
		if id := FormatFromProto(f); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// PreviewSchema returns the preview input of a registry schema message.
func PreviewSchema(m *schemav1.Schema) preview.Schema {
	s := preview.Schema{
		Type:       m.GetType(),
		JSONSchema: m.GetJsonSchema(),
		SDClaims:   append([]string(nil), m.GetSdClaims()...),
		Formats:    FormatsFromProto(m.GetFormats()),
		Expires:    m.GetExpires(),
	}
	for _, d := range m.GetDisplay() {
		s.Display = append(s.Display, preview.Display{
			Name: d.GetName(), Description: d.GetDescription(), Locale: d.GetLocale(),
			LogoURI: d.GetLogoUri(), BackgroundColor: d.GetBackgroundColor(), TextColor: d.GetTextColor(),
		})
	}
	return s
}

// SchemaProto returns the registry message of a draft. The registry
// assigns the version, the state, and the timestamps.
func SchemaProto(d draft.Draft) *schemav1.Schema {
	d = d.Normalize()
	return &schemav1.Schema{
		Id:         d.ID,
		Type:       d.Type,
		JsonSchema: d.Document(),
		Display: []*schemav1.Display{{
			Name: d.Title, Description: d.Description, Locale: d.Locale,
			LogoUri: d.LogoURI, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
		}},
		SdClaims: d.SDClaims(),
		Formats:  FormatsToProto(d.Wire),
		Expires:  d.Expires,
	}
}

// DraftFromProto rebuilds the editor state of a stored schema version, so
// the builder can open it again. The JSON Schema document carries the
// fields. The display metadata carries the wallet card values.
func DraftFromProto(m *schemav1.Schema) (draft.Draft, []string, error) {
	d, warnings, err := draft.FromDocument(m.GetJsonSchema())
	if err != nil {
		return draft.Draft{}, nil, err
	}
	d.ID = m.GetId()
	d.Type = m.GetType()
	d.Expires = m.GetExpires()
	if list := FormatsFromProto(m.GetFormats()); len(list) > 0 {
		d.Wire = list
	}
	if display := m.GetDisplay(); len(display) > 0 {
		e := display[0]
		d.Title, d.Description, d.Locale = e.GetName(), e.GetDescription(), e.GetLocale()
		d.LogoURI, d.BackgroundColor, d.TextColor = e.GetLogoUri(), e.GetBackgroundColor(), e.GetTextColor()
	}
	sd := map[string]bool{}
	for _, n := range m.GetSdClaims() {
		sd[n] = true
	}
	for i := range d.Fields {
		d.Fields[i].SelectivelyDisclosable = sd[d.Fields[i].Name]
	}
	return d.Normalize(), warnings, nil
}
