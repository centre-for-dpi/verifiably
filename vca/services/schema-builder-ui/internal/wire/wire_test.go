// SPDX-License-Identifier: Apache-2.0

package wire_test

import (
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/preview"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/draft"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/wire"
)

func TestFormatRoundTrip(t *testing.T) {
	for _, id := range draft.Formats {
		f := wire.FormatToProto(id)
		if f == commonv1.Format_FORMAT_UNSPECIFIED {
			t.Fatalf("%s has no enum value", id)
		}
		if got := wire.FormatFromProto(f); got != id {
			t.Errorf("round trip of %s gave %s", id, got)
		}
	}
	if got := wire.FormatToProto("nope"); got != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Errorf("unknown id gave %v", got)
	}
	if got := wire.FormatFromProto(commonv1.Format_FORMAT_UNSPECIFIED); got != "" {
		t.Errorf("unknown enum gave %q", got)
	}
}

func TestFormatLists(t *testing.T) {
	got := wire.FormatsToProto([]string{preview.FormatLdpVc, "nope"})
	if len(got) != 1 || got[0] != commonv1.Format_FORMAT_LDP_VC {
		t.Errorf("to proto = %v", got)
	}
	back := wire.FormatsFromProto([]commonv1.Format{commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_UNSPECIFIED})
	if len(back) != 1 || back[0] != preview.FormatLdpVc {
		t.Errorf("from proto = %v", back)
	}
}

func message() *schemav1.Schema {
	return &schemav1.Schema{
		Id: "s1", Type: "Diploma",
		JsonSchema: `{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}`,
		Display: []*schemav1.Display{{
			Name: "Diploma", Description: "A diploma.", Locale: "fr",
			LogoUri: "https://e.test/l.png", BackgroundColor: "#000000", TextColor: "#ffffff",
		}},
		SdClaims: []string{"b"},
		Formats:  []commonv1.Format{commonv1.Format_FORMAT_MSO_MDOC},
		Expires:  true,
	}
}

func TestPreviewSchema(t *testing.T) {
	s := wire.PreviewSchema(message())
	if s.Type != "Diploma" || !s.Expires {
		t.Errorf("schema = %+v", s)
	}
	if len(s.Display) != 1 || s.Display[0].Locale != "fr" || s.Display[0].TextColor != "#ffffff" {
		t.Errorf("display = %+v", s.Display)
	}
	if len(s.Formats) != 1 || s.Formats[0] != preview.FormatMsoMdoc {
		t.Errorf("formats = %v", s.Formats)
	}
	if len(s.SDClaims) != 1 {
		t.Errorf("sd claims = %v", s.SDClaims)
	}
}

func TestSchemaProto(t *testing.T) {
	d := draft.Draft{
		ID: "s1", Type: "Diploma", Title: "Diploma", Wire: []string{preview.FormatLdpVc}, Expires: true,
		Fields: []draft.Field{{Name: "a", Type: "string", SelectivelyDisclosable: true}},
	}
	m := wire.SchemaProto(d)
	if m.GetId() != "s1" || m.GetType() != "Diploma" || !m.GetExpires() {
		t.Errorf("message = %+v", m)
	}
	if len(m.GetFormats()) != 1 || m.GetFormats()[0] != commonv1.Format_FORMAT_LDP_VC {
		t.Errorf("formats = %v", m.GetFormats())
	}
	if len(m.GetSdClaims()) != 1 || m.GetSdClaims()[0] != "a" {
		t.Errorf("sd claims = %v", m.GetSdClaims())
	}
	if m.GetDisplay()[0].GetLocale() != "en" {
		t.Errorf("locale = %q", m.GetDisplay()[0].GetLocale())
	}
}

func TestDraftFromProto(t *testing.T) {
	d, warnings, err := wire.DraftFromProto(message())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
	if d.ID != "s1" || d.Type != "Diploma" || d.Locale != "fr" || !d.Expires {
		t.Errorf("draft = %+v", d)
	}
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatMsoMdoc {
		t.Errorf("wire = %v", d.Wire)
	}
	if d.Fields[0].SelectivelyDisclosable || !d.Fields[1].SelectivelyDisclosable {
		t.Errorf("sd flags = %+v", d.Fields)
	}
}

func TestDraftFromProtoDefaults(t *testing.T) {
	m := &schemav1.Schema{Type: "T", JsonSchema: `{"type":"object","properties":{"a":{"type":"string"}}}`}
	d, _, err := wire.DraftFromProto(m)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatDcSdJwt {
		t.Errorf("wire = %v", d.Wire)
	}
	if d.Locale != "en" {
		t.Errorf("locale = %q", d.Locale)
	}
}

func TestDraftFromProtoBadDocument(t *testing.T) {
	if _, _, err := wire.DraftFromProto(&schemav1.Schema{JsonSchema: "{"}); err == nil {
		t.Error("a broken document must fail")
	}
}
