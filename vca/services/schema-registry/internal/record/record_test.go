// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strings"
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

const doc = `{"type": "object", "properties": {"name": {"type": "string"}, "age": {"type": "integer"}}, "required": ["name"]}`

func valid() Record {
	return Record{
		Type: "UniversityDegree", JSONSchema: doc, Formats: []string{FormatDcSdJwt, FormatJwtVcJSON},
		Display:  []Display{{Name: "Degree", Description: "A degree", Locale: "en"}},
		SDClaims: []string{"name"}, SearchableClaims: []string{"name"},
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(r *Record){
		"empty type":       func(r *Record) { r.Type = "" },
		"space in type":    func(r *Record) { r.Type = "a b" },
		"long type":        func(r *Record) { r.Type = strings.Repeat("a", MaxTypeLength+1) },
		"big schema":       func(r *Record) { r.JSONSchema = `{"title": "` + strings.Repeat("a", MaxSchemaSize) + `"}` },
		"bad schema":       func(r *Record) { r.JSONSchema = "{" },
		"no format":        func(r *Record) { r.Formats = nil },
		"bad format":       func(r *Record) { r.Formats = []string{"xml"} },
		"display name":     func(r *Record) { r.Display = []Display{{Locale: "en"}} },
		"display locale":   func(r *Record) { r.Display = []Display{{Name: "x"}} },
		"sd claim":         func(r *Record) { r.SDClaims = []string{"ghost"} },
		"searchable claim": func(r *Record) { r.SearchableClaims = []string{"ghost"} },
		"retention":        func(r *Record) { r.RetentionDays = -1 },
	}
	for name, mutate := range cases {
		r := valid()
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestHelpers(t *testing.T) {
	r := valid()
	if r.Name() != "Degree" || r.Description() != "A degree" {
		t.Fatal("name")
	}
	r.Display = nil
	if r.Name() != "UniversityDegree" || r.Description() != "" {
		t.Fatal("name without display")
	}
	r = valid()
	r.ID = "degree-1"
	for _, q := range []string{"", "degree", "DEGREE", "a degree", "University", "degree-1"} {
		if !r.Matches(q) {
			t.Errorf("query %q should match", q)
		}
	}
	if r.Matches("passport") {
		t.Error("passport should not match")
	}
	if !r.Offers(FormatDcSdJwt) || r.Offers(FormatMsoMdoc) {
		t.Error("offers")
	}
	if !ValidID("degree-1") || ValidID("Degree") || ValidID("") || ValidID(strings.Repeat("a", 81)) {
		t.Error("ValidID")
	}
	if ConfigurationID("https://issuer.example/vct/degree", FormatDcSdJwt) != "https-issuer.example-vct-degree_dc+sd-jwt" {
		t.Error(ConfigurationID("https://issuer.example/vct/degree", FormatDcSdJwt))
	}
	if ConfigurationID("UniversityDegree", FormatJwtVcJSON) != "UniversityDegree_jwt_vc_json" {
		t.Error("plain configuration id")
	}
	list := Sorted([]Record{{ID: "b", Version: 2}, {ID: "b", Version: 1}, {ID: "a", Version: 1}})
	if list[0].ID != "a" || list[1].Version != 1 || list[2].Version != 2 {
		t.Errorf("sorted: %v", list)
	}
}

func TestLifecycle(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	r := valid()
	r.State = StateDraft
	if _, err := r.Retire(now); err == nil {
		t.Fatal("retire a draft")
	}
	p, err := r.Publish(now, map[string]string{FormatDcSdJwt: "x"})
	if err != nil || p.State != StatePublished || !p.PublishedAt.Equal(now) || p.ConfigurationIDs[FormatDcSdJwt] != "x" {
		t.Fatalf("publish: %v %+v", err, p)
	}
	if _, serr := p.Publish(now, nil); serr == nil {
		t.Fatal("publish twice")
	}
	x, err := p.Retire(now)
	if err != nil || x.State != StateRetired || !x.RetiredAt.Equal(now) {
		t.Fatalf("retire: %v %+v", err, x)
	}
}

func TestProtoConversion(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	r := valid()
	r.ID = "degree"
	r.Version = 2
	r.State = StatePublished
	r.CreatedAt = now
	r.PublishedAt = now
	r.ConfigurationIDs = map[string]string{FormatDcSdJwt: "cfg"}
	m := ToProto(r)
	if m.GetId() != "degree" || m.GetVersion() != 2 || m.GetState() != schemav1.State_STATE_PUBLISHED || len(m.GetFormats()) != 2 || m.GetFormats()[0] != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Fatalf("to proto: %v", m)
	}
	if m.GetCreatedAt() == nil || m.GetPublishedAt() == nil || m.GetRetiredAt() != nil || m.GetDisplay()[0].GetName() != "Degree" {
		t.Fatalf("stamps: %v", m)
	}
	m.Formats = append(m.Formats, commonv1.Format_FORMAT_DC_SD_JWT)
	back, err := FromProto(m)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != "" || back.State != "" || back.Type != "UniversityDegree" || len(back.Formats) != 2 || back.Display[0].Locale != "en" || back.SDClaims[0] != "name" {
		t.Fatalf("from proto: %+v", back)
	}
	if _, err := FromProto(nil); err == nil {
		t.Fatal("nil")
	}
	m.Formats = []commonv1.Format{commonv1.Format_FORMAT_LDP_VC_BBS}
	if _, err := FromProto(m); err == nil {
		t.Fatal("bbs")
	}
	m.Formats = nil
	if _, err := FromProto(m); err == nil {
		t.Fatal("no format")
	}
	pub := ToPublicProto(r)
	if pub.GetConfigurationIds()[FormatDcSdJwt] != "cfg" || len(pub.GetConfigurationIds()) != 1 || len(pub.GetFormats()) != 2 {
		t.Fatalf("public: %v", pub)
	}
	for _, f := range Formats {
		e := FormatToProto(f)
		if got, err := FormatFromProto(e); err != nil || got != f {
			t.Errorf("format %s: %v %v", f, got, err)
		}
	}
	if FormatToProto("xml") != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Error("unknown format")
	}
	for _, s := range States {
		if StateFromProto(StateToProto(s)) != s {
			t.Errorf("state %s", s)
		}
	}
	if StateFromProto(schemav1.State_STATE_UNSPECIFIED) != "" || StateToProto("x") != schemav1.State_STATE_UNSPECIFIED {
		t.Error("unspecified state")
	}
}
