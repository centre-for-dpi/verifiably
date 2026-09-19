// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"strings"
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
)

func TestValidID(t *testing.T) {
	for _, id := range []string{"age-check", "a_b.c", "A1"} {
		if !template.ValidID(id) {
			t.Errorf("ValidID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "a/b", "a b", ".", "..", strings.Repeat("a", template.MaxIDLength+1)} {
		if template.ValidID(id) {
			t.Errorf("ValidID(%q) = true", id)
		}
	}
}

func TestIDFrom(t *testing.T) {
	if got := template.IDFrom("  Age check  over 18 "); got != "age-check-over-18" {
		t.Errorf("IDFrom = %q", got)
	}
	if got := template.IDFrom("!!!"); got != "" {
		t.Errorf("IDFrom of punctuation = %q", got)
	}
	long := template.IDFrom(strings.Repeat("a", template.MaxIDLength+10))
	if len(long) != template.MaxIDLength {
		t.Errorf("IDFrom cuts at the limit, got %d", len(long))
	}
}

func TestBuildFromQueries(t *testing.T) {
	out, err := template.Build(template.Template{
		DisplayName: "Age check",
		Purpose:     "Prove you are over 18",
		Queries: []template.Query{
			{QueryID: "pid", Type: "https://issuer.example/pid", Claims: []string{"birth_date"}, Issuers: []string{"https://issuer.example"}},
			{QueryID: "degree", Type: "DegreeCredential", Format: "jwt_vc_json", Claims: []string{"degree"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.DCQL, `"credentials"`) {
		t.Errorf("dcql = %s", out.DCQL)
	}
	if len(out.Queries) != 2 {
		t.Fatalf("queries = %+v", out.Queries)
	}
	if out.Queries[0].Format != "dc+sd-jwt" {
		t.Errorf("a query without a format takes the SD-JWT VC format, got %q", out.Queries[0].Format)
	}
	if len(out.Queries[0].Issuers) != 1 {
		t.Errorf("the issuer survives, got %+v", out.Queries[0])
	}
	q, err := out.Query()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Credentials) != 2 {
		t.Errorf("parsed query = %+v", q)
	}
	pe, err := out.PresentationExchange()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pe), "input_descriptors") {
		t.Errorf("presentation exchange = %s", pe)
	}
}

func TestBuildFromDCQL(t *testing.T) {
	raw := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["given_name"]}]}]}`
	out, err := template.Build(template.Template{DisplayName: "Paste", DCQL: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Queries) != 1 || out.Queries[0].Type != "v" {
		t.Errorf("queries = %+v", out.Queries)
	}
	if _, err := template.Build(template.Template{DisplayName: "Broken", DCQL: "{"}); err == nil {
		t.Error("broken DCQL wants an error")
	}
	if _, err := template.Build(template.Template{DisplayName: "Empty", DCQL: `{"credentials":[]}`}); err == nil {
		t.Error("a query without a credential wants an error")
	}
}

func TestBuildRejects(t *testing.T) {
	cases := map[string]template.Template{
		"no name":      {Queries: []template.Query{{Type: "A"}}},
		"long name":    {DisplayName: strings.Repeat("a", template.MaxNameLength+1)},
		"long purpose": {DisplayName: "ok", Purpose: strings.Repeat("a", template.MaxNameLength+1)},
		"no query":     {DisplayName: "ok"},
		"bad claim":    {DisplayName: "ok", Queries: []template.Query{{Type: "A", Claims: []string{"a["}}}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := template.Build(in); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestPresentationExchangeOfBrokenTemplate(t *testing.T) {
	if _, err := (template.Template{DCQL: "{"}).PresentationExchange(); err == nil {
		t.Error("broken DCQL wants an error")
	}
	if _, err := (template.Template{DCQL: "{"}).Query(); err == nil {
		t.Error("broken DCQL wants an error")
	}
}

func TestProtoRoundTrip(t *testing.T) {
	in := &discoveryv1.PresentationTemplate{
		Id: "age-check", DisplayName: "Age check", Purpose: "why", TenantId: "t1", CreatedBy: "staff",
		Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
			QueryId: "pid", Type: "https://issuer.example/pid", Format: commonv1.Format_FORMAT_DC_SD_JWT,
			Claims: []string{"birth_date"}, Issuers: []string{"https://issuer.example"},
		}},
	}
	record := template.FromProto(in)
	if record.ID != "age-check" || record.TenantID != "t1" || record.CreatedBy != "staff" {
		t.Errorf("record = %+v", record)
	}
	if len(record.Queries) != 1 || record.Queries[0].Format != "dc+sd-jwt" {
		t.Errorf("queries = %+v", record.Queries)
	}
	record.Version = 2
	record.CreatedAt = time.Unix(1700000000, 0).UTC()
	out := record.ToProto()
	if out.GetVersion() != 2 || out.GetCreatedAt() == nil {
		t.Errorf("proto = %+v", out)
	}
	if out.GetQueries()[0].GetFormat() != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Errorf("format = %v", out.GetQueries()[0].GetFormat())
	}
	if (template.Template{}).ToProto().GetCreatedAt() != nil {
		t.Error("a template without a time writes no timestamp")
	}
}

func TestFormatNamesOfEveryValue(t *testing.T) {
	formats := []commonv1.Format{
		commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_JWT_VC_JSON,
		commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_MSO_MDOC, commonv1.Format_FORMAT_UNSPECIFIED,
	}
	names := []string{"vc+sd-jwt", "dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc", ""}
	for i, f := range formats {
		in := &discoveryv1.PresentationTemplate{
			Id: "x", DisplayName: "x",
			Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{Type: "A", Format: f}},
		}
		record := template.FromProto(in)
		if record.Queries[0].Format != names[i] {
			t.Errorf("FromProto format = %q, want %q", record.Queries[0].Format, names[i])
		}
		if got := record.ToProto().GetQueries()[0].GetFormat(); got != f {
			t.Errorf("ToProto format = %v, want %v", got, f)
		}
	}
}
