// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
)

// plainPE converts to DCQL without a loss.
const plainPE = `{"id": "farmer-check", "name": "Farmer check", "purpose": "Check the farm.",
  "input_descriptors": [{"id": "farmer", "format": {"ldp_vc": {}}, "constraints": {"fields": [
    {"path": ["$.type"], "filter": {"type": "array", "contains": {"type": "string", "const": "FarmerRegistration"}}},
    {"path": ["$.credentialSubject.farm_id"]}]}}]}`

// statusPE asks for a status directive, which DCQL cannot hold.
const statusPE = `{"id": "badge", "input_descriptors": [{"id": "badge", "format": {"jwt_vc_json": {}}, "constraints": {
  "statuses": {"active": {"directive": "required"}},
  "fields": [{"path": ["$.vc.credentialSubject.employee_id"]}]}}]}`

// TestBuildPeTemplate stores a PE definition as the request of a PE
// template. A lossless conversion fills the DCQL too (ADR-042 decision 4).
func TestBuildPeTemplate(t *testing.T) {
	out, err := template.Build(template.Template{Kind: template.KindPE, PresentationDefinition: plainPE})
	if err != nil {
		t.Fatal(err)
	}
	if out.DisplayName != "Farmer check" || out.Purpose != "Check the farm." {
		t.Errorf("name %q purpose %q", out.DisplayName, out.Purpose)
	}
	if !strings.Contains(out.DCQL, `"type_values":[["VerifiableCredential","FarmerRegistration"]]`) {
		t.Errorf("DCQL %s", out.DCQL)
	}
	if len(out.Queries) != 1 || out.Queries[0].Claims[0] != "farm_id" {
		t.Errorf("queries %+v", out.Queries)
	}
	pe, err := out.PresentationExchange()
	if err != nil || !strings.Contains(string(pe), `"id":"farmer-check"`) {
		t.Errorf("PE %s %v", pe, err)
	}
	back := template.FromProto(out.ToProto())
	if back.PresentationDefinition != out.PresentationDefinition || back.Kind != template.KindPE {
		t.Errorf("proto round trip %+v", back)
	}

	lossy, err := template.Build(template.Template{Kind: template.KindPE, DisplayName: "Badge", PresentationDefinition: statusPE})
	if err != nil {
		t.Fatal(err)
	}
	if lossy.DCQL != "" || len(lossy.Queries) != 1 || lossy.DisplayName != "Badge" {
		t.Errorf("lossy PE: DCQL %q queries %+v", lossy.DCQL, lossy.Queries)
	}

	noFormat, err := template.Build(template.Template{Kind: template.KindPE, PresentationDefinition: `{"id": "x", "input_descriptors": [{"id": "a", "constraints": {}}]}`})
	if err != nil || noFormat.DCQL != "" || len(noFormat.Queries) != 0 || noFormat.DisplayName != "x" {
		t.Errorf("PE without a format: %+v %v", noFormat, err)
	}

	for name, tpl := range map[string]template.Template{
		"empty":   {Kind: template.KindPE, DisplayName: "x"},
		"invalid": {Kind: template.KindPE, DisplayName: "x", PresentationDefinition: `{"id": 5, "input_descriptors": []}`},
	} {
		if _, buildErr := template.Build(tpl); buildErr == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A DCQL template drops a definition it carries.
	dcqlOut, err := template.Build(template.Template{DisplayName: "d", PresentationDefinition: plainPE, Queries: licence().Queries})
	if err != nil || dcqlOut.PresentationDefinition != "" {
		t.Errorf("DCQL template kept the definition: %v", err)
	}
}
