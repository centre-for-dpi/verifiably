// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"encoding/json"
	"strings"
	"testing"

	claimstore "github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// TestEveryTemplateRendersOnlyTheRowOfItsConfiguration: Certify picks
// the template from the request and fills it from the row of the token
// subject. So the template of every format opens with a guard on the
// config_id column and renders nothing for a row of another
// configuration (ADR-056 decision 1).
func TestEveryTemplateRendersOnlyTheRowOfItsConfiguration(t *testing.T) {
	schema := `{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"}}}`
	for _, format := range []string{"ldp_vc", "vc+sd-jwt", "mso_mdoc"} {
		id := "medical-licence_" + format
		dto, err := BuildConfiguration(ConfigInput{ID: id, Format: format, Type: "org.example.licence", JSONSchema: schema}, DefaultProfiles())
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		tmpl, err := DecodeTemplate(dto.VcTemplate)
		if err != nil {
			t.Fatal(err)
		}
		if first, _, _ := strings.Cut(tmpl, "\n"); first != "#if($config_id == '"+id+"')" || !strings.HasSuffix(tmpl, "\n#end\n") {
			t.Errorf("%s: the template has no guard:\n%s", format, tmpl)
		}
		own := claimstore.Row{ConfigID: id, Claims: []string{"Amina", "42"}}
		var doc map[string]any
		if err := json.Unmarshal([]byte(fake.Render(tmpl, own)), &doc); err != nil {
			t.Errorf("%s: the own row renders no JSON: %v", format, err)
		}
		for _, other := range []string{"farmer-registration_" + format, "", id + "x", strings.ToUpper(id)} {
			row := claimstore.Row{ConfigID: other, Claims: []string{"Amina", "42"}}
			if out := strings.TrimSpace(fake.Render(tmpl, row)); out != "" {
				t.Errorf("%s: the row of %q renders %q", format, other, out)
			}
		}
	}
}

// TestConfigurationIdsFitTheGuard: the guard quotes the id in a single
// quoted Velocity text, so an id with a quote, a backslash, a Velocity
// sign, a space, or a control character cannot register.
func TestConfigurationIdsFitTheGuard(t *testing.T) {
	schema := `{"type":"object","properties":{"name":{"type":"string"}}}`
	for _, id := range []string{"a'b", `a'b`, "a$b", "a#b", "a b", "a\nb", "", strings.Repeat("a", 129)} {
		if _, err := BuildConfiguration(ConfigInput{ID: id, Format: "ldp_vc", Type: "X", JSONSchema: schema}, DefaultProfiles()); err == nil {
			t.Errorf("the id %q registered", id)
		}
	}
	for _, id := range []string{"FarmerCredential", "farmer-registration_vc+sd-jwt", "urn:x.y~z_1"} {
		if _, err := BuildConfiguration(ConfigInput{ID: id, Format: "ldp_vc", Type: "X", JSONSchema: schema}, DefaultProfiles()); err != nil {
			t.Errorf("the id %q did not register: %v", id, err)
		}
	}
}
