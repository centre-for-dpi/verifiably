package injicertify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Internal template markers must never reach the issue form.
//
// credential_config.display_order does double duty: it declares which POSTed
// claims certify's pre-auth data-provider surfaces into the Velocity context
// (so the ${markers} resolve), AND ListSchemas turns it into FieldsSpec — the
// operator's claim fields.
//
// The regression: declaring the validity markers surfaced them as required
// plain-text inputs ("validFromEpoch *", "validUntilEpoch *") that an operator
// cannot sensibly fill — fieldSpecFor sees no date-ish name in "validFromEpoch"
// and falls through to string/required — sitting right beside the "Validity
// window" datetime pickers that actually supply them.

// wellknownWith serves a credential_configurations_supported whose `order`
// carries the given claim names, the way certify does once SaveCustomSchema has
// declared the markers.
func wellknownWith(t *testing.T, order []string) *Adapter {
	t.Helper()
	body := map[string]any{
		"credential_configurations_supported": map[string]any{
			"custom-dk05t158qnou": map[string]any{
				"format":  "vc+sd-jwt",
				"vct":     "https://verifiably.test/credentials/custom-dk05t158qnou",
				"order":   order,
				"display": []map[string]any{{"name": "Testa Card V2", "locale": "en"}},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestListSchemas_NeverSurfacesInternalMarkersAsFields(t *testing.T) {
	// Every marker a template can declare, across both formats — sourced from
	// the same function the config declaration uses, so a marker added there
	// without being filtered here fails this test.
	markers := append([]string{"statusIdx", "statusUri"}, allValidityMarkerNames()...)
	order := append([]string{"entity_name", "testa_id"}, markers...)

	schemas, err := wellknownWith(t, order).ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 1 {
		t.Fatalf("expected 1 schema, got %d", len(schemas))
	}

	got := map[string]bool{}
	for _, f := range schemas[0].FieldsSpec {
		got[f.Name] = true
	}
	for _, m := range markers {
		if got[m] {
			t.Errorf("%q is an internal marker supplied by verifiably — it must not be an operator field", m)
		}
	}
	// The real claims must survive: over-filtering would silently drop the
	// operator's actual inputs.
	for _, want := range []string{"entity_name", "testa_id"} {
		if !got[want] {
			t.Errorf("operator claim %q must still be a field, got %v", want, got)
		}
	}
}

// isInternalMarker must cover every marker name any template can carry.
func TestIsInternalMarker_CoversEveryDeclaredMarker(t *testing.T) {
	for _, m := range append([]string{"statusIdx", "statusUri"}, allValidityMarkerNames()...) {
		if !isInternalMarker(m) {
			t.Errorf("%q is declared into display_order but not filtered from the issue form", m)
		}
	}
	// And must not swallow real claims that merely look similar.
	for _, ok := range []string{"validity", "valid", "status", "testa_id", "validFromDate"} {
		if isInternalMarker(ok) {
			t.Errorf("%q is an operator claim, not an internal marker", ok)
		}
	}
}

// The markers a schema DECLARES must be exactly the ones the form filters —
// the two lists are derived from validityMarkerNames precisely so they cannot
// drift apart.
func TestDeclaredMarkersAreFiltered(t *testing.T) {
	for _, std := range []string{"sd_jwt_vc (IETF)", "w3c_vcdm_2"} {
		schema := vctypes.Schema{
			ID: "custom-x", Name: "X", Std: std, Custom: true, Expires: true,
			FieldsSpec: []vctypes.FieldSpec{{Name: "testa_id", Datatype: "string"}},
		}
		for _, m := range validityMarkerNames(stdToCredentialFormat(schema.Std)) {
			if !isInternalMarker(m) {
				t.Errorf("[%s] declares marker %q but the issue form would render it", std, m)
			}
		}
	}
}
