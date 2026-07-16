package injicertify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Schema.Expires must survive the round-trip through certify's config.
//
// The regression this pins: Expires lives only in verifiably's store and no
// vendor advertises it, so ListSchemas — which rebuilds a Schema from certify's
// wellknown — reported false for a schema that had been saved as expiring. The
// two halves of the feature then read the flag from different objects and
// disagreed:
//
//	SaveCustomSchema (builder's schema, Expires=true)  -> template gets nbf/exp
//	IssueToWallet    (rebuilt schema,  Expires=false)  -> POSTs no window
//
// which leaves ${validUntilEpoch} unresolved and certify rejects the issuance:
// the schema became unissuable, and the issue form hid the Validity window.
//
// The earlier tests missed it because they hand-built Schema{Expires: true} and
// never went through the round-trip that loses it — so they were testing the
// halves, not the seam between them.

// serveOrder stands up a wellknown carrying the given `order`, exactly as
// certify would after SaveCustomSchema declared it.
func serveOrder(t *testing.T, order []string) *Adapter {
	t.Helper()
	body := map[string]any{
		"credential_configurations_supported": map[string]any{
			"custom-dk0ai8vrac3d": map[string]any{
				"format":  "vc+sd-jwt",
				"vct":     "https://verifiably.test/credentials/custom-dk0ai8vrac3d",
				"order":   order,
				"display": []map[string]any{{"name": "Delegate Testa Card V2", "locale": "en"}},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

// declaredOrder is what SaveCustomSchema writes into display_order for a
// schema, so the test drives the REAL contract rather than a guess at it.
func declaredOrder(t *testing.T, schema vctypes.Schema) []string {
	t.Helper()
	order := []string{}
	for _, f := range schema.FieldsSpec {
		order = append(order, f.Name)
	}
	order = append(order, "statusIdx", "statusUri")
	if schema.ExpiresWithWindow() {
		order = append(order, validityMarkerNames(stdToCredentialFormat(schema.Std))...)
	}
	return order
}

func TestListSchemas_ExpiresSurvivesTheRoundTrip(t *testing.T) {
	saved := vctypes.Schema{
		ID: "custom-dk0ai8vrac3d", Name: "Delegate Testa Card V2",
		Std: "sd_jwt_vc (IETF)", Custom: true, Expires: true,
		FieldsSpec: []vctypes.FieldSpec{{Name: "onBehalfOf"}, {Name: "role"}},
	}

	got, err := serveOrder(t, declaredOrder(t, saved)).ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 schema, got %d", len(got))
	}
	if !got[0].ExpiresWithWindow() {
		t.Error("a schema saved as expiring must still report as expiring after certify hands it back — " +
			"otherwise the template demands a window that issuance never sends, and the schema cannot be issued")
	}
	// The markers are the record of the flag, not operator input.
	for _, f := range got[0].FieldsSpec {
		if isValidityMarker(f.Name) {
			t.Errorf("%q must stay an internal marker, not become a claim field", f.Name)
		}
	}
}

func TestListSchemas_NonExpiringStaysNonExpiring(t *testing.T) {
	saved := vctypes.Schema{
		ID: "custom-dk0ai8vrac3d", Name: "Plain Card",
		Std: "sd_jwt_vc (IETF)", Custom: true,
		FieldsSpec: []vctypes.FieldSpec{{Name: "testa_id"}},
	}

	got, err := serveOrder(t, declaredOrder(t, saved)).ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ExpiresWithWindow() {
		t.Error("a schema with no expiry must not acquire one on the way back — " +
			"the issue form would demand a window its template cannot carry")
	}
}

// The whole loop, end to end: what SaveCustomSchema writes into the TEMPLATE
// and what ListSchemas reads back must agree about whether this credential
// expires. They are what disagreed in production.
func TestTemplateAndReconstructionAgreeOnExpiry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires bool
	}{
		{"expiring", true},
		{"non-expiring", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := vctypes.Schema{
				ID: "custom-dk0ai8vrac3d", Name: "X", Std: "sd_jwt_vc (IETF)",
				Custom: true, Expires: tc.expires,
				FieldsSpec: []vctypes.FieldSpec{{Name: "testa_id"}},
			}
			tmplWantsWindow := len(rawTemplate(t, saved, true)) > 0 &&
				containsMarker(rawTemplate(t, saved, true), "${validUntilEpoch}")

			got, err := serveOrder(t, declaredOrder(t, saved)).ListSchemas(t.Context(), "Inji Certify · Pre-Auth")
			if err != nil {
				t.Fatal(err)
			}
			issuanceSendsWindow := got[0].ExpiresWithWindow()

			if tmplWantsWindow != issuanceSendsWindow {
				t.Errorf("template wants a window=%v but issuance would send one=%v — "+
					"certify rejects the unresolved marker and the schema cannot be issued",
					tmplWantsWindow, issuanceSendsWindow)
			}
		})
	}
}

func containsMarker(s, marker string) bool {
	for i := 0; i+len(marker) <= len(s); i++ {
		if s[i:i+len(marker)] == marker {
			return true
		}
	}
	return false
}
