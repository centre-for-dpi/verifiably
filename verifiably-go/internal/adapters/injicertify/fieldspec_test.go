package injicertify

import "testing"

// fieldSpecFor infers an input Format from a claim's NAME (Inji Certify configs
// carry no per-field type). The heuristic must not date-ify plain string fields:
// the delegation capability's allowedAction ends in "on" but is a string, and a
// date-typed allowedAction gets emptied by the RFC3339 normalization at issue
// time (breaking the capability + the mobile wallet). valid_until/valid_from are
// datetime policy fields, not date-only.
func TestFieldSpecFor_Formats(t *testing.T) {
	cases := []struct {
		name       string
		wantFormat string
	}{
		// The regression: a string field that merely ends in "on"/"at".
		{"allowedAction", ""},
		{"institution", ""},
		{"role", ""},
		{"onBehalfOf", ""},
		// Datetime policy fields (both conventions).
		{"valid_until", "datetime"},
		{"validUntil", "datetime"},
		{"valid_from", "datetime"},
		{"validFrom", "datetime"},
		// Genuine date fields still detected.
		{"issuedOn", "date"},
		{"updatedAt", "date"},
		{"issued_on", "date"},
		{"expires_at", "date"},
		{"dateOfBirth", "date"},
		{"expiryDate", "date"},
		// Other formats unaffected.
		{"email", "email"},
		{"phone", "tel"},
		{"homepageUrl", "uri"},
	}
	for _, c := range cases {
		if got := fieldSpecFor(c.name).Format; got != c.wantFormat {
			t.Errorf("fieldSpecFor(%q).Format = %q, want %q", c.name, got, c.wantFormat)
		}
	}
}
