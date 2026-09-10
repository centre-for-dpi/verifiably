package handlers

import "testing"

// TestCanonicalStd locks the schema-builder Std normalisation that fixed
// the "waltid: unsupported schema standard \"sd_jwt_vc\"" regression seen
// on 2026-04-29. The dropdown emits the bare key (parens + spaces in
// <option value=> would need careful escaping); adapters key off the
// long form. Without this shim, every SD-JWT custom schema fails at
// issue time.
func TestCanonicalStd(t *testing.T) {
	cases := map[string]string{
		"sd_jwt_vc":        "sd_jwt_vc (IETF)",
		"sd_jwt_vc (IETF)": "sd_jwt_vc (IETF)",
		"  sd_jwt_vc  ":    "sd_jwt_vc (IETF)",
		"w3c_vcdm_2":       "w3c_vcdm_2",
		"w3c_vcdm_1":       "w3c_vcdm_1",
		"mso_mdoc":         "mso_mdoc",
		"":                 "",
		"some_other_value": "some_other_value",
	}
	for in, want := range cases {
		if got := canonicalStd(in); got != want {
			t.Errorf("canonicalStd(%q) = %q, want %q", in, got, want)
		}
	}
}
