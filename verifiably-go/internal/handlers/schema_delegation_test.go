package handlers

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// The delegation preset must carry the capability expiry as `valid_until`
// (underscore, dodging Certify's reserved ${validUntil}) AND type it as a
// datetime policy field so the issue form renders a datetime-local picker,
// while every other capability field stays a generic (no-Format) input.
func TestApplyDelegationPreset_ValidUntilDatetime(t *testing.T) {
	d := &builderData{}
	applyDelegationPreset(d)

	if d.Std != "sd_jwt_vc (IETF)" {
		t.Errorf("Std = %q, want sd_jwt_vc (IETF)", d.Std)
	}
	byName := map[string]vctypes.FieldSpec{}
	for _, f := range d.Fields {
		byName[f.Name] = f
	}

	vu, ok := byName["valid_until"]
	if !ok {
		t.Fatal("valid_until field missing from delegation preset")
	}
	if vu.Format != "datetime" {
		t.Errorf("valid_until Format = %q, want %q", vu.Format, "datetime")
	}
	if _, stale := byName["validUntil"]; stale {
		t.Error("stale camelCase validUntil field present — must be valid_until")
	}

	// The other capability fields stay generic dynamic inputs (no Format).
	for _, n := range []string{"onBehalfOf", "role", "allowedAction"} {
		f, ok := byName[n]
		if !ok {
			t.Errorf("capability field %q missing", n)
			continue
		}
		if f.Format != "" {
			t.Errorf("%s should stay generic (no Format), got %q", n, f.Format)
		}
	}
}
