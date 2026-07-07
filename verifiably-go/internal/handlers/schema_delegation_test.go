package handlers

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// The delegation preset carries the capability expiry as a DERIVED valid_until
// field, not a manual row: it enables Expiry (the "This credential expires"
// toggle) and leaves valid_until OUT of the editable field rows. The single
// valid_until{string,datetime} then comes from currentBuilderSchema's funnel —
// so the operator no longer sees a redundant, easily-mistyped valid_until row,
// while every other capability field stays a generic (no-Format) input.
func TestApplyDelegationPreset_ValidUntilViaExpiry(t *testing.T) {
	d := &builderData{}
	applyDelegationPreset(d)

	if d.Std != "sd_jwt_vc (IETF)" {
		t.Errorf("Std = %q, want sd_jwt_vc (IETF)", d.Std)
	}
	if !d.Expiry {
		t.Error("delegation preset must enable Expiry so valid_until is derived, not a manual row")
	}
	byName := map[string]vctypes.FieldSpec{}
	for _, f := range d.Fields {
		byName[f.Name] = f
	}

	// valid_until must NOT be an editable field row (it is derived by the funnel).
	if _, present := byName["valid_until"]; present {
		t.Error("valid_until must not be a preset field row — it is derived via Expiry")
	}
	if _, stale := byName["validUntil"]; stale {
		t.Error("stale camelCase validUntil field present — the expiry field is valid_until")
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

	// End-to-end through the funnel: the built schema carries exactly one
	// valid_until{string,datetime} (the derived capability expiry).
	sess := &Session{IssuerDpg: "Inji Certify · Pre-Auth"}
	built := currentBuilderSchema(sess, *d)
	vu, ok := exactlyOneField(built, "valid_until")
	if !ok {
		t.Fatal("built delegation schema must carry exactly one valid_until")
	}
	if vu.Datatype != "string" || vu.Format != "datetime" {
		t.Errorf("derived valid_until = {%q,%q}, want {string,datetime}", vu.Datatype, vu.Format)
	}
}

// exactlyOneField returns the named field and whether it appears EXACTLY once
// (so a duplicate reads as "not cleanly present" and fails the dedupe assertion).
func exactlyOneField(s vctypes.Schema, name string) (vctypes.FieldSpec, bool) {
	var found vctypes.FieldSpec
	n := 0
	for _, f := range s.FieldsSpec {
		if f.Name == name {
			found = f
			n++
		}
	}
	return found, n == 1
}

// The opt-in expiry toggle derives a valid_until datetime claim onto ANY schema
// (DPG-agnostic), stays OFF by default (no coupling), and never duplicates the
// field the delegation preset already contributes.
func TestCurrentBuilderSchema_ExpiryToggle(t *testing.T) {
	sess := &Session{IssuerDpg: "walt.id"}
	base := []vctypes.FieldSpec{{Name: "givenName", Datatype: "string"}}

	// OFF by default → no valid_until field (a credential with no expiry is not
	// coupled to one).
	off := currentBuilderSchema(sess, builderData{Name: "Card", Fields: base})
	if _, ok := exactlyOneField(off, "valid_until"); ok {
		t.Error("expiry OFF must not add a valid_until field")
	}

	// ON → a single valid_until datetime claim is appended (the temporal gate
	// reads this claim across SD-JWT top-level and W3C credentialSubject).
	on := currentBuilderSchema(sess, builderData{Name: "Card", Fields: base, Expiry: true})
	vu, ok := exactlyOneField(on, "valid_until")
	if !ok {
		t.Fatal("expiry ON must add exactly one valid_until field")
	}
	if vu.Datatype != "string" || vu.Format != "datetime" {
		t.Errorf("valid_until = {%q,%q}, want {string,datetime}", vu.Datatype, vu.Format)
	}

	// Composed with delegation (whose preset already contributes valid_until):
	// dedupe → still exactly one, no duplicate.
	dg := &builderData{Name: "Deleg", Expiry: true}
	applyDelegationPreset(dg)
	composed := currentBuilderSchema(sess, *dg)
	if _, ok := exactlyOneField(composed, "valid_until"); !ok {
		t.Error("delegation + expiry must yield exactly one valid_until (dedupe), got 0 or >1")
	}
}
