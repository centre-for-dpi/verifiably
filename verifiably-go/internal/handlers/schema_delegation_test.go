package handlers

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// The delegation preset provides ONLY the capability fields (onBehalfOf/role/
// allowedAction). It must NOT force expiry on: valid_until is opt-in via the
// "This credential expires" toggle, so an issuer never gets a valid_until field
// they didn't create — which, unprovisioned, renders as ${valid_until} and fails
// the holder's claim.
func TestApplyDelegationPreset_ExpiryOptIn(t *testing.T) {
	d := &builderData{}
	applyDelegationPreset(d)

	if d.Std != "sd_jwt_vc (IETF)" {
		t.Errorf("Std = %q, want sd_jwt_vc (IETF)", d.Std)
	}
	if d.Expiry {
		t.Error("delegation preset must NOT force Expiry — valid_until is opt-in only")
	}
	byName := map[string]vctypes.FieldSpec{}
	for _, f := range d.Fields {
		byName[f.Name] = f
	}

	// valid_until must NOT be a preset field row.
	if _, present := byName["valid_until"]; present {
		t.Error("valid_until must not be a preset field row")
	}
	if _, stale := byName["validUntil"]; stale {
		t.Error("stale camelCase validUntil field present — the expiry field is valid_until")
	}

	// The capability fields stay generic dynamic inputs (no Format).
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

	sess := &Session{IssuerDpg: "Inji Certify · Pre-Auth"}

	// Without the expiry toggle, the built delegation schema carries NO valid_until
	// — the issuer isn't surprised by a field they never created.
	built := currentBuilderSchema(sess, *d)
	if _, present := exactlyOneField(built, "valid_until"); present {
		t.Error("a delegation schema without the expiry toggle must NOT carry valid_until")
	}

	// Opting in (ticking "This credential expires") derives exactly one
	// valid_until{string,datetime}.
	d.Expiry = true
	withExpiry := currentBuilderSchema(sess, *d)
	vu, ok := exactlyOneField(withExpiry, "valid_until")
	if !ok {
		t.Fatal("delegation + expiry toggle must derive exactly one valid_until")
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
