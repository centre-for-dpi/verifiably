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

	// Delegation does not force expiry: without the toggle the schema declares
	// no validity window, and its credentials never expire.
	built := currentBuilderSchema(sess, *d)
	if built.ExpiresWithWindow() {
		t.Error("a delegation schema without the expiry toggle must not declare a validity window")
	}

	// Opting in marks the SCHEMA as expiring; the issuer sets the actual window
	// per-issuance.
	d.Expiry = true
	withExpiry := currentBuilderSchema(sess, *d)
	if !withExpiry.ExpiresWithWindow() {
		t.Fatal("delegation + expiry toggle must declare a validity window")
	}
	// The window is envelope metadata (SD-JWT nbf/exp), NOT a subject claim: a
	// claim is selectively disclosable, so a holder could withhold their own
	// expiry and escape the temporal gate.
	if _, present := exactlyOneField(withExpiry, "valid_until"); present {
		t.Error("expiry must not be a subject claim — it belongs in the credential envelope")
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

// The opt-in expiry toggle marks a schema as carrying a validity window,
// DPG-agnostically, and stays OFF by default (no coupling).
func TestCurrentBuilderSchema_ExpiryToggle(t *testing.T) {
	sess := &Session{IssuerDpg: "walt.id"}
	base := []vctypes.FieldSpec{{Name: "givenName", Datatype: "string"}}

	// OFF by default → the credential never expires, and says so.
	off := currentBuilderSchema(sess, builderData{Name: "Card", Fields: base})
	if off.ExpiresWithWindow() {
		t.Error("expiry OFF must not declare a validity window")
	}

	// ON → the schema declares a window; the issuer supplies the dates at issue
	// time and each adapter writes them into its format's native slot.
	on := currentBuilderSchema(sess, builderData{Name: "Card", Fields: base, Expiry: true})
	if !on.ExpiresWithWindow() {
		t.Fatal("expiry ON must declare a validity window")
	}
	// Envelope, not claims — see TestApplyDelegationPreset_ExpiryOptIn.
	if _, present := exactlyOneField(on, "valid_until"); present {
		t.Error("expiry must not be added as a subject claim")
	}

	// Composed with the delegation preset: still just the flag, no claim.
	dg := &builderData{Name: "Deleg", Expiry: true}
	applyDelegationPreset(dg)
	composed := currentBuilderSchema(sess, *dg)
	if !composed.ExpiresWithWindow() {
		t.Error("delegation + expiry must declare a validity window")
	}
}

// Schemas built before the envelope window existed opted in with a valid_until
// datetime CLAIM. Those must keep working — an operator's saved schema cannot
// silently stop expiring because we changed where the window lives.
func TestExpiresWithWindow_HonoursLegacyValidUntilClaim(t *testing.T) {
	legacy := vctypes.Schema{
		Name: "Legacy Card",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "givenName", Datatype: "string"},
			{Name: "valid_until", Datatype: "string", Format: "datetime"},
		},
	}
	if !legacy.ExpiresWithWindow() {
		t.Error("a schema with a legacy valid_until claim must still declare a window")
	}
	plain := vctypes.Schema{Name: "Plain", FieldsSpec: []vctypes.FieldSpec{{Name: "givenName"}}}
	if plain.ExpiresWithWindow() {
		t.Error("a schema with neither the flag nor valid_until must not declare a window")
	}
}
