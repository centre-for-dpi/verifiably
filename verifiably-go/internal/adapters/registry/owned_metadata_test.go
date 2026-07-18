package registry

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Verifiably-owned schema metadata must survive the vendor merge.
//
// Both entries for a custom schema end up in the list — the vendor
// re-advertises what we registered with it — and findSchemaByID takes the FIRST
// match, the vendor's. A vendor only knows what it stores, and Expires is our
// own concept, so a rebuilt vendor entry reports false and shadows the truth in
// our store. That silently un-expires a credential: the issue form hides the
// Validity window and issuance refuses to send the window the template already
// demands, so certify rejects the unresolved marker.
//
// This matters most for adapters that CANNOT persist the flag vendor-side —
// walt.id and CREDEBL rebuild from their wellknown with nothing to read back.

func TestApplyOwnedMetadata_VendorEntryInheritsExpires(t *testing.T) {
	vendor := []vctypes.Schema{
		{ID: "custom-1", Name: "Delegate Testa Card V2", Vct: "https://issuer.test/credentials/custom-1"},
		{ID: "stock-1", Name: "Stock Credential"},
	}
	custom := []vctypes.Schema{
		{ID: "custom-1", Name: "Delegate Testa Card V2", Custom: true, Expires: true},
	}

	got := applyOwnedMetadata(vendor, custom)

	if !got[0].ExpiresWithWindow() {
		t.Error("the vendor entry shadows the custom one at lookup, so it must inherit Expires — " +
			"otherwise a schema saved as expiring silently stops expiring")
	}
	// Enrich, never replace: the vendor is authoritative for what it owns, and
	// the verifier's presentation definition matches the held token on this vct.
	if got[0].Vct != "https://issuer.test/credentials/custom-1" {
		t.Errorf("the vendor's pinned Vct must survive, got %q", got[0].Vct)
	}
	if got[0].Name != "Delegate Testa Card V2" {
		t.Errorf("unexpected Name rewrite: %q", got[0].Name)
	}
	// A stock schema we know nothing about must be left alone.
	if got[1].ExpiresWithWindow() {
		t.Error("a vendor schema with no matching custom entry must not acquire an expiry")
	}
}

// A schema saved WITHOUT the toggle must not acquire an expiry from the merge —
// the issue form would then demand a window its template cannot carry.
func TestApplyOwnedMetadata_NonExpiringCustomLeavesVendorAlone(t *testing.T) {
	vendor := []vctypes.Schema{{ID: "custom-1", Name: "Plain"}}
	custom := []vctypes.Schema{{ID: "custom-1", Name: "Plain", Custom: true}}

	if applyOwnedMetadata(vendor, custom)[0].ExpiresWithWindow() {
		t.Error("a non-expiring custom schema must not make the vendor entry expire")
	}
}

// A variant id resolves to its parent schema (HasVariantID), so a variant of an
// expiring schema must inherit the flag too.
func TestApplyOwnedMetadata_CoversVariantIDs(t *testing.T) {
	vendor := []vctypes.Schema{{ID: "custom-1-sdjwt", Name: "Testa (SD-JWT)"}}
	custom := []vctypes.Schema{{
		ID: "custom-1", Name: "Testa", Custom: true, Expires: true,
		Variants: []vctypes.SchemaVariant{{ID: "custom-1-sdjwt"}},
	}}

	if !applyOwnedMetadata(vendor, custom)[0].ExpiresWithWindow() {
		t.Error("a variant of an expiring schema must inherit the expiry")
	}
}

// A schema saved the legacy way (a valid_until claim field rather than the
// flag) must still be recognised as expiring.
func TestApplyOwnedMetadata_HonoursLegacyValidUntilSchema(t *testing.T) {
	vendor := []vctypes.Schema{{ID: "custom-1", Name: "Legacy"}}
	custom := []vctypes.Schema{{
		ID: "custom-1", Name: "Legacy", Custom: true,
		FieldsSpec: []vctypes.FieldSpec{{Name: "valid_until", Format: "datetime"}},
	}}

	if !applyOwnedMetadata(vendor, custom)[0].ExpiresWithWindow() {
		t.Error("a legacy valid_until schema declares a window too")
	}
}

// Guard the empty cases rather than index into nothing.
func TestApplyOwnedMetadata_EmptyInputs(t *testing.T) {
	if got := applyOwnedMetadata(nil, []vctypes.Schema{{ID: "a", Expires: true}}); got != nil {
		t.Errorf("no vendor schemas = nothing to enrich, got %v", got)
	}
	vendor := []vctypes.Schema{{ID: "a"}}
	if got := applyOwnedMetadata(vendor, nil); len(got) != 1 || got[0].Expires {
		t.Errorf("no custom schemas = vendor untouched, got %v", got)
	}
}
