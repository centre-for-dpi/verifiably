package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

// The issuance-time validity window contract, shared by the issue form and the
// API so they cannot disagree.
//
// The rule is forced by Inji Certify's static per-schema template, not chosen:
// an expiring schema's SD-JWT template carries the unquoted
// `"exp": ${validUntilEpoch}` (NumericDate is a JSON number), so a blank value
// renders `"exp": ,` — invalid JSON — and certify rejects the whole issuance
// with json_processing_error. Catching it here turns a vendor 400 into
// something an operator can act on.

func expiringSchema() vctypes.Schema {
	return vctypes.Schema{Name: "Testa Card V2", Std: "sd_jwt_vc (IETF)", Custom: true, Expires: true}
}

func plainSchema() vctypes.Schema {
	return vctypes.Schema{Name: "Business Licence", Std: "sd_jwt_vc (IETF)", Custom: true}
}

func TestResolveIssuanceWindow(t *testing.T) {
	now := time.Date(2026, 7, 16, 17, 41, 0, 0, time.UTC)
	const (
		from  = "2026-07-16T17:32:00Z"
		until = "2026-07-16T17:35:00Z"
	)

	t.Run("expiring schema carries the window through", func(t *testing.T) {
		gotFrom, gotUntil, err := resolveIssuanceWindow(expiringSchema(), from, until, now)
		if err != nil {
			t.Fatal(err)
		}
		if gotFrom != from || gotUntil != until {
			t.Errorf("window = (%q,%q), want (%q,%q)", gotFrom, gotUntil, from, until)
		}
	})

	t.Run("expiring schema requires valid_until", func(t *testing.T) {
		_, _, err := resolveIssuanceWindow(expiringSchema(), from, "", now)
		if err == nil {
			t.Fatal("a schema that declares an expiry must be given one — a blank exp renders invalid JSON and certify 400s")
		}
		// The operator has to know what to do about it.
		if !strings.Contains(err.Error(), "Valid until") {
			t.Errorf("error must name the field to fill, got: %v", err)
		}
	})

	t.Run("blank valid_from defaults to the issuance instant", func(t *testing.T) {
		gotFrom, gotUntil, err := resolveIssuanceWindow(expiringSchema(), "", until, now)
		if err != nil {
			t.Fatal(err)
		}
		if gotFrom != now.Format(time.RFC3339) {
			t.Errorf("validFrom = %q, want the issuance instant %q", gotFrom, now.Format(time.RFC3339))
		}
		if gotUntil != until {
			t.Errorf("validUntil = %q, want %q", gotUntil, until)
		}
		// A half-filled window must never leave a marker empty.
		if gotFrom == "" {
			t.Error("validFrom must never resolve empty for an expiring schema — it renders `\"nbf\": ,`")
		}
	})

	t.Run("non-expiring schema gets no window", func(t *testing.T) {
		gotFrom, gotUntil, err := resolveIssuanceWindow(plainSchema(), "", "", now)
		if err != nil {
			t.Fatal(err)
		}
		if gotFrom != "" || gotUntil != "" {
			t.Errorf("window = (%q,%q), want empty — this credential never expires", gotFrom, gotUntil)
		}
	})

	t.Run("non-expiring schema rejects a window rather than dropping it", func(t *testing.T) {
		// The adapters only write temporal claims into a template that declares
		// them, so dates on a non-expiring schema would be silently ignored —
		// the same silent-drop that let 0/9 credentials never expire.
		_, _, err := resolveIssuanceWindow(plainSchema(), from, until, now)
		if err == nil {
			t.Fatal("a window on a non-expiring schema must be refused, not silently dropped")
		}
		if !strings.Contains(err.Error(), "This credential expires") {
			t.Errorf("error must point at the schema toggle, got: %v", err)
		}
	})

	t.Run("legacy valid_until schema still expires", func(t *testing.T) {
		legacy := vctypes.Schema{
			Name: "Legacy", Std: "sd_jwt_vc (IETF)",
			FieldsSpec: []vctypes.FieldSpec{{Name: "valid_until", Format: "datetime"}},
		}
		if _, _, err := resolveIssuanceWindow(legacy, from, until, now); err != nil {
			t.Errorf("a schema opted in the legacy way must still accept a window: %v", err)
		}
	})
}
