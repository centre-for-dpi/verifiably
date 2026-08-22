package mdoc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DrivingPrivilegesArrayConfigSize is the number of entries the walt.id
// isoMdl profile's `driving_privileges` arrayConfig declares.
//
// This is an EXACT count, not a floor or a ceiling. issuer-api2 walks the
// input array and its arrayConfig list in lockstep, one config per element,
// and rejects any other length with:
//
//	Json array sizes (input & config) are not equal
//
// which is already recorded verbatim in TODO.md F4 after it cost several
// attempts to diagnose. The profile at
// deploy/k8s/config/issuer2/issuer2-profiles.conf declares two positionally
// identical object configs, so exactly two entries convert.
//
// Consequence for the UI: the issue form must submit exactly this many
// entries. PadDrivingPrivileges below is what guarantees it, so an operator
// who holds a single category is not forced to invent a second one.
//
// Raising this constant alone changes nothing — the profile's arrayConfig
// list must grow by the same number of entries, or issuance breaks for
// every mDL.
const DrivingPrivilegesArrayConfigSize = 2

// DrivingPrivilege is one entry of the driving_privileges array as it travels
// to walt.id: plain JSON, with dates as "YYYY-MM-DD" strings that the
// profile's `stringToFullDate` conversion turns into CBOR full-dates.
//
// This is deliberately NOT internal/mdl.DrivingPrivilege. That type is the
// VERIFIER's CBOR model (its date fields are cbor-tagged *FullDate), and the
// mediator boundary says we translate rather than encode — walt.id's
// issuer-api2 owns CBOR. Reusing the verifier type here would mean marshalling
// a CBOR-shaped struct to JSON and would drag the emitter role into a package
// documented as read-only. The two shapes are asserted to agree field-for-field
// in drivingprivileges_test.go, so they cannot silently diverge.
type DrivingPrivilege struct {
	VehicleCategoryCode string `json:"vehicle_category_code"`
	IssueDate           string `json:"issue_date,omitempty"`
	ExpiryDate          string `json:"expiry_date,omitempty"`
}

// PadDrivingPrivileges makes a list exactly DrivingPrivilegesArrayConfigSize
// long so it satisfies the profile's fixed-size arrayConfig.
//
// Padding entries repeat the LAST real entry rather than being blank. A blank
// pad would carry empty issue_date/expiry_date strings, and the profile maps
// both through `stringToFullDate`, which fails on an empty string with a
// java.time.format.DateTimeParseException reporting that an empty Text could
// not be parsed at index 0 — the second error string recorded in TODO.md F4.
// Repeating a valid entry keeps every date parseable.
//
// Duplicating a privilege is a real (if redundant) statement about the holder:
// it asserts a category they genuinely hold, twice. That is materially safer
// than the alternatives — a blank entry asserts a privilege with no category
// code, and a fabricated one asserts a category the holder may not have.
//
// Over-long input is truncated, since the profile cannot convert the extra
// entries at all. The caller is expected to have capped the form first; this
// is the backstop.
func PadDrivingPrivileges(in []DrivingPrivilege) []DrivingPrivilege {
	if len(in) == 0 {
		return nil
	}
	if len(in) >= DrivingPrivilegesArrayConfigSize {
		return in[:DrivingPrivilegesArrayConfigSize]
	}
	out := make([]DrivingPrivilege, 0, DrivingPrivilegesArrayConfigSize)
	out = append(out, in...)
	for len(out) < DrivingPrivilegesArrayConfigSize {
		out = append(out, in[len(in)-1])
	}
	return out
}

// EncodeDrivingPrivileges renders the entries as the JSON array walt.id
// expects, padded to the profile's fixed size. Returns nil (not an empty
// array) when there is nothing to send, so the caller omits the claim
// entirely and lets issuer-api2 keep the profile's own value — sending `[]`
// would trip the size check.
func EncodeDrivingPrivileges(in []DrivingPrivilege) (json.RawMessage, error) {
	cleaned := make([]DrivingPrivilege, 0, len(in))
	for _, p := range in {
		p.VehicleCategoryCode = strings.TrimSpace(p.VehicleCategoryCode)
		p.IssueDate = strings.TrimSpace(p.IssueDate)
		p.ExpiryDate = strings.TrimSpace(p.ExpiryDate)
		if p.VehicleCategoryCode == "" {
			// An entry with no category code asserts nothing. Dropping it is
			// what lets the form render spare blank rows the operator can
			// ignore.
			continue
		}
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(PadDrivingPrivileges(cleaned))
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode driving_privileges: %w", err)
	}
	return raw, nil
}
