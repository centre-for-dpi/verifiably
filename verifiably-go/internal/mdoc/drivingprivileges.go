package mdoc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DrivingPrivilegesMaxCategories is the largest number of driving
// categories a single mDL can carry in this deployment.
//
// Unlike its predecessor (DrivingPrivilegesArrayConfigSize), this is a
// CEILING, not an exact count. walt.id's arrayConfig still requires an
// exact-length match — confirmed empirically against a real
// issuer-api2:0.23.1 that there is no variable-length mechanism in its
// config model at all — but that exactness is now handled by having one
// walt.id profile per real category count (isoMdl_1cat..isoMdl_4cat, see
// deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf), selected by
// internal/adapters/waltid's mdlProfileForCategoryCount. This constant
// only bounds how many profiles exist and how many rows the issue form
// renders.
//
// Raising this alone changes nothing: a new profile
// (isoMdl_(N+1)cat) with its own arrayConfig of N+1 entries must be added
// to issuer2-profiles.baseline.conf and mdlProfileForCategoryCount must
// learn to select it, or an operator entering N+1 categories gets
// rejected by buildIssuer2Offer before ever reaching walt.id.
const DrivingPrivilegesMaxCategories = 4

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

// EncodeDrivingPrivileges renders the entries as the JSON array walt.id
// expects. Returns nil (not an empty array) when there is nothing to send,
// so the caller omits the claim entirely and lets issuer-api2 keep the
// profile's own value — sending `[]` would trip the size check.
//
// Never pads. Each real, non-blank entry the caller supplies survives
// as-is; the caller (buildIssuer2Offer) is responsible for choosing the
// walt.id profile whose arrayConfig matches this exact count. Truncates
// to DrivingPrivilegesMaxCategories as a backstop only — the issue form
// caps entry at that same limit first (see issuance.go's error when the
// operator fills more rows than the ceiling), so this path is not
// expected to be exercised in the normal UI flow.
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
	if len(cleaned) > DrivingPrivilegesMaxCategories {
		cleaned = cleaned[:DrivingPrivilegesMaxCategories]
	}
	raw, err := json.Marshal(cleaned)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode driving_privileges: %w", err)
	}
	return raw, nil
}
