// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"strconv"
	"time"
)

// The marker names of the Inji Certify credential template. The
// pre-authorized data provider puts the value of each marker into the
// template of the credential. A marker the template never declared is an
// unknown claim, and Inji rejects the whole request.
const (
	// StatusIndexClaim carries the index of the credential in the status
	// list.
	StatusIndexClaim = "statusIdx"
	// StatusURIClaim carries the public address of the status list.
	StatusURIClaim = "statusUri"
	// ValidFromClaim carries the start of the validity window.
	ValidFromClaim = "validFrom"
	// ValidUntilClaim carries the end of the validity window.
	ValidUntilClaim = "validUntil"
)

// StatusEntry points at the status list entry of one credential.
type StatusEntry struct {
	// Index is the position of the credential in the list.
	Index int64
	// URL is the public address of the list.
	URL string
}

// Validity is the period a credential is valid in.
type Validity struct {
	// From is the start. A zero time leaves the start open.
	From time.Time
	// Until is the end. A zero time leaves the end open.
	Until time.Time
}

// StatusMarkers reports whether the format uses the status markers. The
// SD-JWT template carries an IETF token status list pointer. The JSON-LD
// template carries a W3C bitstring status list entry. Both read the same
// two markers.
func StatusMarkers(format string) bool {
	return format == "vc+sd-jwt" || format == "dc+sd-jwt" || format == "ldp_vc"
}

// Claims returns the claim map of one subject for the staging call.
//
// The map always carries the two status markers when the format uses
// them. An empty status entry gives the index 0 and an empty address. A
// missing marker would leave the placeholder in the template unresolved,
// and Inji then answers with a bad request.
func Claims(subject map[string]any, format string, status StatusEntry, v Validity, withValidity bool) map[string]any {
	out := make(map[string]any, len(subject)+4)
	for k, val := range subject {
		out[k] = val
	}
	if StatusMarkers(format) {
		out[StatusIndexClaim] = strconv.FormatInt(status.Index, 10)
		out[StatusURIClaim] = status.URL
	}
	if withValidity {
		if !v.From.IsZero() {
			out[ValidFromClaim] = v.From.UTC().Format(time.RFC3339)
		}
		if !v.Until.IsZero() {
			out[ValidUntilClaim] = v.Until.UTC().Format(time.RFC3339)
		}
	}
	return out
}

// AuthorizationCodeOffer returns the credential offer document of the
// authorization code flow. Inji Certify hosts no such offer itself, so
// the adapter builds it and serves it at its own address.
func AuthorizationCodeOffer(issuer, configurationID, issuerState, authorizationServer string) map[string]any {
	grant := map[string]any{"issuer_state": issuerState}
	if authorizationServer != "" {
		grant["authorization_server"] = authorizationServer
	}
	return map[string]any{
		"credential_issuer":            issuer,
		"credential_configuration_ids": []string{configurationID},
		"grants":                       map[string]any{"authorization_code": grant},
	}
}
