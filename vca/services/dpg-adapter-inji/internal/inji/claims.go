// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	claimstore "github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
)

// The marker names of the status and validity values of a subject. The
// claims store keeps them in its reserved columns, and the template of a
// configuration reads them there.
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

// ClaimsRow returns the row of the claims store for one subject
// (ADR-051 decision 4). names holds the claim names in column order, as
// ClaimNames gives them. A claim of the subject that the configuration
// does not declare is an error, as it was for the staging check of
// Certify. The status columns stay empty for a format without a status
// entry.
func ClaimsRow(key, configID string, names []string, subject map[string]any, format string,
	status StatusEntry, v Validity, expires time.Time,
) (claimstore.Row, error) {
	if len(names) > claimstore.MaxClaims {
		return claimstore.Row{}, fmt.Errorf("inji: %d claims, the claims store holds %d", len(names), claimstore.MaxClaims)
	}
	known := make(map[string]bool, len(names))
	values := make([]string, len(names))
	for i, name := range names {
		known[name] = true
		values[i] = claimstore.Value(subject[name])
		if err := claimstore.Check(values[i]); err != nil {
			return claimstore.Row{}, fmt.Errorf("inji: the claim %s: %w", name, err)
		}
	}
	var unknown []string
	for name := range subject {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return claimstore.Row{}, fmt.Errorf("inji: the configuration %s declares no claim %s", configID, strings.Join(unknown, ", "))
	}
	row := claimstore.Row{Subject: key, ConfigID: configID, ExpiresAt: expires, Claims: values}
	if StatusMarkers(format) {
		row.StatusIndex = strconv.FormatInt(status.Index, 10)
		row.StatusURI = status.URL
	}
	if !v.From.IsZero() {
		row.ValidFrom = v.From.UTC().Format(time.RFC3339)
	}
	if !v.Until.IsZero() {
		row.ValidUntil = v.Until.UTC().Format(time.RFC3339)
	}
	return row, nil
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
