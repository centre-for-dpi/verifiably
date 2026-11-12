package handlers

import (
	"os"
	"sort"
	"strings"

	"github.com/verifiably/verifiably-go/internal/issuance"
)

// Credentials that holders claim themselves (POST /api/v1/self-issue, the
// wallet's "Discover -> Get") are logged under apiOwnerKey("self-service").
// No operator session ever has that owner key, so these credentials never
// appear on /issuer/credentials and can never be revoked from the UI.
//
// VERIFIABLY_SELF_SERVICE_VIEWERS lets named operators see and revoke them:
//   - unset or empty: original behaviour (nobody sees them)
//   - a comma-separated list of operator owner keys (sessionOwnerKey values)
//   - "*": every logged-in operator (convenient for single-tenant/staging)
//
// Revoking such a credential flips its bit in the status list it was bound to
// at issuance and marks the log entry revoked under its real owner key, so the
// audit trail still shows it as a self-service issuance.

// selfServiceOwner is the owner key self-issued credentials are logged under.
func selfServiceOwner() string { return apiOwnerKey("self-service") }

// selfServiceVisibleTo reports whether the operator with this owner key may
// see and revoke self-issued credentials.
func selfServiceVisibleTo(owner string) bool {
	v := strings.TrimSpace(os.Getenv("VERIFIABLY_SELF_SERVICE_VIEWERS"))
	if v == "" || owner == "" || owner == selfServiceOwner() {
		return false
	}
	if v == "*" {
		return true
	}
	for _, k := range strings.Split(v, ",") {
		if strings.TrimSpace(k) == owner {
			return true
		}
	}
	return false
}

// mayManageIssued reports whether operator `owner` may revoke a log entry
// owned by recOwner: their own entries, plus self-issued ones when allowed.
func mayManageIssued(owner, recOwner string) bool {
	if recOwner == owner {
		return true
	}
	return recOwner == selfServiceOwner() && selfServiceVisibleTo(owner)
}

// withSelfService appends the self-issued entries that match the same
// query/std/format/state filter and DPG track when the operator may see them,
// newest first. When the operator may not, items is returned unchanged.
func (h *H) withSelfService(owner string, filter issuance.Filter, dpg string, items []issuance.IssuedCredential) []issuance.IssuedCredential {
	if h.IssuanceLog == nil || !selfServiceVisibleTo(owner) {
		return items
	}
	f := filter
	f.OwnerKey = selfServiceOwner()
	extra := filterIssuedByDpg(h.IssuanceLog.List(f), dpg)
	if len(extra) == 0 {
		return items
	}
	out := make([]issuance.IssuedCredential, 0, len(items)+len(extra))
	out = append(out, items...)
	out = append(out, extra...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out
}
