package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// statusListKindFor maps a Schema.Std to the status list kind verifiably-go
// hosts for that taxonomy. Returns "" for credentials whose revocation
// flow we don't model (mso_mdoc → MSO/IACA, legacy jwt_vc → out of scope).
func statusListKindFor(std string) string {
	switch std {
	case "w3c_vcdm_2", "w3c_vcdm_1":
		return "bitstring"
	case "sd_jwt_vc (IETF)", "sd_jwt_vc":
		return "token"
	default:
		return ""
	}
}

// allocateStatusListBinding picks the right Store for a schema's Std and
// reserves an index. Returns (binding, store) so the caller can roll back
// on issuance failure — Allocate persists the next-free counter
// immediately, and we don't want the index to drift past the last
// successful issuance just because walt.id 5xx'd.
//
// issuerDpg selects that DPG's own list, so revoking a credential from one
// issuer can't flip a bit in another's list. An unknown or empty DPG falls
// back to the default list rather than dropping revocability.
//
// Returns (nil, nil, nil) when the schema's Std doesn't support a status
// list OR when the corresponding Store isn't configured. Issuance proceeds
// without a binding in that case.
func (h *H) allocateStatusListBinding(issuerDpg string, schema vctypes.Schema) (*backend.StatusListBinding, error) {
	kind := statusListKindFor(schema.Std)
	if kind == "" {
		return nil, nil
	}
	entry := h.statusListFor(issuerDpg, kind)
	if entry == nil || entry.Store == nil {
		return nil, nil
	}
	store := entry.Store
	idx, err := store.Allocate()
	if err != nil {
		return nil, fmt.Errorf("status list allocate: %w", err)
	}
	return &backend.StatusListBinding{
		Type:       store.GetKind(),
		ListID:     store.GetListID(),
		Index:      idx,
		PublishURL: store.GetPublishURL(),
	}, nil
}

// recordIssuance writes the audit-log entry after a successful walt.id
// issuance. Invoked from the issuance handler. The HolderHint is the
// first non-empty of a small allowlist of "looks like a name / id" field
// names so the list page is searchable by holder without us guessing
// per-schema. Subject fields are stored verbatim — they're already in the
// session anyway.
func (h *H) recordIssuance(sess *Session, schema vctypes.Schema, issuerDpg string, subject map[string]string, offerURI string, binding *backend.StatusListBinding) {
	if h.IssuanceLog == nil {
		return
	}
	id := newIssuanceID()
	hint := ""
	for _, k := range []string{"fullName", "name", "given_name", "id", "individualId", "vehicleNumber", "farmerID"} {
		if v := strings.TrimSpace(subject[k]); v != "" {
			hint = v
			break
		}
	}
	// Resolve the wire format from the active variant. Schema.ID after
	// ApplyVariant matches the variant's ID; Schema itself doesn't carry
	// a top-level Format. Fall back to Std so the log column is never empty.
	format := schema.Std
	for _, v := range schema.Variants {
		if v.ID == schema.ID {
			format = v.Format
			break
		}
	}
	rec := issuance.IssuedCredential{
		ID:            id,
		SchemaID:      schema.ID,
		SchemaName:    schema.Name,
		Std:           schema.Std,
		Format:        format,
		IssuerDpg:     issuerDpg,
		// OwnerKey scopes the entry to the issuing operator so the list
		// page never surfaces this credential to a different OIDC
		// subject. See sessionOwnerKey for the derivation.
		OwnerKey:      sessionOwnerKey(sess),
		HolderHint:    hint,
		SubjectFields: subject,
		OfferURI:      offerURI,
	}
	if binding != nil {
		rec.StatusList = &issuance.StatusListEntry{
			Type:   binding.Type,
			ListID: binding.ListID,
			Index:  binding.Index,
		}
	}
	if _, err := h.IssuanceLog.Append(rec); err != nil {
		// Don't fail the issuance — the credential is in the holder's
		// wallet either way. Just log and move on so the operator's flow
		// stays smooth.
		fmt.Printf("issuance log: append %s: %v\n", id, err)
	}
}

// sessionOwnerKey returns the stable per-issuer identity key used to
// scope the issuance log + custom-schema visibility. Mirrors the
// derivation in holderCtx (wallet.go): prefer AuthProvider+Subject (OIDC
// `sub` is guaranteed for an authenticated session and stable across
// devices), then email, then a session-scoped fallback so unauthenticated
// demo flows still self-isolate per browser.
//
// Returning "" would disable per-issuer scoping (admin/CLI semantics).
// We never want that for a request-bound handler — the fallback ensures
// every caller has SOME owner key.
func sessionOwnerKey(sess *Session) string {
	if sess.AuthProvider != "" && sess.UserSubject != "" {
		return sess.AuthProvider + "|" + sess.UserSubject
	}
	if sess.UserEmail != "" {
		return sess.UserEmail
	}
	return "session-" + sess.ID
}

// newIssuanceID mints a stable identifier for the IssuanceLog entry. The
// prefix lets `grep vc-` find them in logs; the millisecond timestamp
// makes them sort-friendly even before the JSON is materialized.
func newIssuanceID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("vc-%d-%s", time.Now().UTC().UnixMilli(), hex.EncodeToString(b[:]))
}

// issuedCredentialsData feeds the /issuer/credentials list page.
type issuedCredentialsData struct {
	Items   []issuance.IssuedCredential
	Stats   issuance.Stats
	Filter  issuance.Filter
	Stds    []string // chip row
	Formats []string
}

// ShowIssuedCredentials renders the list page.
func (h *H) ShowIssuedCredentials(w http.ResponseWriter, r *http.Request) {
	if h.IssuanceLog == nil {
		http.Error(w, "issuance log not configured", http.StatusNotFound)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	data := h.issuedCredentialsBody(sess, r)
	h.render(w, r, "issuer_issued_log", h.pageData(sess, data))
}

// IssuedCredentialsSearch handles HTMX search/filter on the same data.
func (h *H) IssuedCredentialsSearch(w http.ResponseWriter, r *http.Request) {
	if h.IssuanceLog == nil {
		http.Error(w, "issuance log not configured", http.StatusNotFound)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	// Capture the filter state on the session so a Revoke action's re-
	// render preserves what the user was looking at instead of resetting.
	q := r.URL.Query().Get("q")
	if v := r.FormValue("q"); v != "" {
		q = v
	}
	sess.IssuedQuery = q
	if v := r.FormValue("std"); v != "" || r.URL.Query().Has("std") {
		sess.IssuedStd = strings.TrimSpace(r.FormValue("std"))
		if sess.IssuedStd == "" {
			sess.IssuedStd = strings.TrimSpace(r.URL.Query().Get("std"))
		}
		if sess.IssuedStd == "all" {
			sess.IssuedStd = ""
		}
	}
	if v := r.FormValue("format"); v != "" || r.URL.Query().Has("format") {
		sess.IssuedFormat = strings.TrimSpace(r.FormValue("format"))
		if sess.IssuedFormat == "" {
			sess.IssuedFormat = strings.TrimSpace(r.URL.Query().Get("format"))
		}
		if sess.IssuedFormat == "all" {
			sess.IssuedFormat = ""
		}
	}
	if v := r.FormValue("state"); v != "" || r.URL.Query().Has("state") {
		sess.IssuedState = strings.TrimSpace(r.FormValue("state"))
		if sess.IssuedState == "" {
			sess.IssuedState = strings.TrimSpace(r.URL.Query().Get("state"))
		}
		if sess.IssuedState == "all" {
			sess.IssuedState = ""
		}
	}
	data := h.issuedCredentialsBody(sess, r)
	h.renderFragment(w, r, "fragment_issued_credentials_list", data)
}

// RevokeIssuedCredential flips the bit on the credential's status list
// entry, marks the log row revoked, and re-renders the row fragment so
// HTMX can swap it in place.
//
// The action is scoped per-issuer: a Get followed by an OwnerKey check
// + MarkRevoked-with-owner means a malicious POST against another
// issuer's credential id (id-guessing or pasting from logs) returns
// 404, never flips the bit, and never discloses that the id exists
// under a different owner.
func (h *H) RevokeIssuedCredential(w http.ResponseWriter, r *http.Request) {
	if h.IssuanceLog == nil {
		http.Error(w, "issuance log not configured", http.StatusNotFound)
		return
	}
	sess := h.Sessions.MustGet(w, r)
	owner := sessionOwnerKey(sess)
	id := r.PathValue("id")
	if id == "" {
		id = r.FormValue("id")
	}
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	rec, ok := h.IssuanceLog.Get(id)
	// Pre-check: if the entry exists but isn't ours, treat it the same as
	// "not found" so a guess doesn't leak ownership information.
	if !ok || rec.OwnerKey != owner {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	if rec.StatusList == nil {
		// No status list bound — Revoke is meaningless. Surface the reason
		// instead of silently no-op'ing so the operator can tell why
		// their button click didn't take.
		h.errorToast(w, r, "This credential has no status list binding (e.g. mdoc) and cannot be revoked through verifiably-go.")
		return
	}
	store := h.storeForBinding(rec.StatusList.Type, rec.StatusList.ListID)
	if store == nil {
		h.errorToast(w, r, "Status list "+rec.StatusList.Type+" not configured.")
		return
	}
	if err := store.Revoke(rec.StatusList.Index); err != nil {
		h.errorToast(w, r, "Revoke: "+err.Error())
		return
	}
	if _, err := h.IssuanceLog.MarkRevoked(id, owner); err != nil {
		h.errorToast(w, r, "Mark revoked: "+err.Error())
		return
	}
	// HTMX caller targets the row by id so a single-row fragment is enough
	// to reflect the new state. Re-fetch for the latest RevokedAt.
	rec, _ = h.IssuanceLog.Get(id)
	h.renderFragment(w, r, "fragment_issued_credentials_row", rec)
}

// storeForBinding resolves the exact list a credential was issued against.
//
// Resolve by list id, NOT by kind: with per-DPG lists, kind alone is
// ambiguous, and revoking would flip a bit in whichever list happened to
// be the default — marking an unrelated credential revoked while leaving
// the real one valid. The id is recorded in the binding at issuance, so
// it always names the right list.
func (h *H) storeForBinding(kind, listID string) statuslist.Backend {
	if kind == "" {
		return nil
	}
	if listID != "" {
		if e := h.StatusLists.ByID(kind, listID); e != nil {
			return e.Store
		}
	}
	// Records written before per-DPG lists carry no usable id — fall back to
	// the default list for the kind, which is where they were allocated.
	return h.storeForKind(kind)
}

// storeForKind returns the default list for a kind. Prefer storeForBinding
// wherever a binding is available.
func (h *H) storeForKind(kind string) statuslist.Backend {
	if e := h.statusListFor("", kind); e != nil {
		return e.Store
	}
	return nil
}

func (h *H) issuedCredentialsBody(sess *Session, r *http.Request) issuedCredentialsData {
	owner := sessionOwnerKey(sess)
	// Inji auth-code track: holders claim asynchronously via eSignet, so those
	// credentials are never written to the verifiably IssuanceLog — read them
	// from Certify's ledger instead. DPG-scoped: this shows ONLY auth-code creds.
	if r != nil && h.isInjiAuthcode(r.Context(), sess.IssuerDpg) {
		return h.injiIssuedCredentialsBody(sess, r, owner)
	}
	filter := issuance.Filter{
		Query:    sess.IssuedQuery,
		Std:      sess.IssuedStd,
		Format:   sess.IssuedFormat,
		State:    sess.IssuedState,
		OwnerKey: owner,
	}
	// Each DPG track owns its own credentials: scope the list to the currently
	// selected issuer DPG so a walt.id view never shows CREDEBL/pre-auth entries
	// even when the same issuer produced them.
	items := filterIssuedByDpg(h.IssuanceLog.List(filter), sess.IssuerDpg)
	// Stats has to be derived from the owner-scoped slice — the global
	// Summary() across the file would leak counts of other issuers'
	// credentials onto this issuer's banner ("X total / Y revoked"
	// across the entire instance). Rebuild from items instead.
	stats := issuance.Stats{ByStd: map[string]int{}, ByFormat: map[string]int{}}
	// To compute the chip-row Stds/Formats we need the unfiltered slice
	// scoped to this owner + DPG (so the chips show what they could see if they
	// dropped the std/format filter, not just what the current filter returns).
	all := filterIssuedByDpg(h.IssuanceLog.List(issuance.Filter{OwnerKey: owner}), sess.IssuerDpg)
	for _, c := range all {
		stats.Total++
		if c.RevokedAt == nil {
			stats.Active++
		} else {
			stats.Revoked++
		}
		stats.ByStd[c.Std]++
		stats.ByFormat[c.Format]++
	}
	stds := []string{"all"}
	for s := range stats.ByStd {
		stds = append(stds, s)
	}
	formats := []string{"all"}
	for f := range stats.ByFormat {
		formats = append(formats, f)
	}
	return issuedCredentialsData{
		Items:   items,
		Stats:   stats,
		Filter:  filter,
		Stds:    stds,
		Formats: formats,
	}
}

// filterIssuedByDpg keeps only IssuanceLog entries issued on the given DPG
// track. Empty dpg (no active issuer DPG) returns the slice unchanged
// (admin / legacy view).
func filterIssuedByDpg(in []issuance.IssuedCredential, dpg string) []issuance.IssuedCredential {
	if dpg == "" {
		return in
	}
	out := make([]issuance.IssuedCredential, 0, len(in))
	for _, c := range in {
		if c.IssuerDpg == dpg {
			out = append(out, c)
		}
	}
	return out
}

// injiIssuedCredentialsBody builds the issued-credentials view for the Inji
// auth-code track from Certify's ledger (owner-scoped), applying the same
// query/state filters the search box drives. Std/Format are fixed for this
// track (w3c_vcdm_2 / ldp_vc).
func (h *H) injiIssuedCredentialsBody(sess *Session, r *http.Request, owner string) issuedCredentialsData {
	items, err := h.injiLedgerItems(r.Context(), owner, sess.IssuerDpg)
	if err != nil {
		items = nil
	}
	// Auth-code credentials verifiably owns revocation for aren't in certify's
	// ledger — they're recorded in verifiably's IssuanceLog at provision time (with
	// a token status binding for SD-JWT, a bitstring binding for W3C). Merge them
	// in, scoped to this owner + DPG, so the issuer can review + revoke them
	// alongside the certify.ledger rows.
	if h.IssuanceLog != nil {
		for _, c := range h.IssuanceLog.List(issuance.Filter{OwnerKey: owner}) {
			if c.IssuerDpg == sess.IssuerDpg && c.StatusList != nil &&
				(c.StatusList.Type == "token" || c.StatusList.Type == "bitstring") {
				items = append(items, c)
			}
		}
	}
	stats := issuance.Stats{ByStd: map[string]int{}, ByFormat: map[string]int{}}
	for _, c := range items {
		stats.Total++
		if c.RevokedAt == nil {
			stats.Active++
		} else {
			stats.Revoked++
		}
		stats.ByStd[c.Std]++
		stats.ByFormat[c.Format]++
	}
	filter := issuance.Filter{Query: sess.IssuedQuery, State: sess.IssuedState, Std: sess.IssuedStd, Format: sess.IssuedFormat, OwnerKey: owner}
	q := strings.ToLower(strings.TrimSpace(filter.Query))
	filtered := make([]issuance.IssuedCredential, 0, len(items))
	for _, c := range items {
		if filter.State == "active" && c.RevokedAt != nil {
			continue
		}
		if filter.State == "revoked" && c.RevokedAt == nil {
			continue
		}
		if filter.Std != "" && c.Std != filter.Std {
			continue
		}
		if filter.Format != "" && c.Format != filter.Format {
			continue
		}
		if q != "" && !injiMatchesQuery(c, q) {
			continue
		}
		filtered = append(filtered, c)
	}
	return issuedCredentialsData{
		Items:   filtered,
		Stats:   stats,
		Filter:  filter,
		Stds:    []string{"all", "w3c_vcdm_2", "sd_jwt_vc (IETF)"},
		Formats: []string{"all", "ldp_vc", "vc+sd-jwt"},
	}
}

func injiMatchesQuery(c issuance.IssuedCredential, q string) bool {
	if strings.Contains(strings.ToLower(c.SchemaName), q) {
		return true
	}
	for _, v := range c.SubjectFields {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}
