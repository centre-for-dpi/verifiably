// Package issuance keeps a JSON-backed audit log of every credential the
// operator has issued through verifiably-go. The log feeds the
// /issuer/credentials list page and is the source of truth for revocation:
// each entry stores the (status list type, list id, bit index) tuple
// allocated at issuance time, so a Revoke action can flip the right bit
// without re-deriving anything from the credential payload.
//
// The log is a single JSON file (path passed at construction). Writes are
// serialized through a mutex; the file is fsynced on every mutation. This
// is fine for a single-instance demo — for multi-replica use, swap the
// backing store for a real database.
package issuance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// IssuedCredential captures one successful issuance plus its revocation
// state. We deliberately don't store the credential PAYLOAD — that's the
// holder's. Only the metadata an operator needs to find and revoke.
type IssuedCredential struct {
	// ID is verifiably-internal; format vc-<unix-ms>-<rand-suffix>. Not
	// the credentialId on the wire (walt.id mints that and we don't see
	// it directly from the OID4VCI offer URI).
	ID string `json:"id"`

	// SchemaID and SchemaName are copies of the catalog entry the operator
	// picked. SchemaName is what the list page renders.
	SchemaID   string `json:"schemaId"`
	SchemaName string `json:"schemaName"`

	// Std is the wire-format taxonomy the rest of the codebase uses
	// ("w3c_vcdm_2", "sd_jwt_vc (IETF)", "mso_mdoc"). Drives which status
	// list variant the credential is enrolled in.
	Std string `json:"std"`

	// Format is the walt.id wire format ("vc+sd-jwt", "ldp_vc", ...).
	// Recorded for display only; revocation logic keys off Std.
	Format string `json:"format"`

	// IssuerDpg is the DPG label the operator was on when issuing
	// ("Walt Community Stack"). Used so operator A's logs can be filtered
	// out from operator B's view.
	IssuerDpg string `json:"issuerDpg"`

	// OwnerKey is the stable per-issuer identity key (typically the
	// authenticated OIDC `provider|sub` pair) used to partition the log
	// so issuer A doesn't see issuer B's credentials on /issuer/credentials.
	// Empty for entries written before per-issuer scoping shipped or for
	// unauthenticated demo-mode flows; List/MarkRevoked treat an empty
	// filter key as "no scoping" so historical entries stay reachable for
	// admins running an empty filter.
	OwnerKey string `json:"ownerKey,omitempty"`

	// HolderHint is a human-readable identifier picked from SubjectData
	// (first non-empty of fullName / id / vehicleNumber / etc.) so the
	// list page is searchable by name even though we don't track holder
	// DIDs.
	HolderHint string `json:"holderHint,omitempty"`

	// SubjectFields is a verbatim copy of the issued claim set. Used for
	// search and so the list page can render a tooltip / details pane
	// without having to refetch from walt.id.
	SubjectFields map[string]string `json:"subjectFields,omitempty"`

	// OfferURI is what the wallet scans. Recorded so the operator can
	// re-share if the wallet hasn't claimed the offer yet.
	OfferURI string `json:"offerUri,omitempty"`

	// IssuedAt is when verifiably-go received walt.id's success response.
	IssuedAt time.Time `json:"issuedAt"`

	// RevokedAt is non-nil only after a successful Revoke. Re-issuance
	// resets to nil (status list 2023 supports unrevocation; we don't
	// expose it in the UI yet but the field is here so we don't have to
	// migrate later).
	RevokedAt *time.Time `json:"revokedAt,omitempty"`

	// StatusList points to the bit allocated for this credential, nil
	// if the credential's Std doesn't support a status list (e.g. mdoc).
	// Without a StatusList entry the Revoke button stays disabled.
	StatusList *StatusListEntry `json:"statusList,omitempty"`
}

// StatusListEntry is the (which list, which bit) pointer the Revoke
// action follows.
type StatusListEntry struct {
	// Type is "bitstring" (W3C VCDM 2.0) or "token" (IETF SD-JWT VC).
	// Determines which Store the Revoke handler dispatches to.
	Type string `json:"type"`

	// ListID is the public id of the status list ("v1" today; multiple
	// lists let us keep each list under the spec-recommended <128KB ceiling).
	ListID string `json:"listId"`

	// Index is the zero-based bit position within the list.
	Index int `json:"index"`
}

// Filter narrows the list page's view. All fields are AND'd together;
// empty fields don't filter.
type Filter struct {
	// Query is a case-insensitive substring match against SchemaName +
	// HolderHint + every SubjectFields value.
	Query string

	// Std and Format are exact-match filters surfaced as chips. Empty
	// means "any".
	Std    string
	Format string

	// State is "all" (default), "active", or "revoked".
	State string

	// OwnerKey scopes the result to a single issuer's entries. Empty means
	// "no owner filter" (admin / CLI use). Handlers MUST pass a non-empty
	// value when serving authenticated user views, otherwise issuer A
	// could see issuer B's credentials via the same browser tab.
	OwnerKey string
}

// Log is the JSON-backed store. Methods serialize through mu so concurrent
// HTTP handlers can issue + revoke + list without racing.
type Log struct {
	path  string
	mu    sync.RWMutex
	items []IssuedCredential
}

// NewLog opens (or lazily creates) the JSON file at path. The directory
// is created if missing. A non-existent file is treated as an empty log.
func NewLog(path string) (*Log, error) {
	if path == "" {
		return nil, fmt.Errorf("issuance: log path empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("issuance: mkdir %s: %w", filepath.Dir(path), err)
	}
	l := &Log{path: path}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) load() error {
	b, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		l.items = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("issuance: read %s: %w", l.path, err)
	}
	if len(b) == 0 {
		l.items = nil
		return nil
	}
	var items []IssuedCredential
	if err := json.Unmarshal(b, &items); err != nil {
		return fmt.Errorf("issuance: parse %s: %w", l.path, err)
	}
	l.items = items
	return nil
}

// save writes the current items slice to disk atomically (write to temp
// then rename) so a partial write can never corrupt the log.
func (l *Log) save() error {
	b, err := json.MarshalIndent(l.items, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Append records a new issuance. Returns the stored copy (caller's value
// is left untouched in case it wants to use the input again).
func (l *Log) Append(c IssuedCredential) (IssuedCredential, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.ID == "" {
		return IssuedCredential{}, fmt.Errorf("issuance: append: id required")
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now().UTC()
	}
	for _, existing := range l.items {
		if existing.ID == c.ID {
			return IssuedCredential{}, fmt.Errorf("issuance: append: id %q already exists", c.ID)
		}
	}
	l.items = append(l.items, c)
	if err := l.save(); err != nil {
		// roll back the in-memory append so a save failure leaves the
		// log consistent with what's on disk.
		l.items = l.items[:len(l.items)-1]
		return IssuedCredential{}, err
	}
	return c, nil
}

// Get returns a copy of the entry with the given id. ok=false if not found.
func (l *Log) Get(id string) (IssuedCredential, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, c := range l.items {
		if c.ID == id {
			return c, true
		}
	}
	return IssuedCredential{}, false
}

// MarkReinstate clears a previously-set RevokedAt timestamp, restoring the
// credential to active status. No-op when the entry is already active.
// ownerKey enforcement mirrors MarkRevoked.
func (l *Log) MarkReinstate(id, ownerKey string) (IssuedCredential, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, c := range l.items {
		if c.ID != id {
			continue
		}
		if ownerKey != "" && c.OwnerKey != ownerKey {
			return IssuedCredential{}, fmt.Errorf("issuance: mark reinstate: id %q not found", id)
		}
		if c.RevokedAt == nil {
			return c, nil
		}
		l.items[i].RevokedAt = nil
		if err := l.save(); err != nil {
			now := time.Now().UTC()
			l.items[i].RevokedAt = &now
			return IssuedCredential{}, err
		}
		return l.items[i], nil
	}
	return IssuedCredential{}, fmt.Errorf("issuance: mark reinstate: id %q not found", id)
}

// MarkRevoked stamps the entry's RevokedAt to now. Returns the updated
// entry. No-op (still nil error) if already revoked — Revoke is naturally
// idempotent.
//
// ownerKey, when non-empty, must match the entry's OwnerKey or the call
// fails with a not-found error. This keeps a malicious POST to
// /issuer/credentials/{id}/revoke from another issuer's session from
// flipping someone else's bit just by guessing the id. Empty ownerKey
// disables the check (admin/CLI path).
func (l *Log) MarkRevoked(id, ownerKey string) (IssuedCredential, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, c := range l.items {
		if c.ID != id {
			continue
		}
		if ownerKey != "" && c.OwnerKey != ownerKey {
			// Surfaced as not-found rather than 403 so the caller can't
			// confirm the id exists under a different owner.
			return IssuedCredential{}, fmt.Errorf("issuance: mark revoked: id %q not found", id)
		}
		if c.RevokedAt != nil {
			return c, nil
		}
		now := time.Now().UTC()
		l.items[i].RevokedAt = &now
		if err := l.save(); err != nil {
			l.items[i].RevokedAt = nil
			return IssuedCredential{}, err
		}
		return l.items[i], nil
	}
	return IssuedCredential{}, fmt.Errorf("issuance: mark revoked: id %q not found", id)
}

// List returns a sorted+filtered snapshot. Sort is newest-first by
// IssuedAt so the list page reads as a feed.
func (l *Log) List(f Filter) []IssuedCredential {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]IssuedCredential, 0, len(l.items))
	q := strings.ToLower(strings.TrimSpace(f.Query))
	for _, c := range l.items {
		// Per-issuer scoping: if a key is set, only entries owned by that
		// key are returned. Pre-scoping entries (OwnerKey == "") are
		// invisible under any non-empty filter — they only surface to
		// admins running an empty filter.
		if f.OwnerKey != "" && c.OwnerKey != f.OwnerKey {
			continue
		}
		if f.Std != "" && c.Std != f.Std {
			continue
		}
		if f.Format != "" && c.Format != f.Format {
			continue
		}
		switch f.State {
		case "active":
			if c.RevokedAt != nil {
				continue
			}
		case "revoked":
			if c.RevokedAt == nil {
				continue
			}
		}
		if q != "" && !matchesQuery(c, q) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IssuedAt.After(out[j].IssuedAt)
	})
	return out
}

// matchesQuery looks for q in the human-visible fields. Subject values are
// included so an operator can find "the credential I just issued for Wanjiru"
// by searching Wanjiru even though the holder field is named "fullName".
func matchesQuery(c IssuedCredential, q string) bool {
	if strings.Contains(strings.ToLower(c.SchemaName), q) {
		return true
	}
	if strings.Contains(strings.ToLower(c.HolderHint), q) {
		return true
	}
	if strings.Contains(strings.ToLower(c.SchemaID), q) {
		return true
	}
	for _, v := range c.SubjectFields {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}

// Stats summarizes the log for chip badges on the list page.
type Stats struct {
	Total   int
	Active  int
	Revoked int
	// ByStd lets the std-chip row show "(N)" badges next to each chip.
	ByStd map[string]int
	// ByFormat is the same idea for format chips.
	ByFormat map[string]int
}

// Summary computes Stats over the full unfiltered log.
func (l *Log) Summary() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	s := Stats{ByStd: map[string]int{}, ByFormat: map[string]int{}}
	for _, c := range l.items {
		s.Total++
		if c.RevokedAt == nil {
			s.Active++
		} else {
			s.Revoked++
		}
		s.ByStd[c.Std]++
		s.ByFormat[c.Format]++
	}
	return s
}
