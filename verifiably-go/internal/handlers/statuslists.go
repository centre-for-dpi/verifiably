package handlers

import (
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// Per-issuer-DPG status lists.
//
// Each issuer DPG hosts its own bitstring + token list, signed by its own
// self-managed key, so the DPGs are decoupled: revoking an Inji Pre-Auth
// credential can't touch a walt.id list, and a deployment that registers
// no walt.id issuer can still publish a signed list. Previously there was
// one list per kind for the whole process, and the signing key was
// whichever issuer adapter happened to expose IssuerSigningKey — only
// walt.id ever did, so Inji-only stacks 503'd every fetch.
//
// The legacy "v1" lists stay registered as the defaults. They serve
// credentials issued before per-DPG lists existed (whose credentialStatus
// already points at /status-list/{kind}/v1 and can't be rewritten), and
// they're what mock/single-adapter deployments fall back to.

// StatusListEntry pairs a hosted list with the key that signs it.
type StatusListEntry struct {
	Store  statuslist.Backend
	Signer *statuslist.SigningKey
	// DPG is the issuer DPG vendor key (the backends.json "vendor", e.g.
	// "Inji Certify · Pre-Auth"). Empty for the legacy/default list.
	DPG string
	// Kind is "bitstring" or "token".
	Kind string
}

// StatusListSet indexes every status list this process hosts, by public
// list id (the HTTP publish path) and by (DPG, kind) (the allocation and
// URL-embedding paths).
type StatusListSet struct {
	mu       sync.RWMutex
	byID     map[string]*StatusListEntry
	byDPG    map[string]map[string]*StatusListEntry
	defaults map[string]*StatusListEntry
}

func NewStatusListSet() *StatusListSet {
	return &StatusListSet{
		byID:     map[string]*StatusListEntry{},
		byDPG:    map[string]map[string]*StatusListEntry{},
		defaults: map[string]*StatusListEntry{},
	}
}

// Register adds an entry. A blank DPG registers the default/legacy list
// for that kind — the fallback when a DPG has no list of its own.
func (s *StatusListSet) Register(e *StatusListEntry) {
	if s == nil || e == nil || e.Store == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[indexKey(e.Kind, e.Store.GetListID())] = e
	if e.DPG == "" {
		s.defaults[e.Kind] = e
		return
	}
	if s.byDPG[e.DPG] == nil {
		s.byDPG[e.DPG] = map[string]*StatusListEntry{}
	}
	s.byDPG[e.DPG][e.Kind] = e
}

// ByID resolves the list a publish request names. kind guards against
// serving a token list from the bitstring route and vice versa.
func (s *StatusListSet) ByID(kind, id string) *StatusListEntry {
	if s == nil || id == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[indexKey(kind, id)]
}

// indexKey namespaces the id index by kind. The legacy bitstring and token
// lists BOTH have id "v1", so an id-only index silently drops one of them.
// (The PostgreSQL store has this same latent collision — its status_lists
// table is keyed by list_id alone — which is why per-DPG ids below embed
// the kind.)
func indexKey(kind, id string) string { return kind + "/" + id }

// For resolves the list a DPG allocates from. Falls back to the default
// list when the DPG has none — which is the mock/single-adapter case, and
// keeps issuance working rather than silently dropping revocability.
func (s *StatusListSet) For(dpg, kind string) *StatusListEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if byKind, ok := s.byDPG[dpg]; ok {
		if e, ok := byKind[kind]; ok {
			return e
		}
	}
	return s.defaults[kind]
}

// Entries returns every registered list. Order is not guaranteed.
func (s *StatusListSet) Entries() []*StatusListEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*StatusListEntry, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, e)
	}
	return out
}

// StatusListSlug turns an issuer DPG vendor key into a URL- and
// filename-safe token. Vendor keys are display strings ("Inji Certify ·
// Pre-Auth"), so they can't go into a path or a filename as-is. The
// mapping must stay stable across releases: it's baked into the
// credentialStatus URL of every credential already issued.
//
//	"Inji Certify · Pre-Auth" -> "inji-certify-pre-auth"
//	"walt.id"                 -> "walt-id"
func StatusListSlug(vendor string) string {
	var b strings.Builder
	lastDash := true // strip leading separators
	for _, r := range strings.ToLower(vendor) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			// Any run of non-alphanumerics (spaces, "·", ".", "-") collapses
			// to a single dash.
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// StatusListID is the public id of a DPG's list of a given kind. The kind
// is part of the id, not just the URL path, because the PostgreSQL store
// keys rows by list_id ALONE — two lists sharing an id collide on one row.
func StatusListID(vendor, kind string) string {
	slug := StatusListSlug(vendor)
	if slug == "" {
		return kind
	}
	return slug + "-" + kind
}
