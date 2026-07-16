package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// statusListByID resolves the list a publish request names, together with
// the key that signs it.
//
// Signing used to reach into the adapter for walt.id's onboarded issuer
// key, which meant any deployment without a walt.id issuer registered —
// an Inji-only stack, say — 503'd every status-list fetch, and with it
// every revocation check. Each list now carries its own self-managed
// signer, so hosting a list and being able to sign it are the same fact.
func (h *H) statusListByID(kind, id string) *StatusListEntry {
	if id == "" {
		return nil
	}
	if e := h.StatusLists.ByID(kind, id); e != nil {
		return e
	}
	return nil
}

// statusListFor resolves the list an issuer DPG allocates from, falling
// back to the default list when that DPG has none of its own.
func (h *H) statusListFor(dpg, kind string) *StatusListEntry {
	if e := h.StatusLists.For(dpg, kind); e != nil {
		return e
	}
	// Last resort for callers that set BitstringStore/TokenStore directly
	// without building a StatusListSet. Allocation doesn't need a signer,
	// so a store-only entry is enough here; publishing resolves through
	// StatusLists and would still 404.
	switch kind {
	case "bitstring":
		if h.BitstringStore != nil {
			return &StatusListEntry{Store: h.BitstringStore, Kind: kind}
		}
	case "token":
		if h.TokenStore != nil {
			return &StatusListEntry{Store: h.TokenStore, Kind: kind}
		}
	}
	return nil
}

// PublishBitstringStatusList serves GET /status-list/bitstring/{id}. The
// id segment selects one of the per-DPG lists (or the legacy "v1" list);
// each is signed by its own DPG's key.
func (h *H) PublishBitstringStatusList(w http.ResponseWriter, r *http.Request) {
	entry := h.statusListByID("bitstring", r.PathValue("id"))
	if entry == nil {
		http.Error(w, "unknown status list id", http.StatusNotFound)
		return
	}
	// Content-negotiate (F16 full-interop). DEFAULT is now JSON-LD: MOSIP Inji
	// Verify (and most W3C verifiers) fetch the statusListCredential with `*/*`
	// and JSON.parse it — they choke on the JOSE JWS ("Unrecognized token
	// 'eyJhbGci'"). Serve the signed JWS ONLY when explicitly requested via an
	// Accept containing `jwt` (application/vc+jwt) — verifiably's own
	// StatusListCache asks for that so it keeps verifying the list's signature.
	if wantsJWSStatusList(r.Header.Get("Accept")) {
		key := entry.Signer
		if key == nil {
			log.Printf("status-list/bitstring: no signer for list %q", entry.Store.GetListID())
			http.Error(w, "status list signing key unavailable", http.StatusServiceUnavailable)
			return
		}
		jwt, err := entry.Store.PublishBitstringJWT(key)
		if err != nil {
			log.Printf("status-list/bitstring: publish failed: %v", err)
			http.Error(w, "status list unavailable", http.StatusInternalServerError)
			return
		}
		// Per VCDM 2.0 + IANA registry, JOSE-secured VCs use application/vc+jwt.
		w.Header().Set("Content-Type", "application/vc+jwt")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte(jwt))
		return
	}
	// Default: JSON-LD BitstringStatusListCredential with an Ed25519Signature2020
	// Data-Integrity proof so external verifiers (MOSIP Inji Verify) accept it.
	if h.StatusLDSigner == nil {
		http.Error(w, "status list ld signer unavailable", http.StatusServiceUnavailable)
		return
	}
	vc, err := entry.Store.BitstringStatusListVC(h.StatusLDSigner.DID())
	if err != nil {
		log.Printf("status-list/bitstring: build VC failed: %v", err)
		http.Error(w, "status list unavailable", http.StatusInternalServerError)
		return
	}
	signed, err := h.StatusLDSigner.Sign(vc)
	if err != nil {
		log.Printf("status-list/bitstring: LD sign failed: %v", err)
		http.Error(w, "status list unavailable", http.StatusInternalServerError)
		return
	}
	body, err := json.Marshal(signed)
	if err != nil {
		http.Error(w, "status list unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vc+ld+json")
	// Status lists change rarely — cache for 60s (freshly-revoked visibility lags
	// by at most one minute, well inside what verifiers expect).
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(body)
}

// wantsJWSStatusList reports whether the caller explicitly asked for the
// JOSE-secured (application/vc+jwt) status list rather than the default JSON-LD.
func wantsJWSStatusList(accept string) bool {
	return strings.Contains(strings.ToLower(accept), "jwt")
}

// PublishTokenStatusList serves GET /status-list/token/{id} for SD-JWT
// VCs. Same shape as PublishBitstringStatusList but emits the IETF Token
// Status List JWT (status_list claim) with media type
// application/statuslist+jwt (draft-ietf-oauth-status-list §6).
func (h *H) PublishTokenStatusList(w http.ResponseWriter, r *http.Request) {
	entry := h.statusListByID("token", r.PathValue("id"))
	if entry == nil {
		http.Error(w, "unknown status list id", http.StatusNotFound)
		return
	}
	key := entry.Signer
	if key == nil {
		log.Printf("status-list/token: no signer for list %q", entry.Store.GetListID())
		http.Error(w, "status list signing key unavailable", http.StatusServiceUnavailable)
		return
	}
	jwt, err := entry.Store.PublishTokenStatusList(key)
	if err != nil {
		log.Printf("status-list/token: publish failed: %v", err)
		http.Error(w, "status list unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(jwt))
}
