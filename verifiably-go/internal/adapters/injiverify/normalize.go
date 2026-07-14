package injiverify

import (
	"encoding/json"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
)

// normalizeInjiCredentials turns Inji Verify's per-credential results into the
// shared NormalizedCredential shape for cross-credential policies. Each vc is a
// raw JSON-LD VC object or a JSON string holding a compact SD-JWT / VC-JWT.
//
// Inji verifies the VP holder binding but does not surface the holder
// identifier, so HolderBinding is marked Confirmed without an id (the evaluator
// then relies on the capability binding the delegate as subject).
func normalizeInjiCredentials(items []vcResultItem) ([]backend.NormalizedCredential, *backend.HolderBinding) {
	var creds []backend.NormalizedCredential
	for _, it := range items {
		nc, ok := decodeInjiVC(it.VC)
		if !ok {
			continue
		}
		// Retain the host's per-credential verdict so a combined-presentation
		// result can show each credential's own outcome (Inji flags a delegation
		// credential INVALID on its bitstring status while verifiably's own gate
		// clears it — the operator should see that per credential, not collapsed).
		nc.HostStatus = it.VerificationStatus
		creds = append(creds, nc)
	}
	if len(creds) == 0 {
		return nil, nil
	}
	return creds, &backend.HolderBinding{Confirmed: true}
}

// decodeInjiVC decodes one Inji Verify vcResults[].vc — a raw JSON-LD VC object,
// or a JSON string holding a JSON-LD VC / compact SD-JWT / compact VC-JWT — into
// a NormalizedCredential.
func decodeInjiVC(raw json.RawMessage) (backend.NormalizedCredential, bool) {
	if len(raw) == 0 {
		return backend.NormalizedCredential{}, false
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil && len(obj) > 0 {
		return vp.FromVCObject(obj), true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" {
		return backend.NormalizedCredential{}, false
	}
	s = strings.TrimSpace(s)
	switch {
	case strings.Contains(s, "~"):
		return vp.FromCompactSDJWT(s)
	case strings.HasPrefix(s, "{"):
		// Inji Verify serialises a JSON-LD (ldp_vc) credential as a JSON STRING in
		// vcResults[].vc — parse it so its credentialSubject claims
		// (onBehalfOf/subjectRef/…) are recovered for the delegated-access
		// evaluator, not just the signed envelope.
		var inner map[string]any
		if json.Unmarshal([]byte(s), &inner) == nil && len(inner) > 0 {
			return vp.FromVCObject(inner), true
		}
	default:
		if p := vp.DecodeJWTPayload(s); p != nil {
			return vp.FromVCObject(p), true
		}
	}
	return backend.NormalizedCredential{}, false
}
