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
		if len(it.VC) == 0 {
			continue
		}
		var obj map[string]any
		if json.Unmarshal(it.VC, &obj) == nil && len(obj) > 0 {
			creds = append(creds, vp.FromVCObject(obj))
			continue
		}
		var s string
		if json.Unmarshal(it.VC, &s) == nil && s != "" {
			s = strings.TrimSpace(s)
			switch {
			case strings.Contains(s, "~"):
				if nc, ok := vp.FromCompactSDJWT(s); ok {
					creds = append(creds, nc)
				}
			case strings.HasPrefix(s, "{"):
				// Inji Verify serialises a JSON-LD (ldp_vc) credential as a JSON
				// STRING in vcResults[].vc — parse it so its credentialSubject
				// claims (onBehalfOf/subjectRef/…) are recovered for the
				// delegated-access evaluator, not just the signed envelope.
				var inner map[string]any
				if json.Unmarshal([]byte(s), &inner) == nil && len(inner) > 0 {
					creds = append(creds, vp.FromVCObject(inner))
				}
			default:
				if p := vp.DecodeJWTPayload(s); p != nil {
					creds = append(creds, vp.FromVCObject(p))
				}
			}
		}
	}
	if len(creds) == 0 {
		return nil, nil
	}
	return creds, &backend.HolderBinding{Confirmed: true}
}
