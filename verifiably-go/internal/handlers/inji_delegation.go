package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
)

// VerifyInjiDelegation runs the delegated-access evaluator over the holder's
// in-app Inji-claimed credentials (the eSignet auth-code flow). The in-app Inji
// holder CLAIMS credentials but does not OID4VP-present them, so delegation
// verification evaluates the held credential set directly — the same DPG-agnostic
// evaluator the OID4VP verifier path uses, just sourced from the session's
// claimed creds instead of a presented VP.
//
// GET /holder/wallet/inji/verify-delegation
func (h *H) VerifyInjiDelegation(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	creds := normalizeClaimedInjiCreds(sess.InjiClaimedVCs)
	res := backend.VerificationResult{
		Credentials: creds,
		// The in-app holder proved possession via the OID4VCI holder proof at
		// claim time; mark the binding confirmed (no identifier — the evaluator's
		// invocation check then relies on the capability binding the delegate).
		HolderBinding: &backend.HolderBinding{Confirmed: true},
		Valid:         len(creds) > 0,
	}
	h.attachDelegationVerdict(r, &res)
	out := map[string]any{
		"credentialCount": len(creds),
		"valid":           res.Valid,
	}
	if res.Delegation != nil {
		out["delegation"] = res.Delegation
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// normalizeClaimedInjiCreds parses the holder's claimed Inji credentials — stored
// as the raw credential JSON: an object for ldp_vc, or a quoted compact SD-JWT
// string for vc+sd-jwt — into the shared NormalizedCredential shape.
func normalizeClaimedInjiCreds(raws []string) []backend.NormalizedCredential {
	var out []backend.NormalizedCredential
	for _, raw := range raws {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(raw), &obj) == nil && len(obj) > 0 {
			out = append(out, vp.FromVCObject(obj))
			continue
		}
		var s string
		if json.Unmarshal([]byte(raw), &s) == nil && strings.Contains(s, "~") {
			if nc, ok := vp.FromCompactSDJWT(s); ok {
				out = append(out, nc)
			}
		} else if strings.Contains(raw, "~") {
			if nc, ok := vp.FromCompactSDJWT(raw); ok {
				out = append(out, nc)
			}
		}
	}
	return out
}
