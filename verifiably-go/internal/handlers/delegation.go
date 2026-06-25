package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// attachDelegationVerdict runs the delegated-access evaluator over the
// per-credential normalized view of the verified presentation and, when the
// presentation is a delegation presentation, records the verdict on the result
// and downgrades Valid if the delegation is not authorised.
//
// It is the uniform, adapter-agnostic seam (a sibling of attachTrustStatus):
// the host DPG already verified signatures + holder binding; this owns the
// linkage / invocation / capability / revocation checks that no deployed
// verifier performs. No-op unless an adapter populated res.Credentials.
func (h *H) attachDelegationVerdict(r *http.Request, res *backend.VerificationResult) {
	if res == nil || len(res.Credentials) == 0 {
		return
	}
	var trustFn delegation.TrustChecker
	if h.TrustRegistry != nil {
		trustFn = h.TrustRegistry.IsTrusted
	}
	opts := delegation.Options{
		RequestedAction: "present",
		Status:          h.delegationStatusChecker(),
		Trust:           trustFn,
		FailClosed:      true, // revocation status is the hard gate (ADR D4/Q5)
	}
	verdict := delegation.Evaluate(r.Context(), res.Credentials, res.HolderBinding, opts)
	if !verdict.Evaluated {
		return // not a delegation presentation — leave the base verdict untouched
	}
	res.Delegation = &verdict
	if !verdict.Authorized {
		res.Valid = false
		if res.Method != "" {
			res.Method += " · delegation: " + verdict.Reason
		} else {
			res.Method = "delegation: " + verdict.Reason
		}
		slog.Info("delegation denied", "reason", verdict.Reason)
	}
}

// delegationStatusChecker returns a StatusChecker that resolves a credential's
// revocation status against the issuer's published status list, reusing the
// Hub's signature-verifying status-list cache and the bitstring/token decoders.
// Errors (unreachable list, malformed payload) are surfaced so the evaluator can
// fail closed.
func (h *H) delegationStatusChecker() delegation.StatusChecker {
	return func(ctx context.Context, ref delegation.StatusRef) (bool, error) {
		if h.StatusListCache == nil {
			return false, fmt.Errorf("no status-list cache configured")
		}
		if ref.URI == "" {
			return false, fmt.Errorf("credential carries no status-list URL")
		}
		out, err := h.StatusListCache.Fetch(ctx, ref.Issuer, ref.URI)
		if err != nil {
			return false, fmt.Errorf("status-list fetch: %w", err)
		}
		if out.RawJWT == "" {
			return false, fmt.Errorf("status-list unavailable for %s", ref.URI)
		}
		return statusBitRevoked(out.RawJWT, ref)
	}
}

// statusBitRevoked extracts the revocation bit at ref.Index from a status-list
// JWT, handling both the W3C Bitstring (vc.credentialSubject.encodedList, gzip,
// multibase 'u' prefix, MSB-first) and IETF Token Status List (status_list.lst,
// zlib, LSB-first) encodings.
func statusBitRevoked(rawJWT string, ref delegation.StatusRef) (bool, error) {
	payload, err := jwtPayloadClaims(rawJWT)
	if err != nil {
		return false, err
	}
	idx := int(ref.Index)
	if strings.EqualFold(ref.Type, "TokenStatusList") {
		sl, _ := payload["status_list"].(map[string]any)
		lst, _ := sl["lst"].(string)
		if lst == "" {
			return false, fmt.Errorf("token status list missing lst")
		}
		bs, err := statuslist.DecodeZlibBase64URL(lst, statuslist.DefaultBits)
		if err != nil {
			return false, err
		}
		return bs.Get(idx), nil
	}
	// W3C BitstringStatusListEntry.
	vc, _ := payload["vc"].(map[string]any)
	cs, _ := vc["credentialSubject"].(map[string]any)
	enc, _ := cs["encodedList"].(string)
	if enc == "" {
		return false, fmt.Errorf("bitstring status list missing encodedList")
	}
	enc = strings.TrimPrefix(enc, "u") // strip multibase base64url prefix
	bs, err := statuslist.DecodeGzipBase64URL(enc, statuslist.DefaultBits)
	if err != nil {
		return false, err
	}
	return bs.Get(idx), nil
}

// jwtPayloadClaims base64url-decodes and JSON-parses the payload of a compact
// JWS. The signature was already verified by the status-list cache on fetch.
func jwtPayloadClaims(jwt string) (map[string]any, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed status-list JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("status-list JWT payload: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("status-list JWT payload JSON: %w", err)
	}
	return m, nil
}
