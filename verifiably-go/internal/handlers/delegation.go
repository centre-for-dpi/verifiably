package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
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
	// Temporal-validity gate — applies to EVERY verify (delegation or not) that
	// populates Credentials. No deployed DPG verifier reliably enforces
	// validFrom/validUntil (or nbf/exp) across all formats, so without this an
	// expired or not-yet-valid credential resolves as verified. Runs before the
	// delegation evaluator so a stale-window credential is rejected regardless of
	// whether the presentation is a delegation.
	// Resolve the schemas ONCE for every surface that names a presented
	// credential (the temporal prose here, the per-credential cards below).
	// Nil-guarded: h.Adapter is nil in unit tests, and an unresolved name just
	// falls back to the wire type.
	schemas := h.presentedSchemasSafe(r.Context())
	attachTemporalVerdict(res, time.Now(), schemas)
	// Revocation gate — also applies to EVERY verify that populates Credentials.
	// No deployed DPG verifier reliably enforces status-list revocation across
	// formats (Inji Verify's vcverifier logs "Credential status checking not
	// supported for this credential format [VC_SD_JWT]" and returns SUCCESS for a
	// revoked SD-JWT), so verifiably — which owns/serves the status list —
	// enforces it here.
	h.attachRevocationVerdict(r.Context(), res)
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
	if verdict.Evaluated {
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
	// Per-credential card model for a COMBINED presentation (delegated pair or
	// multi-credential VP); no-op for a single-credential verify.
	h.buildDelegationCredentialViews(r.Context(), res, schemas)
}

// presentedSchemasSafe returns every schema this deployment hosts, for
// resolving a presented credential's wire type back to its issuer-given name.
// Returns nil (never panics) when no adapter is wired or the vendor can't be
// reached — callers fall back to the wire type.
func (h *H) presentedSchemasSafe(ctx context.Context) []vctypes.Schema {
	if h.Adapter == nil {
		return nil
	}
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		return nil
	}
	return schemas
}

// buildDelegationCredentialViews assembles the per-credential card model shown
// for a COMBINED presentation. Each view carries one credential's disclosed
// claims plus the checks attributed to it: the external verifier's per-credential
// verdict, the credential's own validity + revocation, and — for the delegation
// and its subject — the delegation sub-checks (linkage on both, invocation +
// capability on the delegation). It reuses the same primitives the gates use
// (TemporalBounds, StatusRefOf, delegationStatusChecker) so the per-card outcomes
// match the aggregate verdict. Empty for a single-credential verify (which keeps
// the flat result card).
func (h *H) buildDelegationCredentialViews(ctx context.Context, res *backend.VerificationResult, schemas []vctypes.Schema) {
	if res == nil || len(res.Credentials) == 0 {
		return
	}
	del := res.Delegation
	combined := len(res.Credentials) > 1 || (del != nil && del.Evaluated)
	if !combined {
		return
	}
	now := time.Now()
	views := make([]backend.CredentialView, 0, len(res.Credentials))
	for i, c := range res.Credentials {
		v := backend.CredentialView{
			Title:      credentialCardTitle(schemas, c),
			Issuer:     c.Issuer,
			Format:     c.Format,
			HostStatus: c.HostStatus,
			Claims:     c.Claims,
		}
		isDeleg, isSubj := false, false
		if del != nil && del.Evaluated {
			switch i {
			case del.DelegationIndex:
				v.Role, isDeleg = "delegation", true
			case del.SubjectIndex:
				v.Role, isSubj = "subject", true
			}
		}
		// Per-credential checks. The external verifier's per-credential verdict is
		// NOT surfaced: now that auth-code W3C credentials carry a real
		// credentialStatus block, the host and verifiably evaluate the SAME status,
		// so a separate "External verifier" pill would be redundant with "Not
		// revoked". Signature trust is folded into the overall res.Valid.
		v.Checks = append(v.Checks, credTemporalCheck(c, now), h.credRevocationCheck(ctx, c))
		// Attribute the delegation sub-checks to the credential each concerns.
		if del != nil && del.Evaluated {
			switch {
			case isDeleg:
				v.Checks = append(v.Checks,
					delegCheck("Linkage", del.Linkage, "delegation is about the presented subject"),
					delegCheck("Invocation", del.Invocation, "presenter is the bound delegate"),
					delegCheck("Capability", del.Capability, "action permitted, within validity"),
				)
			case isSubj:
				v.Checks = append(v.Checks, delegCheck("Linkage", del.Linkage, "is the subject this delegation names"))
			}
		}
		views = append(views, v)
	}
	res.CredentialViews = views
}

// credentialCardTitle is a human title for a presented-credential card: the
// issuer's name for the schema ("Testa Card V2") when we host it.
//
// Falls back to the first meaningful type reduced to its final path segment —
// which for an SD-JWT vct is the bare schema id ("custom-dk05t158qnou"). That
// fallback used to be the ONLY behaviour, so every delegated card showed a slug
// while the picker beside it showed the real name. It still applies to
// credentials we have no schema for (issued by another deployment), where the
// slug is the most we know.
func credentialCardTitle(schemas []vctypes.Schema, c backend.NormalizedCredential) string {
	if n := schemaNameForCredential(schemas, c); n != "" {
		return n
	}
	for _, t := range c.Types {
		t = strings.TrimSpace(t)
		if t == "" || strings.EqualFold(t, "VerifiableCredential") {
			continue
		}
		if i := strings.LastIndexAny(t, "/#"); i >= 0 && i+1 < len(t) {
			t = t[i+1:]
		}
		return t
	}
	return "Credential"
}

// credTemporalCheck reports whether the credential is within its own validity
// window right now (the same computation attachTemporalVerdict makes globally).
//
// A credential with no window is a PASS: not expiring is a legitimate property,
// not a failure, and most credentials here have no window. But it must not
// claim to be "within its validity window" — there is no window to be within,
// and saying so is indistinguishable from a window that was actually checked.
// That wording hid a real bug: every Inji Certify credential was issued without
// a window (its adapter dropped the operator's dates), so expired credentials
// verified green under a note asserting they'd been checked.
func credTemporalCheck(c backend.NormalizedCredential, now time.Time) backend.CredCheck {
	nb, na := c.TemporalBounds()
	if !nb.IsZero() && now.Before(nb) {
		return backend.CredCheck{Label: "Within validity", Status: "fail", Note: "not yet valid (from " + nb.Format(time.RFC3339) + ")"}
	}
	if !na.IsZero() && now.After(na) {
		return backend.CredCheck{Label: "Within validity", Status: "fail", Note: "expired (" + na.Format(time.RFC3339) + ")"}
	}
	if nb.IsZero() && na.IsZero() {
		return backend.CredCheck{Label: "Within validity", Status: "pass", Note: "no expiry — this credential does not expire"}
	}
	return backend.CredCheck{Label: "Within validity", Status: "pass", Note: "within its validity window"}
}

// credRevocationCheck reports this credential's own revocation status against its
// issuer's status list (na when it carries no status reference, or when no
// status-list cache is configured).
func (h *H) credRevocationCheck(ctx context.Context, c backend.NormalizedCredential) backend.CredCheck {
	ref, ok := delegation.StatusRefOf(c)
	if !ok {
		return backend.CredCheck{Label: "Not revoked", Status: "na", Note: "carries no status list"}
	}
	if h.StatusListCache == nil {
		return backend.CredCheck{Label: "Not revoked", Status: "na", Note: "status list not checked"}
	}
	revoked, err := h.delegationStatusChecker()(ctx, ref)
	if err != nil {
		return backend.CredCheck{Label: "Not revoked", Status: "na", Note: "status could not be checked: " + err.Error()}
	}
	if revoked {
		return backend.CredCheck{Label: "Not revoked", Status: "fail", Note: "revoked on the issuer's status list"}
	}
	return backend.CredCheck{Label: "Not revoked", Status: "pass", Note: "not revoked on the issuer's status list"}
}

// delegCheck maps a delegation sub-check boolean to a card check.
func delegCheck(label string, ok bool, note string) backend.CredCheck {
	if ok {
		return backend.CredCheck{Label: label, Status: "pass", Note: note}
	}
	return backend.CredCheck{Label: label, Status: "fail", Note: note}
}

// attachTemporalVerdict downgrades a verification when any presented credential
// is outside its own validity window (validFrom/validUntil, issuanceDate/
// expirationDate, or nbf/exp). An absent bound imposes no constraint. This is
// the B7 correctness/security gate — a sibling of attachDelegationVerdict /
// attachTrustStatus that owns temporal validity no adapter reliably enforces.
func attachTemporalVerdict(res *backend.VerificationResult, now time.Time, schemas []vctypes.Schema) {
	for _, c := range res.Credentials {
		notBefore, notAfter := c.TemporalBounds()
		label := temporalCredLabel(schemas, c)
		if !notBefore.IsZero() && now.Before(notBefore) {
			temporalDowngrade(res, fmt.Sprintf("%s is not yet valid (validFrom %s)", label, notBefore.Format(time.RFC3339)))
			return
		}
		if !notAfter.IsZero() && now.After(notAfter) {
			temporalDowngrade(res, fmt.Sprintf("%s has expired (validUntil %s)", label, notAfter.Format(time.RFC3339)))
			return
		}
	}
}

func temporalDowngrade(res *backend.VerificationResult, reason string) {
	res.Valid = false
	if res.Method != "" {
		res.Method += " · " + reason
	} else {
		res.Method = reason
	}
	slog.Info("temporal policy failed", "reason", reason)
}

// temporalCredLabel names the credential in the user-facing "<x> has expired"
// prose. Reuses the card resolver so the message reads "Testa Card V2 has
// expired".
//
// It used to return c.Types[0] verbatim, which is worse than the card slug in
// both directions: on SD-JWT that is the whole vct URL, and on W3C it is the
// generic "VerifiableCredential" — useless for a delegated pair, where it can't
// say WHICH credential expired.
func temporalCredLabel(schemas []vctypes.Schema, c backend.NormalizedCredential) string {
	if n := credentialCardTitle(schemas, c); n != "" && n != "Credential" {
		return n
	}
	return "credential"
}

// attachRevocationVerdict downgrades a verification when any presented credential
// has been revoked on its issuer's published status list. It is the revocation
// sibling of attachTemporalVerdict: no deployed DPG verifier reliably enforces
// status-list revocation for every format (Inji Verify's vcverifier returns
// SUCCESS for a revoked SD-JWT), and verifiably owns/serves the status list, so
// it enforces it at this uniform seam for every verify path. Fail-closed: a
// credential that carries a status reference the checker cannot resolve is denied
// — an attacker must not launder a revoked credential through a verifier that
// skips status checking. Only runs when a status-list cache is configured (Hub
// mode); other deployments have nothing to check against, so it no-ops.
func (h *H) attachRevocationVerdict(ctx context.Context, res *backend.VerificationResult) {
	if res == nil || len(res.Credentials) == 0 || h.StatusListCache == nil {
		return
	}
	check := h.delegationStatusChecker()
	resolved := false
	for _, c := range res.Credentials {
		ref, ok := delegation.StatusRefOf(c)
		if !ok {
			continue // no status reference — nothing to enforce for this credential
		}
		revoked, err := check(ctx, ref)
		if err != nil {
			revocationDowngrade(res, "revocation status could not be checked ("+err.Error()+")")
			return
		}
		resolved = true
		if revoked {
			revocationDowngrade(res, "a presented credential has been revoked")
			return
		}
	}
	// At least one status list was actually resolved, so the CheckedRevocation
	// flag (which adapters set optimistically) is now truthful.
	if resolved {
		res.CheckedRevocation = true
	}
}

func revocationDowngrade(res *backend.VerificationResult, reason string) {
	res.Valid = false
	if res.Method != "" {
		res.Method += " · " + reason
	} else {
		res.Method = reason
	}
	slog.Info("revocation policy failed", "reason", reason)
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

// statusBitRevoked extracts the revocation bit at ref.Index from a status-list,
// handling both the W3C Bitstring (vc.credentialSubject.encodedList, gzip,
// multibase 'u' prefix, MSB-first) and IETF Token Status List (status_list.lst,
// zlib, LSB-first) encodings, whether the list was served as a compact JWS or a
// bare JSON-LD credential (see statusListClaims).
func statusBitRevoked(rawJWT string, ref delegation.StatusRef) (bool, error) {
	payload, err := statusListClaims(rawJWT)
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
	// W3C BitstringStatusListEntry. The bitstring lives under vc.credentialSubject
	// for a JWT-VC status list (our own JWS form), or directly under
	// credentialSubject for a bare JSON-LD BitstringStatusListCredential (the form
	// Inji's auth-code Certify serves). Fall back to the top level when there is
	// no nested vc — mirrors vp.FromVCObject's inner-vc handling.
	vc, _ := payload["vc"].(map[string]any)
	if vc == nil {
		vc = payload
	}
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

// statusListClaims returns the status-list document as a claims map, accepting
// EITHER a compact JWS (JOSE-secured form — payload base64url-decoded + parsed)
// OR a bare JSON-LD status-list credential served as application/json.
//
// Inji's auth-code Certify serves its BitstringStatusListCredential as a bare
// JSON-LD VC and ignores our Accept: application/vc+jwt, so treating every
// status list as a compact JWS made jwtPayloadClaims split the JSON on '.' and
// base64url-decode a middle chunk into binary (the "invalid character ''"
// failure). Handling the bare-JSON form lets verifiably read Certify's bitstring
// and enforce real revocation instead of failing closed on a parse error.
//
// NOTE: for the bare JSON-LD form the credential's embedded proof is not
// cryptographically verified here (the status-list cache's verifyJWT only covers
// 3-part JWS); integrity rests on the TLS fetch from the issuer's own did:web
// origin — the same gap that already applies to any non-JWS list. Future
// hardening: verify the JSON-LD Ed25519Signature2020 proof.
func statusListClaims(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return nil, fmt.Errorf("status-list JSON: %w", err)
		}
		return m, nil
	}
	return jwtPayloadClaims(raw)
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
