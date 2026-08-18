package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/mdl"
)

// mdlNonceTTL bounds how long a citizen has to build and submit a proof after
// requesting a nonce.
const mdlNonceTTL = 5 * time.Minute

// mdlCredentialValidity bounds how long an issued credential's ValidityInfo
// claims to be valid for. It must not exceed the DSC's own validity window
// (internal/mdl.serverDSCValidity, currently 457 days — the ISO/IEC 18013-5
// Annex B maximum), or the mdoc would outlive the very certificate chain a
// verifier needs to check its IssuerAuth signature: a wallet holding the
// credential past that point would see verifiers reject it as
// "certificate has expired" even though ValidityInfo still claims it's
// valid. This POC signer also regenerates a fresh IACA/DSC on every process
// restart (see serversigner.go), so in practice a credential is only ever
// verifiable within a single server run — this constant just avoids
// additionally overclaiming a validity period the signer can't back.
const mdlCredentialValidity = 457 * 24 * time.Hour

// mdlAudience returns the audience the proof-of-possession JWT must target
// for this request: this server's own public base URL plus the endpoint
// path, exactly what the wallet's requestMdl.ts already sends as the second
// argument to buildPossessionProof — no separate configuration needed on
// either side. Deriving it from the request (via the existing publicBase
// helper, handlers.go:276) rather than hardcoding a literal is what makes
// this endpoint's audience automatically correct in every deployment.
func mdlAudience(r *http.Request) string {
	return publicBase(r) + "/api/v1/credentials/mdl/issue"
}

type mdlIssueRequest struct {
	AccessToken string           `json:"access_token"`
	Proof       *mdlProofRequest `json:"proof,omitempty"`
}

type mdlProofRequest struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

// APIMdlIssue handles POST /api/v1/credentials/mdl/issue — the two-step
// OID4VCI proof-of-possession flow for mDL (ISO/IEC 18013-5) credentials.
//
// Step 1 (no "proof" in the body): verify the citizen's token, mint and
// return a c_nonce.
// Step 2 (body carries "proof"): verify the token again, verify the proof JWT
// against that same nonce, extract the device key it proves possession of,
// and issue an mdoc binding the MSO to exactly that key — never to a key
// supplied by any other channel (spec §AD-2).
func (h *H) APIMdlIssue(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if h.MdlNonces == nil || h.MdlSigner == nil {
		apiError(w, http.StatusServiceUnavailable, "mDL issuance is not configured")
		return
	}
	if h.RateLimiter != nil && !h.RateLimiter.Allow("mdl-issue", r) {
		apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var body mdlIssueRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	accessToken := strings.TrimSpace(body.AccessToken)
	if accessToken == "" {
		apiError(w, http.StatusUnauthorized, "access_token required")
		return
	}

	claims, err := h.verifyCitizenToken(r.Context(), accessToken)
	if err != nil {
		apiError(w, http.StatusUnauthorized, "token verification failed")
		return
	}
	holderSub := strings.TrimSpace(claims["sub"])
	if holderSub == "" {
		apiError(w, http.StatusUnauthorized, "access_token has no sub claim")
		return
	}

	if body.Proof == nil {
		h.mdlIssueStepOne(w)
		return
	}
	h.mdlIssueStepTwo(r, w, *body.Proof, holderSub, claims)
}

// mdlIssueStepOne mints a fresh nonce for the citizen to prove possession
// against.
func (h *H) mdlIssueStepOne(w http.ResponseWriter) {
	nonce := h.MdlNonces.Issue()
	apiJSON(w, http.StatusOK, map[string]any{
		"c_nonce":            nonce,
		"c_nonce_expires_in": int(mdlNonceTTL.Seconds()),
	})
}

// mdlIssueStepTwo verifies the proof and issues the credential.
//
// Order matters here: the signature is verified BEFORE the nonce is
// consumed, never the other way around. If a nonce were consumed on the
// strength of an unverified claim, anyone holding any valid access_token
// could burn a nonce that belongs to a different citizen's in-flight
// session by submitting a garbage-signed JWT that merely names that nonce —
// nonces travel in an HTTP body and are not secret from whoever can observe
// them. Verifying first means only a proof with a genuinely valid signature
// can ever spend a nonce.
func (h *H) mdlIssueStepTwo(r *http.Request, w http.ResponseWriter, proofReq mdlProofRequest, holderSub string, claims map[string]string) {
	if proofReq.ProofType != "jwt" {
		apiError(w, http.StatusBadRequest, "unsupported proof_type: "+proofReq.ProofType)
		return
	}
	if proofReq.JWT == "" {
		apiError(w, http.StatusBadRequest, "proof.jwt required")
		return
	}

	proof, err := VerifyPossessionProof(proofReq.JWT, mdlAudience(r))
	if err != nil {
		apiError(w, http.StatusUnauthorized, "proof verification failed: "+err.Error())
		return
	}
	if !h.MdlNonces.Consume(proof.Nonce) {
		apiError(w, http.StatusBadRequest, "nonce is invalid, expired, or already used")
		return
	}

	// POC simplification: LicenceData is not fully derivable from generic
	// OIDC claims without knowledge of the specific configured provider's
	// claim set. Subject identity (sub) comes from verified claims, per the
	// same rule self_issue.go follows; the remaining licence fields are
	// fixed POC placeholders, not invented claim mappings. Revisit once a
	// real IdP's claim schema for this is known.
	licence := mdlLicenceFromClaims(claims, holderSub)

	issuerSigned, err := mdl.Issue(r.Context(), h.MdlSigner, licence, proof.DeviceKey, licence.ExpiryDate)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "issuance failed: "+err.Error())
		return
	}

	em, err := mdl.EncMode()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "encoding failed: "+err.Error())
		return
	}
	encoded, err := em.Marshal(issuerSigned)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "encoding failed: "+err.Error())
		return
	}

	apiJSON(w, http.StatusOK, map[string]any{
		"credential": base64.RawURLEncoding.EncodeToString(encoded),
	})
}

// mdlLicenceFromClaims builds the POC's LicenceData from verified OIDC
// claims. See the comment at its call site: the fixed fields below are a
// documented POC simplification, not a general claim mapping.
//
// Dates are truncated to midnight UTC, matching the convention the rest of
// internal/mdl uses (see issue_test.go's sampleLicence). Issuing them with a
// time-of-day component would make IssueDate/ExpiryDate (encoded as
// FullDate, which truncates to a bare date) inconsistent with ValidityInfo's
// ValidUntil (encoded as TDate, which keeps the full timestamp) — risking
// validUntil exceeding expiry_date by up to 24h, which violates the
// normative constraint in spec §C.7.1.
func mdlLicenceFromClaims(claims map[string]string, holderSub string) mdl.LicenceData {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	return mdl.LicenceData{
		FamilyName:           firstNonEmpty(claims["family_name"], "POC"),
		GivenName:            firstNonEmpty(claims["given_name"], holderSub),
		BirthDate:            now.AddDate(-30, 0, 0), // POC placeholder: not derived from a real IdP claim
		IssueDate:            now,
		ExpiryDate:           now.Add(mdlCredentialValidity),
		IssuingCountry:       "DO",
		IssuingAuthority:     "INTRANT",
		DocumentNumber:       holderSub,
		UNDistinguishingSign: "DOM",
		DrivingPrivileges: []mdl.DrivingPrivilege{
			{VehicleCategoryCode: "B"},
		},
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
