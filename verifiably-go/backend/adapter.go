// Package backend defines the Adapter interface that the handlers depend on.
// Implement this interface to connect a real backend.
//
// Every request and response type is in this package. Domain types (DPG,
// Schema, Credential, ...) live in vctypes.
//
// To plug in a backend:
//
//	type MyAdapter struct { apiURL string; token string }
//	func (a *MyAdapter) ListIssuerDpgs(ctx context.Context) (map[string]vctypes.DPG, error) { ... }
//	// ... implement every method ...
//
//	// Then register the adapter in config/backends.json under a type string
//	// recognised by internal/adapters/factory.
//
// See docs/integration.md for endpoint-level mapping per configured DPG.
package backend

import (
	"context"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Adapter is the single seam between the UI and any backend.
//
// All methods take a context.Context so handlers can propagate request deadlines
// and cancellation. Errors bubble up to the HTMX layer as toasts; return
// descriptive error messages when something goes wrong.
type Adapter interface {
	// --- Catalogs: static capability metadata ---
	//
	// In a real deployment these return your gateway's list of supported DPGs
	// for each role, including plain-language capability descriptions that the
	// UI surfaces to end users. If you have only one vendor per role, return a
	// single-entry map.

	// ListIssuerDpgs returns issuer-capable DPGs keyed by vendor name.
	ListIssuerDpgs(ctx context.Context) (map[string]vctypes.DPG, error)

	// ListHolderDpgs returns wallet DPGs keyed by vendor name.
	ListHolderDpgs(ctx context.Context) (map[string]vctypes.DPG, error)

	// ListVerifierDpgs returns verifier DPGs keyed by vendor name.
	ListVerifierDpgs(ctx context.Context) (map[string]vctypes.DPG, error)

	// --- Schemas ---

	// ListSchemas returns schemas available to issue with the given issuer DPG.
	// Includes both pre-configured catalog schemas and any user-saved custom ones.
	ListSchemas(ctx context.Context, issuerDpg string) ([]vctypes.Schema, error)

	// ListAllSchemas returns every schema, regardless of which DPG supports it.
	// Used by lookup-by-id paths in the issuance flow.
	ListAllSchemas(ctx context.Context) ([]vctypes.Schema, error)

	// SaveCustomSchema persists a user-built schema. Called from the schema
	// builder's "Save" button. The schema's ID is already set by the caller.
	SaveCustomSchema(ctx context.Context, schema vctypes.Schema) error

	// DeleteCustomSchema removes a user-built schema. Pre-configured catalog
	// schemas should not be deletable; return an error if id refers to one.
	DeleteCustomSchema(ctx context.Context, id string) error

	// --- Issuance ---

	// PrefillSubjectFields returns default values for the single-subject form
	// when the operator chooses "Enter manually". For non-manual sources
	// (API / MOSIP / custom plugin / presentation-during-issuance), this is
	// not called.
	PrefillSubjectFields(ctx context.Context, schema vctypes.Schema) (map[string]string, error)

	// IssueToWallet generates a credential offer deliverable via OID4VCI.
	// Returns the offer URI that the holder's wallet will open.
	IssueToWallet(ctx context.Context, req IssueRequest) (IssueToWalletResult, error)

	// IssueAsPDF generates a printable credential with an embedded QR code.
	// Only called when the issuer DPG's DirectPDF capability is true.
	IssueAsPDF(ctx context.Context, req IssueRequest) (IssueAsPDFResult, error)

	// IssueBulk processes a CSV-worth of rows. Returns a summary; per-row
	// success/failure detail is for UI consumption (not every row needs to
	// be echoed back — errors + total counts suffice).
	IssueBulk(ctx context.Context, req IssueBulkRequest) (IssueBulkResult, error)

	// --- Wallet / holder ---

	// ListWalletCredentials returns credentials already held by this holder.
	// In the demo this includes a seed credential; in production, query your wallet store.
	ListWalletCredentials(ctx context.Context) ([]vctypes.Credential, error)

	// DeleteWalletCredential removes a held credential from the wallet by id.
	// Implementations that don't support deletion (e.g. read-only wallets)
	// return backend.ErrNotSupported; the handler surfaces that as a toast.
	DeleteWalletCredential(ctx context.Context, credentialID string) error

	// ListExampleOffers returns demo offer URIs that the wallet's "paste example"
	// helper cycles through. For production, return an empty slice (the feature
	// is a demo-only affordance) or a small list of test-environment URIs.
	ListExampleOffers(ctx context.Context) ([]string, error)

	// ParseOffer resolves an openid-credential-offer:// URI (inline or by-reference)
	// into a credential-for-review shape. Must return a Credential with Status="pending"
	// and a freshly-assigned ID the UI can target for accept/reject.
	ParseOffer(ctx context.Context, offerURI string) (vctypes.Credential, error)

	// ClaimCredential consummates an offer — the holder has approved it.
	// Return the claimed credential with Status="accepted".
	ClaimCredential(ctx context.Context, cred vctypes.Credential) (vctypes.Credential, error)

	// PresentCredential drives the holder side of OID4VP: the holder picks a
	// held credential (credID) and hands it to the verifier named in the
	// request URI. Return a PresentCredentialResult the UI can surface back to
	// the operator. Adapters for verifier-only or issuer-only DPGs return
	// ErrNotApplicable.
	PresentCredential(ctx context.Context, req PresentCredentialRequest) (PresentCredentialResult, error)

	// BootstrapOffers returns offer URIs generated from live backends. Called
	// once at startup (per issuer DPG) to replace hardcoded fixtures. Adapters
	// that can't or shouldn't issue speculative demo credentials return an
	// empty slice + nil error.
	BootstrapOffers(ctx context.Context) ([]string, error)

	// --- Verifier ---

	// ListOID4VPTemplates returns preset presentation requests the verifier can issue.
	// The UI populates a dropdown from this. For production, return your verifier's
	// configured templates.
	ListOID4VPTemplates(ctx context.Context) (map[string]vctypes.OID4VPTemplate, error)

	// RequestPresentation generates an OID4VP presentation request URI and
	// a server-side state token. The UI shows the URI as a QR + link; the
	// state is used to correlate the holder's response on a later call.
	RequestPresentation(ctx context.Context, req PresentationRequest) (PresentationRequestResult, error)

	// FetchPresentationResult retrieves the verification outcome for a previously
	// issued OID4VP request, identified by state. templateKey is passed through so
	// the adapter can reconstruct what was asked for (which fields, etc.).
	FetchPresentationResult(ctx context.Context, state, templateKey string) (VerificationResult, error)

	// VerifyDirect validates a credential the holder handed over (scan / upload / paste),
	// without an OID4VP round-trip. method is "scan" | "upload" | "paste". For "paste",
	// CredentialData is the raw credential string; for scan/upload it's empty (the
	// UI simulates; a real adapter with real input would receive the bytes here too).
	VerifyDirect(ctx context.Context, req DirectVerifyRequest) (VerificationResult, error)
}

// --- Request / response shapes ---

// IssueRequest is the input to both IssueToWallet and IssueAsPDF.
type IssueRequest struct {
	IssuerDpg   string
	Schema      vctypes.Schema
	SubjectData map[string]string
	Flow        string // "pre_auth" or "auth_code"; empty = adapter default

	// StatusList enrolls the credential in a verifiably-go-hosted revocation
	// list. The handler allocates an index from the appropriate Store before
	// calling the adapter; the adapter is responsible for embedding the
	// binding into the credential body so verifiers can later GET the
	// PublishURL and check Index. nil means "no status list" — the credential
	// is unrevocable end-to-end and the issuance log marks the entry without
	// a StatusListEntry pointer.
	StatusList *StatusListBinding
}

// StatusListBinding is the (which list, which bit, where to fetch) pointer
// the handler hands the adapter to inject into the VC. Type matches
// internal/statuslist.Store.Kind: "bitstring" for W3C VCDM 2.0 (BSL 2023),
// "token" for SD-JWT (IETF Token Status List).
type StatusListBinding struct {
	Type       string
	ListID     string
	Index      int
	PublishURL string // absolute, browser-reachable URL the verifier dereferences
}

// IssueToWalletResult describes a generated credential offer.
type IssueToWalletResult struct {
	OfferURI  string        // the openid-credential-offer:// URI
	OfferID   string        // adapter-assigned id for tracing / retrieval
	Flow      string        // echoes the flow actually used (may differ from request)
	ExpiresIn time.Duration // how long until the offer becomes invalid
	PIN       string        // pre-auth PIN the holder must enter in the wallet (empty when not required)
}

// IssueAsPDFResult describes a generated PDF credential.
type IssueAsPDFResult struct {
	IssuerName    string            // human-readable issuer name (for the PDF header)
	IssuerDID     string            // issuer DID (for the PDF header / QR payload)
	PayloadSizeKB int               // approximate QR payload size in kilobytes
	Fields        map[string]string // the subject fields as issued (echo of input)
	// DownloadID is the adapter-assigned key the UI uses to fetch the PDF
	// bytes via /issuer/issue/pdf/{id}. Empty string when the adapter does
	// not actually host a PDF blob (some DPGs only report metadata).
	DownloadID string
}

// IssueBulkRequest is the input to IssueBulk.
type IssueBulkRequest struct {
	IssuerDpg string
	Schema    vctypes.Schema
	// Rows holds the parsed CSV body — one map of field-name→value per row.
	// Adapters iterate Rows, call the underlying issuer per row, and return an
	// aggregated IssueBulkResult. RowCount mirrors len(Rows) and stays present
	// for backward compatibility with templates that just want a total.
	Rows     []map[string]string
	RowCount int
}

// IssueBulkResult summarizes a bulk-issue operation.
type IssueBulkResult struct {
	Accepted int
	Rejected int
	Errors   []BulkError // illustrative errors for UI display (not necessarily exhaustive)

	// Rows is the per-row report the bulk-issuance UI renders. Each entry
	// carries the original subject (so the operator can see WHO it was for),
	// the offer URI (so they can copy/send it), and status metadata. This
	// is what lets a government issuing office actually use the feature —
	// without it they can only see "10 accepted" and have no idea which
	// citizens got which offers. Row numbers are 1-indexed to match the
	// operator's mental model of "row 1 is the first data row of my file".
	Rows []BulkRowResult
}

// BulkRowResult is the per-row output for a bulk issuance.
type BulkRowResult struct {
	Row     int               // 1-indexed position in the source (CSV/API/DB)
	Subject map[string]string // the row's raw field values (holder, dateOfBirth, …)
	Label   string            // one-line summary picked from Subject (holder | firstName+familyName | first value)
	Status  string            // "issued" | "failed"
	OfferURI string           // OID4VCI offer URI — empty when Status=="failed"
	Error   string            // failure reason (truncated) — empty when Status=="issued"
}

// BulkError describes one row-level error in a bulk issuance.
type BulkError struct {
	Row    int
	Reason string
}

// PresentationRequest is the input to RequestPresentation. Callers can
// drive the verifier in two modes:
//
//   - By key:   set TemplateKey to a preset the adapter knows about.
//   - By value: set Template to an inline OID4VPTemplate (typically one the
//               handler assembled from a schema + user-selected fields).
//               Adapters that see a non-nil Template use it verbatim and
//               ignore TemplateKey.
type PresentationRequest struct {
	VerifierDpg string
	TemplateKey string // adapter-defined; maps to the verifier's stored presentation templates
	Template    *vctypes.OID4VPTemplate
	// Policies is the list of verification policies the operator selected
	// (see walt.id's vc_policies / vp_policies). Recognized values:
	// "signature" | "expired" | "not-before" | "webhook". Adapters that
	// don't support per-request policy tuning ignore the list.
	Policies   []string
	WebhookURL string // only used when "webhook" is in Policies
}

// PresentationRequestResult describes a generated OID4VP request.
type PresentationRequestResult struct {
	RequestURI string // the openid4vp:// URI
	State      string // server-side correlation token; echo back to FetchPresentationResult
	Template   vctypes.OID4VPTemplate
}

// DirectVerifyRequest is the input to VerifyDirect.
type DirectVerifyRequest struct {
	VerifierDpg    string
	Method         string // "scan" | "upload" | "paste"
	CredentialData string // raw credential string — decoded QR payload for scan, extracted QR for upload, raw JWT/VC for paste
}

// PresentCredentialRequest is the input to PresentCredential.
type PresentCredentialRequest struct {
	HolderDpg      string
	CredentialID   string // id of a credential already in the holder's wallet
	RequestURI     string // the openid4vp:// URI the holder received
	DisclosedClaim []string // optional: subset of claims to disclose for SD-JWT VC
}

// PresentationPreview describes what a verifier is asking for and which
// values the wallet would disclose if the holder confirms. Built by the
// optional PresentationPreviewer interface (walt.id implements it); used
// by /holder/present's consent interstitial so the operator reviews what
// leaves the wallet before the actual OID4VP submit.
type PresentationPreview struct {
	// VerifierClientID is the client_id the verifier advertised — usually
	// a base URL (e.g. http://verifier.example/openid4vc/verify). Rendered
	// as the "requested by" line.
	VerifierClientID string
	// CredentialID + CredentialTitle echo what the holder picked.
	CredentialID    string
	CredentialTitle string
	// Fields is one row per claim the verifier is asking for. Value is
	// what the wallet has for that claim (empty when the held credential
	// doesn't carry it); Required flags PD constraints that don't have a
	// walt.id-style "optional" marker — for now everything requested is
	// considered required.
	Fields []PresentationField
	// Disclosure mirrors the PD's limit_disclosure hint: "required" (SD-JWT
	// honors per-field filtering), "preferred" (JWT VC sends the whole
	// credential anyway), or "none" (no explicit limit_disclosure).
	Disclosure string
	// Compatible is false when the backend's matcher would reject the
	// picked credential (wrong format, missing claims, etc.). The consent
	// UI uses this to block the Disclose button and surface a specific
	// reason — better than letting the user click through and hit an
	// opaque "no credential matches" error on the submit.
	Compatible bool
	// IncompatibleReason names the specific mismatch when Compatible is
	// false. Rendered verbatim on the consent card.
	IncompatibleReason string
	// RequestedFormat is the credential format the verifier is asking
	// for (e.g. "vc+sd-jwt"). Surfaced so the incompatibility banner can
	// point at the exact format the operator would need to re-issue in.
	RequestedFormat string
}

// PresentationField is one claim row on the consent page.
type PresentationField struct {
	Name     string
	Value    string
	Required bool
}

// PresentationPreviewer is optionally implemented by adapters that can
// resolve a verifier's presentation definition without submitting. Handlers
// detect this via type assertion; non-implementing adapters get a minimal
// fallback preview (just the picked credential, no per-field breakdown).
type PresentationPreviewer interface {
	PreviewPresentation(ctx context.Context, req PresentCredentialRequest) (PresentationPreview, error)
}

// PresentCredentialResult describes the outcome of a holder-side presentation.
type PresentCredentialResult struct {
	Success       bool
	Method        string // human-readable summary, e.g. "OID4VP · selective over SD-JWT VC"
	SharedClaims  []string
	VerifierState string // echo of the verifier's state/correlation token, if any
}

// PolicyOutcome is one verifier policy's evaluation result. Passed=true
// means the policy ran cleanly; Reason carries walt.id's diagnostic
// string when a policy failed (verbatim — the UI surfaces it under
// the policy name so operators can act on the specific failure).
type PolicyOutcome struct {
	Name   string
	Passed bool
	Reason string
}

// FailedPolicies returns the subset whose Passed flag is false. Helper
// for templates that want to highlight just the failures without
// recomputing.
func (r VerificationResult) FailedPolicies() []PolicyOutcome {
	out := make([]PolicyOutcome, 0, len(r.PolicyOutcomes))
	for _, p := range r.PolicyOutcomes {
		if !p.Passed {
			out = append(out, p)
		}
	}
	return out
}

// VerificationResult is the output of both FetchPresentationResult and VerifyDirect.
//
// Pending=true signals that no holder has submitted a presentation yet — the
// verifier session is still open. The UI renders this as an "awaiting
// response" state instead of the red "invalid" card that would otherwise
// result from Valid=false. Direct-verify callers always leave Pending at
// its zero (false) — only the polling FetchPresentationResult ever sets it.
type VerificationResult struct {
	Valid             bool
	Pending           bool      // no holder submission yet; the rest of the fields are unset
	Method            string    // human-readable: "OID4VP · selective — only age_over_18 is shared"
	Format            string    // credential format: "w3c_vcdm_2", "sd_jwt_vc (IETF)", etc.
	Issuer            string    // issuer identifier (DID or URL)
	Subject           string    // subject identifier (typically a DID)
	Requested         []string  // fields received (OID4VP only; nil for direct verify)
	Issued            time.Time // when the credential was originally issued
	CheckedRevocation bool      // false for offline scan (no status-list lookup possible)
	// PoliciesApplied names the verification policies that were actually run
	// on the submitted credential (e.g. "signature", "expired"). Used by the
	// result fragment to show "the VP was verified along with:" like walt.id's
	// portal. Empty for direct-verify callers that don't expose policy info.
	PoliciesApplied []string
	// PolicyOutcomes is the per-policy success/failure detail. When Valid
	// is false this is the source of the operator's actionable info — the
	// result template renders the failed entries with their walt.id-supplied
	// reason text (e.g. "Status validation failed: expected 0, got 1" for
	// a revoked credential). Adapters that can't surface per-policy detail
	// leave this nil and the template falls back to PoliciesApplied.
	PolicyOutcomes []PolicyOutcome
	// DisclosedFields holds the holder-disclosed claim values extracted from
	// the VP token. The map key is the claim name, the value is the string
	// rendering (scalars stringified, nested objects JSON-encoded). Used by
	// the flip-side of the result card to show the actual data that was
	// shared — like walt.id's "Presented Credentials" panel.
	DisclosedFields map[string]string
	// CredentialTitle is the human-readable name of the presented credential
	// type (e.g. "Bank Id") — rendered as a heading on the flipped result.
	CredentialTitle string
	// IssuerDisplay is the human-readable issuer attribution recorded by
	// the issuing portal on the matching Schema (e.g. "Ministry of Health").
	// Surfaces next to the bare Issuer DID so verifier operators see who
	// stands behind a credential, not just an opaque key identifier.
	// Populated by the verifier handler on a best-effort basis: looks up
	// the schema by CredentialTitle in the local store, copies its
	// IssuerDisplayName. Empty when no matching schema exists (e.g.
	// credentials minted by a different deployment).
	IssuerDisplay string

	// TrustStatus is set by the verifier handler after a trust-registry
	// lookup on the Issuer DID. Values: "trusted", "untrusted", "unknown"
	// (registry configured but DID not found), or "" (no registry wired).
	TrustStatus string
	// TrustReason carries the explanation when TrustStatus is "untrusted",
	// e.g. "accreditation expired on 2026-01-01".
	TrustReason string
}
