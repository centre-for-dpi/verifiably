// Package vctypes holds the domain types the UI and adapters traffic in.
// These are pure data types — no behavior, no dependencies on either the
// mock or any specific backend implementation. Import this package from
// your own adapter code.
package vctypes

import (
	"strings"
	"time"
)

// DPG describes a Digital Public Good's capabilities.
// The same shape serves issuer, holder, and verifier DPGs; role-specific
// flags are simply unused when they don't apply.
type DPG struct {
	Vendor   string
	Version  string
	Tag      string // short label like "API-based" or "MOSIP"
	Tagline  string // one-line description
	Formats  []string
	Caveats  string // plain-language warning text shown in the UI
	Redirect bool   // holder/verifier only — if true, selecting this DPG hands off to its own UI
	// UIURL is the public URL of the vendor's own UI, used as the target
	// address the redirect-notice page links to. Populated by the registry
	// from backends.json; empty for non-redirect DPGs.
	UIURL string
	// InAppPath, when set, makes selecting this DPG navigate to an in-app flow
	// (e.g. "/issuer/schema/build" or "/holder/wallet/inji") instead of the
	// external redirect notice. Takes precedence over Redirect.
	InAppPath string
	// SchemaApply, when "inji_authcode", makes the shared schema builder's save
	// apply via the Inji auth-code (Flow B) path instead of the default adapter
	// (issuing every data model the builder offers as Inji Certify credentials).
	SchemaApply string

	// Issuer-specific capability flags
	FlowPreAuth                 bool
	FlowAuthCode                bool
	FlowPresentationDuringIssue bool
	FlowPlain                   string // plain-language explanation of flows
	FormatsPlain                string // plain-language explanation of formats
	DirectPDF                   bool
	DirectPDFPlain              string
	// BulkOnly, when true, marks a DPG whose only issuance model is
	// bulk-provision-then-self-claim (e.g. Inji auth-code: the issuer loads
	// many subjects into the data-provider table, holders then claim via
	// eSignet). The Mode page greys the single-subject scale and
	// ShowIssuanceMode/SetIssuanceMode force Scale="bulk".
	BulkOnly bool

	// Structured capability list. Renders on the DPG picker card and drives
	// downstream screen branching via Kind/Key pairs (no string matches on
	// vendor names in handlers). Empty for legacy/mock DPGs; registry-backed
	// DPGs populate this from backends.json.
	Capabilities []Capability
}

// Capability is one structured "what you'll actually experience" item on a DPG
// card. Handlers may look up capabilities by Kind to decide whether to enable a
// downstream option (e.g. Kind="mode" Key="pdf" to enable the PDF destination).
// Title/Body render to the user; Kind/Key drive logic.
type Capability struct {
	Title string // short headline, e.g. "User logs in at the identity provider"
	Body  string // one-sentence plain-language description
	Kind  string // "flow" | "data" | "wallet" | "token" | "mode" | "limitation"
	Key   string // machine key: e.g. "auth_code", "pre_auth", "pdf", "identity_lookup"
}

// Schema is a credential schema available to an issuer.
type Schema struct {
	ID     string
	Name   string
	Std    string   // e.g. "w3c_vcdm_2", "sd_jwt_vc (IETF)", "jwt_vc", "mso_mdoc"
	DPGs   []string // vendor names that support this schema
	Desc   string
	Custom bool // true for user-built schemas

	// OwnerKey is the stable per-issuer identity key (typically the
	// authenticated OIDC `provider|sub` pair) of the operator who saved
	// this custom schema. Empty for stock/vendor catalog entries (which
	// every issuer can see) or for legacy custom schemas saved before
	// owner-scoping shipped. Registry.ListSchemas filters its in-memory
	// custom-schema slice by this key so issuer A's schema browser
	// never surfaces schemas saved by issuer B.
	OwnerKey string

	// IssuerDisplayName is the human-readable issuer attribution for
	// credentials of this schema (e.g. "Ministry of Health"). Surfaces
	// in two places:
	//   - walt.id catalog `display.description` (composed alongside
	//     Schema.Desc) so external wallets fetching the wellknown see
	//     "<Desc> · Issued by <IssuerDisplayName>" on the credential
	//     card. Walt.id 0.18.2 has no per-credential issuer field in
	//     the wellknown; composition into description is the only
	//     surface that propagates across formats.
	//   - verifier UI's result panel — when verifying a presented
	//     credential, we look up the matching schema by name in our
	//     own store and render this value alongside the bare DID
	//     walt.id put in the VC body. Visible to verifiers running on
	//     the same verifiably-go instance; external verifiers without
	//     access to our schema metadata fall back to the DID.
	IssuerDisplayName string

	// Custom-schema extras (empty for pre-configured schemas)
	AdditionalTypes []string
	FieldsSpec      []FieldSpec

	// SourceIssuerDID identifies the issuer DID that defined this schema.
	// Set by the Hub's schema aggregator on federated schemas so the public
	// /verify portal can perform trust checks against the correct issuer.
	SourceIssuerDID string `json:"sourceIssuerDid,omitempty"`

	// SourceDeployment is the Hub's Registry adapter key (member.ID from
	// federation.json) for the issuer that owns this schema. Used by
	// PublicVerifyRequest to route the OID4VP request to the correct verifier.
	SourceDeployment string `json:"sourceDeployment,omitempty"`

	// Variants lists every wire-format this credential type is available in.
	// For walt.id, one credential name (e.g. "IdentityCredential") is served
	// under several configuration ids (one per format). The schema picker
	// collapses them into a single card and uses Variants to render the
	// format chip-row — so users switch format without navigating away.
	// ID on the Schema itself points to the currently-selected variant;
	// Variants[i].ID is the configuration id to submit if the user picks
	// that format. Empty for custom schemas (format is fixed by Std).
	Variants []SchemaVariant

	// Vct mirrors the selected variant's Vct (the SD-JWT VC issuer-
	// advertised credential type URL, e.g.
	// "http://localhost:7002/draft13/OpenBadgeCredential"). ApplyVariant
	// copies it onto the Schema so downstream code (walt.id's SD-JWT
	// issuance body) can set the credential's vct claim correctly —
	// using Schema.ID instead produces a vct that doesn't match the PD
	// filter walt.id's verifier advertises for the same credential.
	Vct string
}

// SchemaVariant is one available wire-format for a credential type. Label
// is the human-readable name shown in the UI (e.g. "SD-JWT + IETF"); Format
// is the raw walt.id format key (e.g. "vc+sd-jwt"); Std is the verifiably-go
// taxonomy category the format belongs to (e.g. "sd_jwt_vc (IETF)").
type SchemaVariant struct {
	ID     string
	Format string
	Std    string
	Label  string
	// Vct is the SD-JWT VC's `vct` claim — the issuer-advertised
	// credential type URL. Walt.id's verifier/wallet PD matcher keys off
	// this exact string for SD-JWT presentations, so the verifier's
	// request must carry the full URL (not just the short type name).
	// Empty for non-SD-JWT variants.
	Vct string
	// CanPresent is false for formats that the backend issuer can emit but
	// the verifier can't filter for (so the credential can't be presented
	// end-to-end). Walt.id Community Stack v0.18.2 has two such gaps —
	// `jwt_vc_json-ld` (missing from its VCFormat enum) and `dc+sd-jwt`
	// (rejected by VerifierService.getPresentationFormat). The verifier UI
	// hides these; the issuer UI shows them with a warning so the operator
	// chooses knowingly.
	CanPresent bool
}

// HasVariantID returns true if id equals the Schema's own ID or any variant's
// ID. Handlers use this for schema lookup after a user switches format — the
// selected id may be a non-default variant that wouldn't match s.ID.
func (s Schema) HasVariantID(id string) bool {
	if s.ID == id {
		return true
	}
	for _, v := range s.Variants {
		if v.ID == id {
			return true
		}
	}
	return false
}

// ApplyVariant returns a copy of s with ID + Std replaced by the matching
// variant's values. Returns s unchanged when id already equals s.ID or no
// matching variant exists. This lets downstream code (IssueToWallet,
// buildCredentialData) see the user's chosen format on the Schema itself.
func (s Schema) ApplyVariant(id string) Schema {
	if s.ID == id {
		// Populate Vct even for the default variant so SD-JWT issuance
		// doesn't fall back to Schema.ID.
		for _, v := range s.Variants {
			if v.ID == id {
				s.Vct = v.Vct
				return s
			}
		}
		return s
	}
	for _, v := range s.Variants {
		if v.ID == id {
			s.ID = v.ID
			s.Std = v.Std
			s.Vct = v.Vct
			return s
		}
	}
	return s
}

// BaseType returns the canonical credential type name by stripping known
// wire-format suffixes from s.ID. Walt.id's config ids follow the pattern
// "<TypeName>_<format>" (e.g. "BankId_vc+sd-jwt") where TypeName is the
// credential type as used in the VP's `type` or `vct` claim. Other
// adapters that use this helper get a no-op when none of the known
// suffixes match — they can store BaseType on Schema.ID directly.
func (s Schema) BaseType() string {
	suffixes := []string{
		"_jwt_vc_json-ld",
		"_jwt_vp_json-ld",
		"_jwt_vc_json",
		"_jwt_vp_json",
		"_vc+sd-jwt",
		"_dc+sd-jwt",
		"_mso_mdoc",
		"_ldp_vc",
		"_ldp_vp",
		"_jwt_vc",
		"_jwt_vp",
	}
	for _, suf := range suffixes {
		if strings.HasSuffix(s.ID, suf) {
			return strings.TrimSuffix(s.ID, suf)
		}
	}
	return s.ID
}

// CustomTypeName returns the canonical credential type identifier for a
// custom (user-built) schema. This is the string that:
//   - lands in the issued VC's `type` array (W3C JWT/LDP) or `vct` claim
//     (SD-JWT VC) — set during issuance by the walt.id adapter
//   - identifies the catalog entry registered with walt.id (configID is
//     "<TypeName>_<wireFormat>")
//   - is what the verifier's PD filter must ask for to match what's in the
//     wallet
//
// Prefers AdditionalTypes[0] (the builder's "Extra Type" field) so an
// operator who knows the canonical name can pin it; otherwise CamelCases
// the schema's Name. Empty/all-non-alphanumeric Name falls back to
// "CustomCredential" so we always emit something valid.
//
// Stock (non-Custom) schemas should use Schema.BaseType() — this method
// is meaningful only when Schema.Custom == true.
func (s Schema) CustomTypeName() string {
	if len(s.AdditionalTypes) > 0 {
		if t := strings.TrimSpace(s.AdditionalTypes[0]); t != "" {
			return t
		}
	}
	return sanitizeTypeNameVC(s.Name)
}

// sanitizeTypeNameVC mirrors waltid.sanitizeTypeName — kept here so vctypes
// stays vendor-agnostic. Title-cases letter runs and strips non-alphanumerics;
// "" → "CustomCredential" so callers always get a valid identifier.
func sanitizeTypeNameVC(name string) string {
	var b strings.Builder
	capNext := true
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			capNext = false
		case r >= 'a' && r <= 'z':
			if capNext {
				b.WriteRune(r - 32)
			} else {
				b.WriteRune(r)
			}
			capNext = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			capNext = false
		default:
			capNext = true
		}
	}
	out := b.String()
	if out == "" {
		return "CustomCredential"
	}
	return out
}

// FieldSpec describes one claim in a credential schema.
type FieldSpec struct {
	Name     string
	Datatype string // "string" | "number" | "integer" | "boolean"
	Format   string // optional: "date" | "uri" | ...
	Required bool
}

// Credential is the wallet/verifier-side view of an issued credential.
// For pending offers (not yet accepted into a wallet), Status is "pending".
type Credential struct {
	ID     string
	Title  string
	Issuer string
	// IssuerDisplay is the human-readable attribution sourced from the
	// matching Schema.IssuerDisplayName (e.g. "Ministry of Health"). The
	// wallet card renders this in place of the bare DID when populated;
	// raw `Issuer` (a DID or URL) remains the fallback so creds minted by
	// other deployments still surface something. Empty when no matching
	// schema is in the local store.
	IssuerDisplay string
	Type          string
	// Format is the wire format the backend stored this credential in,
	// e.g. "jwt_vc_json" or "vc+sd-jwt". Used in UI pickers so the user
	// can distinguish multiple credentials of the same name that differ
	// only by format — otherwise a picker showing "Open Badge Credential"
	// twice is impossible to choose from correctly.
	Format string
	Status string // "pending" | "accepted"
	Source string // "scan" | "paste" | "inbox" — how the holder received it
	Fields map[string]string
}

// OID4VPTemplate is a preset presentation request a verifier can issue.
type OID4VPTemplate struct {
	Title      string
	Fields     []string
	Format     string // the verifiably-go Std ("w3c_vcdm_2", "sd_jwt_vc (IETF)", "mso_mdoc")
	Disclosure string // plain-language disclosure summary shown to the verifier operator
	// CredentialType is the canonical walt.id credential type (e.g.
	// "BankId", "OpenBadgeCredential") — used as the `type` filter when
	// building JWT VC presentation requests. Falls back to Title when
	// empty, but that guess appends "Credential" and is often wrong.
	CredentialType string
	// Vct is the full `vct` URL for SD-JWT VC credentials (e.g.
	// "http://issuer.example/draft13/BankId"). Walt.id's PD matcher
	// demands the exact issuer-advertised URL, not a short type name.
	// Empty for non-SD-JWT templates.
	Vct string
	// WireFormat is the exact walt.id format key (jwt_vc_json / ldp_vc /
	// vc+sd-jwt / etc.) the verifier's presentation_definition should
	// specify. Format carries the Std — a taxonomy grouping — but one
	// Std spans multiple wire formats (w3c_vcdm_2 covers jwt_vc_json,
	// jwt_vc_json-ld, ldp_vc, jwt_vc), and walt.id's matcher treats
	// each as distinct. Adapters prefer WireFormat over Format when
	// building the PD, so the specific chip the user clicked survives
	// into the request.
	WireFormat string
}

// IssuerIdentity is the operator's own display identity (the "who's issuing this").
type IssuerIdentity struct {
	Name string
	DID  string
}

// Duration-safe helpers for adapters that work with time.Duration naturally.
// ExpiresIn on IssueToWalletResult is a time.Duration; helper converts to seconds.
func SecondsFromDuration(d time.Duration) int { return int(d / time.Second) }
