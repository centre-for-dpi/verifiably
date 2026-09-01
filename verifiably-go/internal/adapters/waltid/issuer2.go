package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// issuer-api2 is a SEPARATE walt.id service from the legacy issuer-api, used
// only for mso_mdoc. It is the only walt.id issuer that can type CBOR (via
// mDocNameSpacesDataMappingConfig), which ISO 18013-5 requires: without it
// birth_date serialises as text instead of tag 1004 and portrait as text
// instead of a byte string, and no conformant reader accepts the result.
//
// Every other format stays on the legacy issuer-api — issuer-api2 demands
// pre-provisioned profiles and so cannot host the operator-defined custom
// schemas SaveCustomSchema supports today.

// mdocProfile pairs an issuer-api2 profileId with the base namespace its
// docType uses. The namespace is carried explicitly rather than derived by
// stripping the docType's last dot-segment: that derivation holds for mDL
// (org.iso.18013.5.1.mDL -> org.iso.18013.5.1) but NOT for Photo ID
// (org.iso.23220.photoid.1 strips to org.iso.23220.photoid, while the real
// base namespace is org.iso.23220.1). Getting this wrong produces a
// structurally valid credential with a wrong namespace — silently
// non-conformant.
type mdocProfile struct {
	profileID     string
	baseNamespace string
}

// docTypeProfiles maps an ISO docType onto the issuer-api2 profile that
// issues it. Only docTypes with a profile versioned in
// deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf appear here: issuer-api2
// rejects a profileId it cannot resolve, so an unlisted docType must fail
// early with a clear message rather than at issuance time.
//
// Keys must match issuer2-profiles.conf's credentialConfigurationId EXACTLY,
// including case — this is an exact-match allowlist, not a
// case-insensitive lookup. mDL and Photo ID disagree on the casing of their
// last segment (mDL vs photoid) because the underlying ISO standards
// themselves disagree, not because of any inconsistency in our code. Do not
// "tidy" these into matching case; that would break resolution for whichever
// one you changed.
//
// mDL's entry is ALLOWLIST MEMBERSHIP + NAMESPACE ONLY — its profileID is
// deliberately "", not a real profile. mDL has no single profile to name
// here: buildIssuer2Offer selects isoMdl_1cat..isoMdl_4cat by the real
// driving_privileges count via mdlProfileForCategoryCount, and "isoMdl"
// itself no longer exists in the HOCON (it was split into those four). A
// caller that ignores mdlProfileForCategoryCount and dispatches on this
// map's mDL profileID directly must fail loudly on the empty string rather
// than silently POSTing a deleted profile name to walt.id.
//
// baseNamespace comes from mdoc.NamespaceForDocType — the allowlist shared
// with internal/adapters/injicertify/db.go's mdocNamespaceForDocType — rather
// than a literal here, so the two adapters cannot drift onto different
// namespaces for the same docType the way injicertify's independent
// dot-stripping reimplementation once silently did for Photo ID.
var docTypeProfiles = map[string]mdocProfile{
	mdoc.MDLDocType:     {profileID: "", baseNamespace: mustNamespace(mdoc.MDLDocType)},
	mdoc.PhotoIDDocType: {profileID: "isoPhotoId", baseNamespace: mustNamespace(mdoc.PhotoIDDocType)},
}

// mustNamespace resolves a docType's namespace from the package-level
// allowlist docTypeProfiles is built from. Panics on an unknown docType —
// acceptable here because this only ever runs at package-init time over the
// two docType constants above, never over request data; a mismatch would be
// a programming error caught at process startup, not a runtime condition.
func mustNamespace(docType string) string {
	ns, ok := mdoc.NamespaceForDocType(docType)
	if !ok {
		panic("waltid: mdoc.NamespaceForDocType has no entry for " + docType)
	}
	return ns
}

// profileIDForDocType resolves an ISO docType to its issuer-api2 profile.
func profileIDForDocType(docType string) (mdocProfile, bool) {
	p, ok := docTypeProfiles[docType]
	return p, ok
}

// mdlProfileForCategoryCount resolves the issuer-api2 profile for an mDL
// carrying exactly n real driving_privileges entries.
//
// walt.id's arrayConfig requires an EXACT length match — confirmed
// empirically against a real issuer-api2:0.23.1 with arrayConfig sizes of
// 2, 3, and 6: in every case, only that exact declared size succeeds, any
// other length (including a smaller one) fails with
// "Json array sizes (input & config) are not equal". There is no
// variable-length mechanism in walt.id's config model to fall back to.
//
// So instead of one isoMdl profile padded to a fixed size,
// issuer2-profiles.baseline.conf declares one profile PER real category
// count — isoMdl_1cat through isoMdl_4cat — all sharing the same
// credentialConfigurationId ("org.iso.18013.5.1.mDL") and the same
// issuerKey/x5Chain (by HOCON substitution reference, not literal
// duplication). Confirmed empirically that two profiles sharing one
// credentialConfigurationId do not collide: profileId is fixed
// server-side at offer-creation time (POST /issuer2/credential-offers),
// before the wallet ever resolves anything, so the wallet never needs to
// disambiguate between them.
//
// n <= 0 or n > mdoc.DrivingPrivilegesMaxCategories returns (mdocProfile{}, false):
// 0 real categories is refused because driving_privileges is a MANDATORY
// ISO 18013-5 Table 3 element for mDL, and more than the ceiling has no
// profile provisioned for it.
func mdlProfileForCategoryCount(n int) (mdocProfile, bool) {
	if n <= 0 || n > mdoc.DrivingPrivilegesMaxCategories {
		return mdocProfile{}, false
	}
	return mdocProfile{
		profileID:     fmt.Sprintf("isoMdl_%dcat", n),
		baseNamespace: "org.iso.18013.5.1",
	}, true
}

// mdocDocTypeFor resolves a schema's ISO docType.
//
// AdditionalTypes[0] comes first: for a builder-made mdoc schema that is the
// operator's selected docType, and it is the ONLY place that survives the
// save. SaveCustomSchema persists a custom schema under its generated
// "custom-<nano>" ID, so BaseType() — which derives from Schema.ID by
// stripping a wire-format suffix — hands back that generated ID rather than
// the docType. Resolving from it failed on a real deployment with
//
//	no issuer-api2 profile for docType "custom-dkv6iyntczt6"
//
// while the docType sat correctly in AdditionalTypes the whole time.
//
// BaseType() remains the fallback for stock catalog entries, whose IDs are
// "<docType>_<wireFormat>" and carry no AdditionalTypes.
func mdocDocTypeFor(schema vctypes.Schema) string {
	if len(schema.AdditionalTypes) > 0 {
		if dt := strings.TrimSpace(schema.AdditionalTypes[0]); dt != "" {
			return dt
		}
	}
	if dt := schema.BaseType(); dt != "" {
		return dt
	}
	return schema.ID
}

// mdocNamespaceFor derives the namespace from a docType by stripping the last
// dot-segment: org.iso.18013.5.1.mDL -> org.iso.18013.5.1.
//
// This heuristic does NOT hold for every docType: org.iso.23220.photoid.1
// strips to org.iso.23220.photoid, but Photo ID's real base namespace is
// org.iso.23220.1. It is correct for mDL only by coincidence of that
// docType's shape.
//
// buildIssuer2Offer does not call this directly — it takes the namespace
// from docTypeProfiles, where it is pinned explicitly per docType and so
// cannot be wrong in this way. The one remaining caller is
// catalog.go's namespace resolution, which falls back to this function only
// for a docType absent from docTypeProfiles (i.e. one with no provisioned
// issuer-api2 profile yet). That is exactly why the fallback exists and
// exactly why it must not become the primary path: extending it to cover
// Photo ID would reintroduce the wrong-namespace bug docTypeProfiles was
// built to avoid.
func mdocNamespaceFor(docType string) string {
	if i := strings.LastIndex(docType, "."); i > 0 {
		return docType[:i]
	}
	return docType
}

// issuer2OfferRequest is the POST /issuer2/credential-offers body. Its shape
// differs from the legacy issuer-api's IssuanceRequest entirely: profileId +
// runtimeOverrides, not credentialConfigurationId + mdocData.
type issuer2OfferRequest struct {
	ProfileID        string                   `json:"profileId"`
	AuthMethod       string                   `json:"authMethod"`
	ExpiresInSeconds int                      `json:"expiresInSeconds,omitempty"`
	RuntimeOverrides *issuer2RuntimeOverrides `json:"runtimeOverrides,omitempty"`
}

type issuer2RuntimeOverrides struct {
	// CredentialData is namespace-keyed, exactly like the legacy mdocData:
	// {"<namespace>": {"<field>": <value>}}.
	//
	// The inner value type is `any`, not `string`, because ISO 18013-5's
	// `driving_privileges` is an array of objects. It was map[string]string,
	// so the operator's form value reached walt.id as the JSON string "1" and
	// issuance failed at wallet-redemption time with "Expected to execute
	// conversion from json array, but input |\"1\"| is not a json array"
	// (TODO.md F4). Flat fields still marshal as JSON strings exactly as
	// before — only the structured ones differ.
	CredentialData map[string]map[string]any `json:"credentialData,omitempty"`
}

// issuer2OfferResponse is the 201 body. The legacy issuer-api returns the
// offer URI as a bare text/plain string; issuer-api2 returns JSON, so the
// caller must parse rather than trim.
type issuer2OfferResponse struct {
	OfferID         string `json:"offerId"`
	CredentialOffer string `json:"credentialOffer"`
}

// issuer2OfferTTL bounds how long the citizen has to scan the offer.
const issuer2OfferTTL = 300

// buildIssuer2Offer turns a schema plus the operator's filled-in fields into
// a credential-offer request.
//
// Only fields the operator actually supplied are sent. This is deliberate and
// load-bearing: issuer-api2 deep-merges runtimeOverrides over the profile, so
// an omitted field keeps whatever the profile holds. Our versioned profile has
// its sample data emptied for exactly this reason (see
// deploy/k8s/config/issuer2/issuer2-profiles.baseline.conf) — walt.id's shipped default
// is a fictional Austrian person, and inheriting it silently would issue a
// real credential carrying someone else's data.
// structured carries the non-scalar claims (see backend.IssueRequest.
// StructuredData) that cannot ride in the flat subject map. A nil or empty
// map keeps the previous behaviour exactly, EXCEPT for mDL: an mDL with no
// driving_privileges is now a hard error (see below), because the field is
// ISO 18013-5 Table 3 MANDATORY and there is no longer a padding path to
// silently paper over its absence.
func buildIssuer2Offer(schema vctypes.Schema, subject map[string]string, structured map[string]json.RawMessage) (issuer2OfferRequest, error) {
	docType := mdocDocTypeFor(schema)

	var profile mdocProfile
	if docType == "org.iso.18013.5.1.mDL" {
		// mDL selects its profile by the REAL number of driving_privileges
		// entries the operator supplied — see mdlProfileForCategoryCount's
		// doc comment for why: walt.id's arrayConfig requires an exact
		// length match, confirmed empirically, so one profile per real
		// category count replaces the old fixed-size-plus-padding approach.
		n := 0
		if raw, ok := structured["driving_privileges"]; ok && len(raw) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return issuer2OfferRequest{}, fmt.Errorf(
					"waltid: driving_privileges is not a JSON array: %w", err)
			}
			n = len(arr)
		}
		p, ok := mdlProfileForCategoryCount(n)
		if !ok {
			if n == 0 {
				return issuer2OfferRequest{}, fmt.Errorf(
					"waltid: driving_privileges es obligatorio en ISO 18013-5 — ingresa al menos una categoría de conducción antes de emitir")
			}
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: no se pueden emitir %d categorías de conducción en una sola credencial — el máximo es %d",
				n, mdoc.DrivingPrivilegesMaxCategories)
		}
		profile = p
	} else {
		p, ok := profileIDForDocType(docType)
		if !ok {
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: no issuer-api2 profile for docType %q — only pre-provisioned docTypes can be issued (see deploy/k8s/config/issuer2/issuer2-profiles.conf)",
				docType)
		}
		profile = p
	}

	data := make(map[string]any, len(subject)+len(structured))
	for k, v := range subject {
		if v == "" {
			continue // omit rather than assert a blank
		}
		data[k] = v
	}
	// Omitting a blank is right for text, but FATAL for a date. issuer-api2
	// deep-merges runtimeOverrides over the profile, and our profile ships
	// every sample value emptied (walt.id's defaults are a fictional Austrian
	// person). So a date we omit keeps the profile's "" — and its
	// stringToFullDate conversion cannot parse an empty string. The offer
	// still returns 201; issuance dies on the citizen's phone with
	//
	//	java.time.format.DateTimeParseException: Text '' could not be parsed
	//
	// Reproduced against a live issuer-api2 by omitting issue_date. Sending a
	// real value for every date the profile maps is the only way to keep the
	// profile's blank from reaching the converter, so an unfilled optional
	// date falls back to a defined one rather than being left out.
	for _, f := range schema.FieldsSpec {
		if f.Format != "date" {
			continue
		}
		if s, ok := data[f.Name].(string); ok && strings.TrimSpace(s) != "" {
			continue
		}
		if fb := mdocDateFallback(f.Name, subject); fb != "" {
			data[f.Name] = fb
		}
	}
	// Structured claims override any flat entry of the same name. The issue
	// form never posts both, but an API caller could, and the structured value
	// is the one the profile's arrayConfig can actually convert.
	for k, raw := range structured {
		if len(raw) == 0 {
			continue
		}
		// Decoding into `any` (rather than keeping the json.RawMessage bytes)
		// makes the in-memory request already hold the same shape the wire
		// body will carry — a real []any for an array claim like
		// driving_privileges, not a quoted string — so callers inspecting
		// req.RuntimeOverrides directly (as tests do) see the same type the
		// HTTP body serialises to. json.RawMessage's own MarshalJSON would
		// have produced a semantically/structurally equivalent wire body —
		// same keys, same values, same array order — but NOT necessarily
		// byte-identical: decoding to `any` yields map[string]any, which
		// encoding/json marshals with keys sorted alphabetically, so object
		// key order can differ from a raw passthrough. Nothing downstream
		// relies on byte-stability of this JSON (walt.id's entriesConfigMap
		// is name-keyed, not positional), so that difference is harmless —
		// decoding here keeps both paths consistent without relying on
		// json.RawMessage's implicit passthrough behaviour.
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: structured claim %q is not valid JSON: %w", k, err)
		}
		data[k] = v
	}

	req := issuer2OfferRequest{
		ProfileID:        profile.profileID,
		AuthMethod:       "PRE_AUTHORIZED",
		ExpiresInSeconds: issuer2OfferTTL,
	}
	if len(data) > 0 {
		req.RuntimeOverrides = &issuer2RuntimeOverrides{
			CredentialData: map[string]map[string]any{profile.baseNamespace: data},
		}
	}
	return req, nil
}

// issueMdocViaIssuer2 posts a credential offer to issuer-api2 and adapts its
// JSON response to the same IssueToWalletResult the legacy path returns, so
// callers cannot tell which service issued.
func (a *Adapter) issueMdocViaIssuer2(ctx context.Context, req backend.IssueRequest) (backend.IssueToWalletResult, error) {
	if a.issuer2 == nil {
		return backend.IssueToWalletResult{}, fmt.Errorf(
			"waltid: mso_mdoc requires issuer-api2 but issuer2BaseUrl is not configured — the legacy issuer-api cannot type CBOR and would emit a non-conformant credential")
	}

	offerReq, err := buildIssuer2Offer(req.Schema, req.SubjectData, req.StructuredData)
	if err != nil {
		return backend.IssueToWalletResult{}, err
	}

	raw, err := a.issuer2.DoRaw(ctx, "POST", "/issuer2/credential-offers",
		jsonReader(offerReq), "application/json", nil)
	if err != nil {
		// Surface issuer-api2's own message verbatim. A malformed profile
		// breaks its whole catalog, so the service's wording is more useful
		// to whoever debugs this than anything we could substitute.
		return backend.IssueToWalletResult{}, fmt.Errorf("waltid issuer-api2: %w", err)
	}

	var resp issuer2OfferResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return backend.IssueToWalletResult{}, fmt.Errorf(
			"waltid issuer-api2: parse offer response: %w (body: %.200s)", err, string(raw))
	}
	if resp.CredentialOffer == "" {
		return backend.IssueToWalletResult{}, fmt.Errorf(
			"waltid issuer-api2: response carried no credentialOffer (body: %.200s)", string(raw))
	}

	return backend.IssueToWalletResult{
		OfferURI: resp.CredentialOffer,
		OfferID:  resp.OfferID,
		Flow:     req.Flow,
	}, nil
}

// mdocDateFallback supplies a defensible value for a date the operator left
// blank, so the profile's unparseable "" never reaches walt.id's converter.
//
// This is deliberately NOT "today" for everything. A date in an mdoc is an
// assertion about the holder, and inventing one is worse than a failed
// issuance: nobody audits a credential that looks fine. So each fallback is
// chosen to be either tautologically true or a restatement of a value the
// operator did supply:
//
//   - issue_date: today. The credential IS being issued now, so this is true
//     by construction.
//   - portrait_capture_date: the issue date when present, else today. ISO
//     treats it as metadata about the image, and claiming the portrait was
//     captured no later than issuance is the conservative reading.
//
// Any other date-mapped field returns "" — the caller then leaves it out and
// issuance fails loudly at redemption. That is intentional: a field we cannot
// derive honestly must not be silently filled, and a hard failure is the
// signal to add it to the form (see TestEveryProfileDateFieldIsReachableFromTheForm).
func mdocDateFallback(name string, subject map[string]string) string {
	today := time.Now().UTC().Format("2006-01-02")
	switch name {
	case "issue_date":
		return today
	case "portrait_capture_date":
		if v := strings.TrimSpace(subject["issue_date"]); v != "" {
			return v
		}
		return today
	default:
		return ""
	}
}
