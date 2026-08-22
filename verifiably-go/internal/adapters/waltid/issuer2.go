package waltid

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
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
// deploy/k8s/config/issuer2/issuer2-profiles.conf appear here: issuer-api2
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
var docTypeProfiles = map[string]mdocProfile{
	"org.iso.18013.5.1.mDL":   {"isoMdl", "org.iso.18013.5.1"},
	"org.iso.23220.photoid.1": {"isoPhotoId", "org.iso.23220.1"},
}

// profileIDForDocType resolves an ISO docType to its issuer-api2 profile.
func profileIDForDocType(docType string) (mdocProfile, bool) {
	p, ok := docTypeProfiles[docType]
	return p, ok
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
// deploy/k8s/config/issuer2/issuer2-profiles.conf) — walt.id's shipped default
// is a fictional Austrian person, and inheriting it silently would issue a
// real credential carrying someone else's data.
// structured carries the non-scalar claims (see backend.IssueRequest.
// StructuredData) that cannot ride in the flat subject map. A nil or empty
// map keeps the previous behaviour exactly.
func buildIssuer2Offer(schema vctypes.Schema, subject map[string]string, structured map[string]json.RawMessage) (issuer2OfferRequest, error) {
	docType := mdocDocTypeFor(schema)
	profile, ok := profileIDForDocType(docType)
	if !ok {
		return issuer2OfferRequest{}, fmt.Errorf(
			"waltid: no issuer-api2 profile for docType %q — only pre-provisioned docTypes can be issued (see deploy/k8s/config/issuer2/issuer2-profiles.conf)",
			docType)
	}

	data := make(map[string]any, len(subject)+len(structured))
	for k, v := range subject {
		if v == "" {
			continue // omit rather than assert a blank
		}
		data[k] = v
	}
	// Structured claims override any flat entry of the same name. The issue
	// form never posts both, but an API caller could, and the structured value
	// is the one the profile's arrayConfig can actually convert.
	for k, raw := range structured {
		if len(raw) == 0 {
			continue
		}
		// json.RawMessage marshals verbatim, so the array reaches issuer-api2
		// as a real JSON array rather than a quoted string. Validate here
		// rather than trusting the caller: a malformed value would otherwise
		// surface as an opaque walt.id error at wallet-redemption time, long
		// after the operator has left the form.
		if !json.Valid(raw) {
			return issuer2OfferRequest{}, fmt.Errorf(
				"waltid: structured claim %q is not valid JSON", k)
		}
		data[k] = raw
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
