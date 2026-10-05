// SPDX-License-Identifier: Apache-2.0

package service

import (
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
)

// FormatOf maps a proto format to the core format.
func FormatOf(f commonv1.Format) vc.Format {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_DC_SD_JWT:
		return vc.FormatSDJWT
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return vc.FormatJWT
	case commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_LDP_VC_BBS:
		return vc.FormatJSONLD
	case commonv1.Format_FORMAT_MSO_MDOC:
		return vc.FormatMdoc
	case commonv1.Format_FORMAT_UNSPECIFIED:
	}
	return vc.FormatUnknown
}

// ToPresentation turns a RawPresentation into the input of the checks.
// A credential that does not decode becomes a credential with an empty
// view, so the signature check reports the problem.
func ToPresentation(raw *ingestv1.RawPresentation) policy.Presentation {
	out := policy.Presentation{
		Carrier:   carrierName(raw.GetCarrier()),
		Nonce:     raw.GetNonce(),
		Envelopes: envelopes(raw.GetPayload()),
	}
	if raw.GetStackCheckedHolder() {
		// The verifier of the stack accepted the answer, holder binding
		// included (ADR-083 decision 4).
		out.Holder = &vc.HolderBinding{Confirmed: true}
	}
	for _, c := range raw.GetCredentials() {
		out.Credentials = append(out.Credentials, toCredential(FormatOf(c.GetFormat()), c.GetPayload()))
	}
	if len(out.Credentials) == 0 && len(raw.GetPayload()) > 0 {
		out.Credentials = append(out.Credentials, toCredential(FormatOf(raw.GetFormat()), raw.GetPayload()))
	}
	return out
}

// toCredential decodes one credential payload.
func toCredential(format vc.Format, payload []byte) policy.Credential {
	if format == vc.FormatUnknown {
		format = vc.DetectFormat(payload)
	}
	out := policy.Credential{Format: format}
	if format != vc.FormatJSONLD && format != vc.FormatJSON {
		out.Token = string(payload)
	}
	if parsed, err := vc.Parse(payload); err == nil {
		out.VC = parsed
	}
	return out
}

// envelopes returns the VP JWTs of a vp_token: the token itself, or the
// entries of a list or of a query id map, that carry a vp claim.
func envelopes(payload []byte) []string {
	text := strings.TrimSpace(string(payload))
	var tokens []string
	var list []any
	var byQuery map[string]any
	switch {
	case json.Unmarshal([]byte(text), &list) == nil:
		tokens = vc.AsStringSlice(list)
	case json.Unmarshal([]byte(text), &byQuery) == nil:
		for _, v := range byQuery {
			tokens = append(tokens, vc.AsStringSlice(v)...)
		}
	default:
		tokens = []string{text}
	}
	var out []string
	for _, tok := range tokens {
		if claims, err := jose.PeekPayload(tok); err == nil && claims["vp"] != nil {
			out = append(out, tok)
		}
	}
	sort.Strings(out)
	return out
}

// carrierName returns the plain word of a carrier. Both directions of
// OID4VP are an OID4VP answer to the checks.
func carrierName(c ingestv1.Carrier) string {
	switch c {
	case ingestv1.Carrier_CARRIER_OID4VP, //nolint:staticcheck // SA1019: the service still reads the old carrier value
		ingestv1.Carrier_CARRIER_OID4VP_RESPONSE:
		return policy.CarrierOID4VP
	case ingestv1.Carrier_CARRIER_IMAGE:
		return "image"
	case ingestv1.Carrier_CARRIER_PDF:
		return "pdf"
	case ingestv1.Carrier_CARRIER_XML:
		return "xml"
	case ingestv1.Carrier_CARRIER_JSON:
		return "json"
	case ingestv1.Carrier_CARRIER_QR:
		return "qr"
	case ingestv1.Carrier_CARRIER_QR_CLAIM169:
		return "qr-claim169"
	case ingestv1.Carrier_CARRIER_UNSPECIFIED:
	}
	return "unknown"
}

// ToProtoResults maps the check results into proto.
func ToProtoResults(results []policy.CheckResult) []*policyv1.CheckResult {
	out := make([]*policyv1.CheckResult, 0, len(results))
	for _, r := range results {
		out = append(out, &policyv1.CheckResult{
			Name:            r.Name,
			Outcome:         outcomeOf(r.Result),
			Detail:          r.Detail,
			Evidence:        r.Evidence,
			CredentialIndex: toInt32(int64(r.CredentialIndex)),
		})
	}
	return out
}

// outcomeOf maps a core outcome to proto.
func outcomeOf(o policy.Outcome) policyv1.Outcome {
	switch o {
	case policy.Pass:
		return policyv1.Outcome_OUTCOME_PASS
	case policy.Fail:
		return policyv1.Outcome_OUTCOME_FAIL
	case policy.Skip:
		return policyv1.Outcome_OUTCOME_SKIP
	case policy.Error:
		return policyv1.Outcome_OUTCOME_ERROR
	}
	return policyv1.Outcome_OUTCOME_UNSPECIFIED
}

// VerdictOf maps a core verdict to proto.
func VerdictOf(v policy.Verdict) policyv1.EvaluateResponse_Verdict {
	switch v {
	case policy.Valid:
		return policyv1.EvaluateResponse_VERDICT_VALID
	case policy.Invalid:
		return policyv1.EvaluateResponse_VERDICT_INVALID
	case policy.Indeterminate:
		return policyv1.EvaluateResponse_VERDICT_INDETERMINATE
	}
	return policyv1.EvaluateResponse_VERDICT_UNSPECIFIED
}

// ToCoreSet maps a stored policy set to the core set.
func ToCoreSet(set *policyv1.PolicySet) policy.Set {
	out := policy.Set{ID: set.GetId(), Version: set.GetVersion()}
	for _, c := range set.GetChecks() {
		out.Settings = append(out.Settings, policy.Setting{
			Name: c.GetName(), Params: c.GetParams(), Blocking: c.GetBlocking(),
		})
	}
	return out
}

// toInt32 converts n to int32. A value out of range clamps to the limit.
func toInt32(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
