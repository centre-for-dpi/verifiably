// SPDX-License-Identifier: Apache-2.0

// Package check turns a pasted presentation into a VerificationResult
// with one card per credential (ADR-025 decisions 2 and 5). It calls the
// verifier policy service and stores nothing.
package check

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MaxDisplayFields caps the claims one card shows.
const MaxDisplayFields = 20

// Options configure the evaluator.
type Options struct {
	// Client calls the verifier policy service.
	Client policyv1connect.PolicyServiceClient
	// PolicySetID selects the policy set. Empty uses the default set.
	PolicySetID string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Evaluate checks one pasted presentation and builds a result. The
// caller decides whether to store it.
func Evaluate(ctx context.Context, opts Options, payload []byte) (*resultsv1.VerificationResult, error) {
	if opts.Client == nil {
		return nil, errors.New("check: no policy service is configured")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	raw := RawOf(payload, opts.Now())
	resp, err := opts.Client.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: raw,
		PolicySetId:  opts.PolicySetID,
	}))
	if err != nil {
		return nil, err
	}
	return Build(raw, resp.Msg), nil
}

// RawOf wraps pasted bytes in a RawPresentation. The carrier is a paste,
// so the format comes from the bytes.
func RawOf(payload []byte, at time.Time) *ingestv1.RawPresentation {
	format := vc.DetectFormat(payload)
	return &ingestv1.RawPresentation{
		Carrier:      ingestv1.Carrier_CARRIER_JSON,
		Format:       protoFormat(format),
		Payload:      payload,
		DetectedType: ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL,
		Credentials:  []*commonv1.Credential{{Format: protoFormat(format), Payload: payload}},
		ReceivedAt:   timestamppb.New(at),
	}
}

// protoFormat maps a core format to the proto format.
func protoFormat(f vc.Format) commonv1.Format {
	switch f {
	case vc.FormatSDJWT:
		return commonv1.Format_FORMAT_DC_SD_JWT
	case vc.FormatJWT:
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case vc.FormatJSONLD:
		return commonv1.Format_FORMAT_LDP_VC
	case vc.FormatMdoc:
		return commonv1.Format_FORMAT_MSO_MDOC
	case vc.FormatJSON, vc.FormatUnknown:
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// Build turns an evaluation into a result with one card per credential
// (ADR-025 decision 2).
func Build(raw *ingestv1.RawPresentation, resp *policyv1.EvaluateResponse) *resultsv1.VerificationResult {
	out := &resultsv1.VerificationResult{
		Verdict:          resp.GetVerdict(),
		ReceivedAt:       raw.GetReceivedAt(),
		EvaluatedAt:      resp.GetEvaluatedAt(),
		PolicySetId:      resp.GetPolicySetId(),
		PolicySetVersion: resp.GetPolicySetVersion(),
		Carrier:          "paste",
		RawRef:           raw.GetRef(),
	}
	for _, c := range resp.GetChecks() {
		if c.GetCredentialIndex() < 0 {
			out.Checks = append(out.Checks, c)
		}
	}
	for i, cred := range raw.GetCredentials() {
		out.Credentials = append(out.Credentials, Summary(i, cred, resp.GetChecks()))
	}
	return out
}

// Summary builds the card of one credential.
func Summary(index int, cred *commonv1.Credential, checks []*policyv1.CheckResult) *resultsv1.CredentialSummary {
	out := &resultsv1.CredentialSummary{Format: cred.GetFormat(), Trust: "unknown"}
	parsed, err := vc.Parse(cred.GetPayload())
	if err == nil {
		out.Type = parsed.PrimaryType()
		out.Title = parsed.PrimaryType()
		out.Issuer = parsed.Issuer
		out.DisplayFields = displayFields(parsed)
		out.Validity = validity(parsed)
		out.DecodedJson = decoded(parsed)
	}
	for _, c := range checks {
		if int(c.GetCredentialIndex()) != index {
			continue
		}
		out.Checks = append(out.Checks, c)
		if c.GetName() == policy.NameTrustChain {
			out.Trust = trustWord(c)
			if name := c.GetEvidence()["issuer_name"]; name != "" {
				out.IssuerName = name
			}
		}
	}
	return out
}

// trustWord maps the trust chain outcome to a plain word.
func trustWord(c *policyv1.CheckResult) string {
	switch c.GetOutcome() {
	case policyv1.Outcome_OUTCOME_PASS:
		return "trusted"
	case policyv1.Outcome_OUTCOME_FAIL:
		return "untrusted"
	case policyv1.Outcome_OUTCOME_ERROR:
		return "unavailable"
	case policyv1.Outcome_OUTCOME_SKIP, policyv1.Outcome_OUTCOME_UNSPECIFIED:
	}
	return "unknown"
}

// displayFields returns the claims the card shows, capped in number.
func displayFields(c vc.Credential) map[string]string {
	if len(c.Claims) == 0 {
		return nil
	}
	out := make(map[string]string, len(c.Claims))
	for name, value := range c.Claims {
		if len(out) >= MaxDisplayFields {
			break
		}
		out[name] = value
	}
	return out
}

// validity returns the validity window of a credential.
func validity(c vc.Credential) *commonv1.ValidityWindow {
	from, until := c.TemporalBounds()
	if from.IsZero() && until.IsZero() {
		return nil
	}
	out := &commonv1.ValidityWindow{}
	if !from.IsZero() {
		out.ValidFrom = timestamppb.New(from)
	}
	if !until.IsZero() {
		out.ValidUntil = timestamppb.New(until)
	}
	return out
}

// decoded returns the credential as indented JSON for the disclosure.
func decoded(c vc.Credential) string {
	raw, err := json.MarshalIndent(c.Raw, "", "  ")
	if err != nil {
		return ""
	}
	return string(raw)
}
