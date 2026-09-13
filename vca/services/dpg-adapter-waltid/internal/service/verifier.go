// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
)

// CreateRequest starts an OID4VP transaction.
//
// walt.id 0.18.2 answers a Presentation Exchange 2.0 request only, so
// the caller must send presentation_definition. A DCQL query alone is a
// bad request for this adapter.
func (s *Service) CreateRequest(
	ctx context.Context, req *connect.Request[backendv1.CreateRequestRequest],
) (*connect.Response[backendv1.CreateRequestResponse], error) {
	if !s.client.HasVerifier() {
		return nil, unimplemented("this adapter has no verifier URL, so it serves no verifier role")
	}
	definition := strings.TrimSpace(req.Msg.GetPresentationDefinition())
	if definition == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"walt.id 0.18.2 reads a Presentation Exchange definition only; set presentation_definition"))
	}
	entries, err := waltid.RequestCredentialsFromDefinition(definition)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	format := waltid.Format("")
	if len(entries) > 0 {
		if f, ok := entries[0]["format"].(string); ok {
			format = waltid.Format(f)
		}
	}
	body := waltid.VerifyRequest{
		RequestCredentials: entries,
		VPPolicies:         waltid.VPPolicies(),
		VCPolicies:         waltid.VCPolicies(req.Msg.GetDpgPolicies(), format),
	}
	body.VCPolicies = append(body.VCPolicies, waltid.WebhookPolicy(req.Msg.GetWebhookUrl())...)
	authorizeURL, verr := s.client.Verify(ctx, body)
	if verr != nil {
		return nil, failed("create the presentation request", verr)
	}
	return connect.NewResponse(&backendv1.CreateRequestResponse{
		RequestUri: authorizeURL,
		State:      waltid.StateFromAuthorizeURL(authorizeURL),
	}), nil
}

// GetResult reads the state of one OID4VP transaction.
func (s *Service) GetResult(
	ctx context.Context, req *connect.Request[backendv1.GetResultRequest],
) (*connect.Response[backendv1.GetResultResponse], error) {
	if !s.client.HasVerifier() {
		return nil, unimplemented("this adapter has no verifier URL, so it serves no verifier role")
	}
	state := strings.TrimSpace(req.Msg.GetState())
	if state == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a state"))
	}
	session, err := s.client.SessionResult(ctx, state)
	if err != nil {
		return nil, failed("read the verifier session", err)
	}
	tokens := waltid.PresentedCredentials(session.TokenResponse)
	out := &backendv1.GetResultResponse{
		State:     backendv1.GetResultResponse_STATE_PENDING,
		DpgChecks: dpgChecks(waltid.PolicyChecks(session.PolicyResults)),
	}
	if len(tokens) == 0 && session.VerificationResult == nil {
		return connect.NewResponse(out), nil
	}
	for _, token := range tokens {
		out.Presented = append(out.Presented, &commonv1.Credential{
			Format:  commonv1.Format_FORMAT_UNSPECIFIED,
			Payload: []byte(token),
		})
	}
	out.State = backendv1.GetResultResponse_STATE_REJECTED
	if session.VerificationResult != nil && *session.VerificationResult {
		out.State = backendv1.GetResultResponse_STATE_ACCEPTED
	}
	out.ReceivedAt = timestamp(s.now().UTC())
	return connect.NewResponse(out), nil
}

// dpgChecks maps the walt.id policy verdicts onto the contract message.
func dpgChecks(checks []waltid.Check) []*backendv1.GetResultResponse_DpgCheck {
	if len(checks) == 0 {
		return nil
	}
	out := make([]*backendv1.GetResultResponse_DpgCheck, 0, len(checks))
	for _, c := range checks {
		out = append(out, &backendv1.GetResultResponse_DpgCheck{
			Name: c.Name, Passed: c.Passed, Reason: c.Reason,
		})
	}
	return out
}

// ListCredentialTypes returns the credential configurations of walt.id.
func (s *Service) ListCredentialTypes(
	ctx context.Context, req *connect.Request[backendv1.ListCredentialTypesRequest],
) (*connect.Response[backendv1.ListCredentialTypesResponse], error) {
	if !s.client.HasIssuer() {
		return nil, unimplemented("this adapter has no issuer URL, so it has no credential catalogue")
	}
	meta, err := s.client.Metadata(ctx)
	if err != nil {
		return nil, failed("read the issuer metadata", err)
	}
	all := configurations(meta)
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	start := 0
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		if n, perr := parseToken(token); perr == nil {
			start = n
		}
	}
	page := &commonv1.PageResult{TotalSize: int64(len(all))}
	if start >= len(all) {
		return connect.NewResponse(&backendv1.ListCredentialTypesResponse{Page: page}), nil
	}
	end := start + size
	if end < len(all) {
		page.NextPageToken = formatToken(end)
	} else {
		end = len(all)
	}
	return connect.NewResponse(&backendv1.ListCredentialTypesResponse{
		Configurations: all[start:end],
		Page:           page,
	}), nil
}

// configurations maps the walt.id catalog onto the contract message. The
// entries come back in a stable order.
func configurations(meta waltid.IssuerMetadata) []*backendv1.CredentialConfiguration {
	ids := make([]string, 0, len(meta.CredentialConfigurationsSupported))
	for id := range meta.CredentialConfigurationsSupported {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*backendv1.CredentialConfiguration, 0, len(ids))
	for _, id := range ids {
		entry := meta.CredentialConfigurationsSupported[id]
		cfg := &backendv1.CredentialConfiguration{
			Id:     id,
			Format: contractFormat(entry.Format),
			Type:   entry.Vct,
		}
		if entry.CredentialDefinition != nil && len(entry.CredentialDefinition.Type) > 0 {
			types := entry.CredentialDefinition.Type
			cfg.Type = types[len(types)-1]
		}
		if len(entry.Display) > 0 {
			cfg.Display = string(entry.Display[0])
		}
		out = append(out, cfg)
	}
	return out
}
