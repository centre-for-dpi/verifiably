// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
)

// v2Prefix marks the state of a verifier 2 session, so GetResult reads
// the verifier that holds it.
const v2Prefix = "v2:"

// CreateRequest starts an OID4VP transaction.
//
// A DCQL query goes to the verifier-api2, which speaks OID4VP 1.0. A
// Presentation Exchange 2.0 definition goes to the verifier-api, which
// reads nothing else. The capability answer lists the protocol of each
// verifier this deployment runs.
func (s *Service) CreateRequest(
	ctx context.Context, req *connect.Request[backendv1.CreateRequestRequest],
) (*connect.Response[backendv1.CreateRequestResponse], error) {
	if !s.client.HasVerifier() && !s.client.HasVerifier2() {
		return nil, unimplemented("this adapter has no verifier URL, so it serves no verifier role")
	}
	if query := strings.TrimSpace(req.Msg.GetDcql()); query != "" && s.client.HasVerifier2() {
		return s.createSession2(ctx, req.Msg, query)
	}
	if !s.client.HasVerifier() {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"this deployment runs the walt.id verifier 2 only, which reads a DCQL query; set dcql"))
	}
	definition := strings.TrimSpace(req.Msg.GetPresentationDefinition())
	if definition == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"the walt.id verifier-api reads a Presentation Exchange definition only; set presentation_definition"))
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

// createSession2 starts a cross device session of the verifier-api2 with
// the DCQL query as the caller wrote it.
func (s *Service) createSession2(
	ctx context.Context, msg *backendv1.CreateRequestRequest, query string,
) (*connect.Response[backendv1.CreateRequestResponse], error) {
	if !json.Valid([]byte(query)) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the DCQL query is not JSON"))
	}
	setup := waltid.Session2Setup{
		FlowType: waltid.FlowCrossDevice,
		CoreFlow: waltid.CoreFlow{DcqlQuery: json.RawMessage(query)},
	}
	if policies := waltid.VCPolicies2(msg.GetDpgPolicies(), msg.GetWebhookUrl()); len(policies) > 0 {
		setup.CoreFlow.Policies = &waltid.Policies2{VCPolicies: policies}
	}
	created, err := s.client.CreateSession2(ctx, setup)
	if err != nil {
		return nil, failed("create the verifier 2 session", err)
	}
	return connect.NewResponse(&backendv1.CreateRequestResponse{
		RequestUri: created.RequestURL(),
		State:      v2Prefix + created.SessionID,
	}), nil
}

// GetResult reads the state of one OID4VP transaction.
func (s *Service) GetResult(
	ctx context.Context, req *connect.Request[backendv1.GetResultRequest],
) (*connect.Response[backendv1.GetResultResponse], error) {
	if !s.client.HasVerifier() && !s.client.HasVerifier2() {
		return nil, unimplemented("this adapter has no verifier URL, so it serves no verifier role")
	}
	state := strings.TrimSpace(req.Msg.GetState())
	if state == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a state"))
	}
	if id, ok := strings.CutPrefix(state, v2Prefix); ok {
		return s.result2(ctx, id)
	}
	if !s.client.HasVerifier() {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment runs no walt.id verifier-api, so it holds no such session"))
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

// result2 reads one verifier 2 session. A session that has not ended is
// pending.
func (s *Service) result2(ctx context.Context, id string) (*connect.Response[backendv1.GetResultResponse], error) {
	if !s.client.HasVerifier2() {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment runs no walt.id verifier-api2, so it holds no such session"))
	}
	session, err := s.client.SessionInfo2(ctx, id)
	if err != nil {
		return nil, failed("read the verifier 2 session", err)
	}
	out := &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}
	switch session.Status {
	case waltid.Status2Expired:
		out.State = backendv1.GetResultResponse_STATE_EXPIRED
		return connect.NewResponse(out), nil
	case waltid.Status2Successful:
		out.State = backendv1.GetResultResponse_STATE_ACCEPTED
	case waltid.Status2Failed:
		out.State = backendv1.GetResultResponse_STATE_REJECTED
	default:
		return connect.NewResponse(out), nil
	}
	out.DpgChecks = dpgChecks(session.Checks())
	ids, tokens := session.Credentials()
	for i, token := range tokens {
		out.Presented = append(out.Presented, &commonv1.Credential{
			Format:  contractFormat(session.FormatOf(ids[i])),
			Payload: []byte(token),
		})
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
