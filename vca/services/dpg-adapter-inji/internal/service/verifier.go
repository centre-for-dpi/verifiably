// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// requestKey returns the store key of the claim names of one
// transaction.
func requestKey(state string) string {
	return "request/" + strings.ReplaceAll(inji.TransactionIDOf(state), "/", "_")
}

// CreateRequest starts an OID4VP transaction on Inji Verify.
//
// Release 0.16.0 reads a Presentation Exchange definition. A DCQL query
// alone is a bad request for this adapter.
func (s *Service) CreateRequest(
	ctx context.Context, req *connect.Request[backendv1.CreateRequestRequest],
) (*connect.Response[backendv1.CreateRequestResponse], error) {
	if s.verify == nil {
		return nil, unimplemented("this adapter has no Inji Verify URL, so it serves no verifier role")
	}
	definition := strings.TrimSpace(req.Msg.GetPresentationDefinition())
	if definition == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"set presentation_definition, because Inji Verify 0.16.0 reads a Presentation Exchange definition only"))
	}
	nonce := req.Msg.GetNonce()
	if nonce == "" {
		nonce = s.newID()
	}
	transaction, err := s.verify.CreateRequest(ctx, definition, nonce)
	if err != nil {
		return nil, failed("create the presentation request", err)
	}
	// The claim names of the request drive the check of the answer.
	if names := inji.RequestedClaims(definition); len(names) > 0 {
		raw := []byte(strings.Join(names, "\n"))
		if perr := s.store.Put(ctx, requestKey(transaction.State), raw); perr != nil {
			return nil, connect.NewError(connect.CodeInternal, perr)
		}
	}
	out := &backendv1.CreateRequestResponse{
		RequestUri: transaction.RequestURI,
		State:      transaction.State,
	}
	if transaction.ExpiresAt > 0 {
		out.ExpiresAt = timestamp(time.Unix(transaction.ExpiresAt, 0).UTC())
	}
	return connect.NewResponse(out), nil
}

// GetResult reads the state of one OID4VP transaction.
//
// Inji Verify can report success for a presentation that answers with
// the wrong credential. The adapter therefore checks that a presented
// credential carries at least one of the claim names of the request. It
// lowers the verdict when nothing matches.
func (s *Service) GetResult(
	ctx context.Context, req *connect.Request[backendv1.GetResultRequest],
) (*connect.Response[backendv1.GetResultResponse], error) {
	if s.verify == nil {
		return nil, unimplemented("this adapter has no Inji Verify URL, so it serves no verifier role")
	}
	state := strings.TrimSpace(req.Msg.GetState())
	if state == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a state"))
	}
	result, err := s.verify.Result(ctx, state)
	if err != nil {
		return nil, failed("read the presentation result", err)
	}
	out := &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}
	if !result.Answered() {
		return connect.NewResponse(out), nil
	}
	for _, r := range result.VCResults {
		out.Presented = append(out.Presented, &commonv1.Credential{
			Format:  commonv1.Format_FORMAT_UNSPECIFIED,
			Payload: presentedPayload(r),
		})
		out.DpgChecks = append(out.DpgChecks, &backendv1.GetResultResponse_DpgCheck{
			Name:   "inji-verification-status",
			Passed: strings.EqualFold(r.VerificationStatus, "SUCCESS"),
			Reason: reasonOf(r.VerificationStatus),
		})
	}
	accepted := result.Succeeded()
	if accepted {
		names := s.requestedClaims(ctx, state)
		if !inji.MatchesRequestedClaims(result.VCResults, names) {
			accepted = false
			out.DpgChecks = append(out.DpgChecks, &backendv1.GetResultResponse_DpgCheck{
				Name:   "requested-claims",
				Passed: false,
				Reason: "no presented credential carries a claim the request named",
			})
		}
	}
	out.State = backendv1.GetResultResponse_STATE_REJECTED
	if accepted {
		out.State = backendv1.GetResultResponse_STATE_ACCEPTED
	}
	out.ReceivedAt = timestamp(s.now().UTC())
	return connect.NewResponse(out), nil
}

// requestedClaims returns the stored claim names of one transaction.
func (s *Service) requestedClaims(ctx context.Context, state string) []string {
	raw, err := s.store.Get(ctx, requestKey(state))
	if errors.Is(err, store.ErrNotFound) || err != nil {
		return nil
	}
	return strings.Split(string(raw), "\n")
}

// presentedPayload returns the credential bytes of one result. A JSON
// string arrives as a compact token, which the adapter unwraps.
func presentedPayload(r inji.VCResult) []byte {
	raw := []byte(r.VC)
	if len(raw) > 1 && raw[0] == '"' {
		if compact, ok := unquote(raw); ok {
			return compact
		}
	}
	return raw
}

// unquote reads a JSON string value.
func unquote(raw []byte) ([]byte, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	return []byte(s), true
}

// reasonOf returns the failure text of a verification status.
func reasonOf(status string) string {
	if strings.EqualFold(status, "SUCCESS") {
		return ""
	}
	return status
}
