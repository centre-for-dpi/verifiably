// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// CreateRequest starts an OID4VP transaction with a DCQL query.
//
// CREDEBL reads DCQL. A Presentation Exchange definition alone is a bad
// request for this adapter.
func (s *Service) CreateRequest(
	ctx context.Context, req *connect.Request[backendv1.CreateRequestRequest],
) (*connect.Response[backendv1.CreateRequestResponse], error) {
	raw := strings.TrimSpace(req.Msg.GetDcql())
	if raw == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"CREDEBL reads a DCQL query; set dcql"))
	}
	query, err := credebl.ParseDcql(raw)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	verifierID, verr := s.ensureVerifier(ctx)
	if verr != nil {
		return nil, verr
	}
	presentation, perr := s.client.CreatePresentation(ctx, verifierID, query)
	if perr != nil {
		return nil, failed("create the presentation request", perr)
	}
	return connect.NewResponse(&backendv1.CreateRequestResponse{
		RequestUri: presentation.RequestURI,
		State:      presentation.State,
	}), nil
}

// ensureVerifier returns the identifier of the OID4VP verifier. It
// remembers the identifier, so a later call needs no extra round trip.
func (s *Service) ensureVerifier(ctx context.Context) (string, error) {
	if s.verifierID != "" {
		return s.verifierID, nil
	}
	if raw, err := s.store.Get(ctx, verifierKey); err == nil && len(raw) > 0 {
		return string(raw), nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", connect.NewError(connect.CodeInternal, err)
	}
	logo := ""
	if s.publicURL != "" {
		logo = s.publicURL + "/static/logo.png"
	}
	id, err := s.client.EnsureVerifier(ctx, s.verifierName, logo)
	if err != nil {
		return "", failed("provision the verifier", err)
	}
	if err := s.store.Put(ctx, verifierKey, []byte(id)); err != nil {
		return "", connect.NewError(connect.CodeInternal, err)
	}
	return id, nil
}

// GetResult reads the state of one OID4VP transaction.
func (s *Service) GetResult(
	ctx context.Context, req *connect.Request[backendv1.GetResultRequest],
) (*connect.Response[backendv1.GetResultResponse], error) {
	state := strings.TrimSpace(req.Msg.GetState())
	if state == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a state"))
	}
	session, err := s.client.Presentation(ctx, state)
	if err != nil {
		return nil, failed("read the verification session", err)
	}
	out := &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}
	switch session.State {
	case credebl.StateVerified:
		out.State = backendv1.GetResultResponse_STATE_ACCEPTED
		out.DpgChecks = []*backendv1.GetResultResponse_DpgCheck{
			{Name: "credebl-response-verified", Passed: true},
		}
	case credebl.StateError:
		out.State = backendv1.GetResultResponse_STATE_REJECTED
		out.DpgChecks = []*backendv1.GetResultResponse_DpgCheck{
			{Name: "credebl-response-verified", Passed: false, Reason: string(session.State)},
		}
	default:
		return connect.NewResponse(out), nil
	}
	for _, token := range session.Tokens {
		out.Presented = append(out.Presented, &commonv1.Credential{
			Format:  commonv1.Format_FORMAT_DC_SD_JWT,
			Payload: []byte(token),
		})
	}
	out.ReceivedAt = timestamp(s.now().UTC())
	return connect.NewResponse(out), nil
}
