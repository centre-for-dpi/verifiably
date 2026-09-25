// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// RegisterCredentialConfiguration makes a schema issuable on Inji
// Certify through its credential configuration API (ADR-045 decision 1).
// It creates the entry, or replaces it when Certify holds the id. Certify
// then lists the entry in its issuer metadata.
func (s *Service) RegisterCredentialConfiguration(
	ctx context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest],
) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it registers no configuration")
	}
	cfg := req.Msg.GetConfiguration()
	if cfg == nil || strings.TrimSpace(cfg.GetId()) == "" || strings.TrimSpace(cfg.GetType()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a configuration with an id and a type"))
	}
	format := wireFormat(cfg.GetFormat())
	dto, err := inji.BuildConfiguration(inji.ConfigInput{
		ID: cfg.GetId(), Format: format, Type: cfg.GetType(), JSONSchema: cfg.GetJsonSchema(),
		Display: cfg.GetDisplay(), SDClaims: cfg.GetSdClaims(), Contexts: cfg.GetContexts(),
	}, s.profiles)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	var out inji.ConfigResponse
	_, gerr := s.certify.GetConfiguration(ctx, cfg.GetId())
	switch {
	case errors.Is(gerr, inji.ErrConfigNotFound):
		out, err = s.certify.CreateConfiguration(ctx, dto)
	case gerr != nil:
		return nil, configError("read the credential configuration", gerr)
	default:
		out, err = s.certify.UpdateConfiguration(ctx, cfg.GetId(), dto)
	}
	if err != nil {
		return nil, configError("write the credential configuration", err)
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: out.ID}), nil
}

// configError maps a refusal of the configuration API onto a Connect
// error that keeps the Certify code.
func configError(action string, err error) *connect.Error {
	var ae *inji.APIError
	if !errors.As(err, &ae) {
		return failed(action, err)
	}
	code := connect.CodeFailedPrecondition
	switch {
	case strings.HasSuffix(ae.Code, "_config_exists"):
		code = connect.CodeAlreadyExists
	case ae.Code == "unsupported_format", strings.HasSuffix(ae.Code, "_mandatory_fields_missing"),
		strings.HasPrefix(ae.Code, "invalid_"):
		code = connect.CodeInvalidArgument
	case errors.Is(err, inji.ErrConfigNotFound):
		code = connect.CodeNotFound
	}
	return connect.NewError(code, fmt.Errorf("%s: %w", action, err))
}

// wireFormat maps a contract format onto the Inji wire name. A format
// Certify does not register gives its contract name, which the builder
// then refuses with a reason.
func wireFormat(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_LDP_VC:
		return "ldp_vc"
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt"
	default:
		return f.String()
	}
}
