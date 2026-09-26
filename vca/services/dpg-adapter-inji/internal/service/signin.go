// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"slices"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
)

// SignIn is the store of the holder sign in sources. The holder
// authorization server of the adapter implements it (ADR-052 decision 3).
type SignIn interface {
	// SetSignInSource stores the source of one configuration.
	SetSignInSource(ctx context.Context, src authz.SignInSource) error
	// ClearSignInSource removes the source of one configuration.
	ClearSignInSource(ctx context.Context, configID string) error
	// SignInSourceOf returns the source of one configuration.
	SignInSourceOf(ctx context.Context, configID string) (authz.SignInSource, bool, error)
	// VouchedClaims returns the ID token claims a source may name.
	VouchedClaims() []string
	// LooksUp reports whether a claim without an offer can reach a
	// data source.
	LooksUp() bool
}

// UseSignIn hands the service the holder authorization server, which is
// built after the service because it calls the offers of the service.
func (s *Service) UseSignIn(signIn SignIn) { s.signIn = signIn }

// signInReady reports whether a holder can claim without an offer.
func (s *Service) signInReady() bool { return s.signIn != nil && s.signIn.LooksUp() }

// GetHolderSignInSource returns the source of the first configuration
// that has one, and the claims of the ID token a source may name.
func (s *Service) GetHolderSignInSource(
	ctx context.Context, req *connect.Request[backendv1.GetHolderSignInSourceRequest],
) (*connect.Response[backendv1.GetHolderSignInSourceResponse], error) {
	if s.signIn == nil {
		return nil, noSignIn()
	}
	out := &backendv1.GetHolderSignInSourceResponse{VouchedClaims: s.signIn.VouchedClaims()}
	for _, id := range req.Msg.GetConfigurationIds() {
		src, found, err := s.signIn.SignInSourceOf(ctx, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if found {
			out.Source = sourceToProto(src)
			break
		}
	}
	return connect.NewResponse(out), nil
}

// SetHolderSignInSource stores the source for every configuration of a
// schema, or removes it. The claim must be one the holder provider
// vouches for, so a holder cannot pick the value that finds the row of
// another person (ADR-056 decision 2). The server checks the claim again
// at each claim.
func (s *Service) SetHolderSignInSource(
	ctx context.Context, req *connect.Request[backendv1.SetHolderSignInSourceRequest],
) (*connect.Response[backendv1.SetHolderSignInSourceResponse], error) {
	if !s.signInReady() {
		return nil, noSignIn()
	}
	var ids []string
	for _, id := range req.Msg.GetConfigurationIds() {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name the credential configurations of the schema"))
	}
	if req.Msg.GetClear() {
		for _, id := range ids {
			if err := s.signIn.ClearSignInSource(ctx, id); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
		}
		return connect.NewResponse(&backendv1.SetHolderSignInSourceResponse{}), nil
	}
	in := req.Msg.GetSource()
	src := authz.SignInSource{
		SourceID: strings.TrimSpace(in.GetSourceId()), Field: strings.TrimSpace(in.GetField()),
		TokenClaim: strings.TrimSpace(in.GetTokenClaim()), SchemaID: strings.TrimSpace(in.GetSchemaId()), SchemaVersion: in.GetSchemaVersion(),
	}
	if src.SourceID == "" || src.Field == "" || src.TokenClaim == "" || src.SchemaID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a sign in source needs the data source, the field, the ID token claim, and the schema"))
	}
	if !slices.Contains(s.signIn.VouchedClaims(), src.TokenClaim) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"the holder provider does not vouch for the claim "+src.TokenClaim+"; name one of "+strings.Join(s.signIn.VouchedClaims(), ", ")))
	}
	for _, id := range ids {
		src.ConfigID = id
		if err := s.signIn.SetSignInSource(ctx, src); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return connect.NewResponse(&backendv1.SetHolderSignInSourceResponse{Source: sourceToProto(src)}), nil
}

func sourceToProto(src authz.SignInSource) *backendv1.HolderSignInSource {
	return &backendv1.HolderSignInSource{
		SourceId: src.SourceID, Field: src.Field, TokenClaim: src.TokenClaim, SchemaId: src.SchemaID, SchemaVersion: src.SchemaVersion,
	}
}

func noSignIn() error {
	return connect.NewError(connect.CodeFailedPrecondition, errors.New(
		"this Inji deployment has no holder authorization server with a data source; set VCA_INJI_AUTHZ_ISSUER and VCA_INJI_DATA_SOURCE_URL"))
}
