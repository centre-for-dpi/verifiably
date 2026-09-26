// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// SetPresentationRequirement is not available. This adapter lists no
// FEATURE_PRESENTATION_DURING_ISSUANCE.
func (s *Service) SetPresentationRequirement(
	context.Context, *connect.Request[backendv1.SetPresentationRequirementRequest],
) (*connect.Response[backendv1.SetPresentationRequirementResponse], error) {
	return nil, unimplemented("this DPG checks no presentation during issuance")
}

// GetPresentationRequirement is not available. This adapter lists no
// FEATURE_PRESENTATION_DURING_ISSUANCE.
func (s *Service) GetPresentationRequirement(
	context.Context, *connect.Request[backendv1.GetPresentationRequirementRequest],
) (*connect.Response[backendv1.GetPresentationRequirementResponse], error) {
	return nil, unimplemented("this DPG checks no presentation during issuance")
}

// GetHolderSignInSource is not available. This adapter lists no
// FEATURE_HOLDER_SIGN_IN_SOURCE.
func (s *Service) GetHolderSignInSource(
	context.Context, *connect.Request[backendv1.GetHolderSignInSourceRequest],
) (*connect.Response[backendv1.GetHolderSignInSourceResponse], error) {
	return nil, unimplemented("this DPG issues no credential after a holder sign in without an offer")
}

// SetHolderSignInSource is not available. This adapter lists no
// FEATURE_HOLDER_SIGN_IN_SOURCE.
func (s *Service) SetHolderSignInSource(
	context.Context, *connect.Request[backendv1.SetHolderSignInSourceRequest],
) (*connect.Response[backendv1.SetHolderSignInSourceResponse], error) {
	return nil, unimplemented("this DPG issues no credential after a holder sign in without an offer")
}

// ListConnections is not available. walt.id speaks OID4VCI and OID4VP,
// not DIDComm, so it keeps no connection.
func (s *Service) ListConnections(
	context.Context, *connect.Request[backendv1.ListConnectionsRequest],
) (*connect.Response[backendv1.ListConnectionsResponse], error) {
	return nil, unimplemented("this DPG speaks no DIDComm, so it keeps no connection")
}
