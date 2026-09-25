// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// identityMessage says why the identity RPCs answer Unimplemented. Inji
// Certify reads its issuer DID and its signing keys from its own
// configuration. The adapter does not drive them yet, so the capability
// answer lists no identity feature and the identity page offers no
// action on this stack (ADR-046 decision 1).
const identityMessage = "the adapter does not manage the issuer identity of Inji Certify; Certify reads it from its own configuration"

// GetIssuerIdentity is not available. See identityMessage.
func (s *Service) GetIssuerIdentity(
	context.Context, *connect.Request[backendv1.GetIssuerIdentityRequest],
) (*connect.Response[backendv1.GetIssuerIdentityResponse], error) {
	return nil, unimplemented(identityMessage)
}

// ProvisionIssuerIdentity is not available. See identityMessage.
func (s *Service) ProvisionIssuerIdentity(
	context.Context, *connect.Request[backendv1.ProvisionIssuerIdentityRequest],
) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	return nil, unimplemented(identityMessage)
}

// ImportIssuerIdentity is not available. See identityMessage.
func (s *Service) ImportIssuerIdentity(
	context.Context, *connect.Request[backendv1.ImportIssuerIdentityRequest],
) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	return nil, unimplemented(identityMessage)
}
