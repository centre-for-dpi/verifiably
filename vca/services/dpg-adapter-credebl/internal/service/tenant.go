// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// tenantMessage says why the tenant service answers Unimplemented.
// The adapter acts for one configured organisation until it gains the
// organisation calls. The capability answer lists neither
// FEATURE_MULTI_TENANCY nor FEATURE_TENANT_CLIENT_CREDENTIALS, so the
// admin pages offer no tenancy and no stack credential on this stack
// (ADR-037 decision 3, ADR-038 decision 2).
const tenantMessage = "this adapter manages no CREDEBL organisation as a tenant yet; it acts for the one configured organisation"

// CreateTenant is not available. See tenantMessage.
func (s *Service) CreateTenant(
	context.Context, *connect.Request[backendv1.CreateTenantRequest],
) (*connect.Response[backendv1.CreateTenantResponse], error) {
	return nil, unimplemented(tenantMessage)
}

// GetTenant is not available. See tenantMessage.
func (s *Service) GetTenant(
	context.Context, *connect.Request[backendv1.GetTenantRequest],
) (*connect.Response[backendv1.GetTenantResponse], error) {
	return nil, unimplemented(tenantMessage)
}

// ListTenants is not available. See tenantMessage.
func (s *Service) ListTenants(
	context.Context, *connect.Request[backendv1.ListTenantsRequest],
) (*connect.Response[backendv1.ListTenantsResponse], error) {
	return nil, unimplemented(tenantMessage)
}

// DeleteTenant is not available. See tenantMessage.
func (s *Service) DeleteTenant(
	context.Context, *connect.Request[backendv1.DeleteTenantRequest],
) (*connect.Response[backendv1.DeleteTenantResponse], error) {
	return nil, unimplemented(tenantMessage)
}

// ListClientCredentials is not available. See tenantMessage.
func (s *Service) ListClientCredentials(
	context.Context, *connect.Request[backendv1.ListClientCredentialsRequest],
) (*connect.Response[backendv1.ListClientCredentialsResponse], error) {
	return nil, unimplemented(tenantMessage)
}

// CreateClientCredential is not available. See tenantMessage.
func (s *Service) CreateClientCredential(
	context.Context, *connect.Request[backendv1.CreateClientCredentialRequest],
) (*connect.Response[backendv1.CreateClientCredentialResponse], error) {
	return nil, unimplemented(tenantMessage)
}

// DeleteClientCredential is not available. See tenantMessage.
func (s *Service) DeleteClientCredential(
	context.Context, *connect.Request[backendv1.DeleteClientCredentialRequest],
) (*connect.Response[backendv1.DeleteClientCredentialResponse], error) {
	return nil, unimplemented(tenantMessage)
}
