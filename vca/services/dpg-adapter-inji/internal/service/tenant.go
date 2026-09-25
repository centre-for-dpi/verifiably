// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// tenantMessage says why the tenant service answers Unimplemented. Inji has no multi tenancy.
// The capability answer lists no FEATURE_MULTI_TENANCY, so the admin
// pages offer no tenancy on this stack (ADR-037 decision 3).
const tenantMessage = "Inji keeps no tenants; one deployment serves one organisation"

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
