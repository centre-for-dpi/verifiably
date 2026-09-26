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
