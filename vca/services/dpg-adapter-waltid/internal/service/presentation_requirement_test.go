// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

func TestSetPresentationRequirementIsUnimplemented(t *testing.T) {
	var s *Service
	_, err := s.SetPresentationRequirement(context.Background(),
		connect.NewRequest(&backendv1.SetPresentationRequirementRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("code = %v", connect.CodeOf(err))
	}
}
