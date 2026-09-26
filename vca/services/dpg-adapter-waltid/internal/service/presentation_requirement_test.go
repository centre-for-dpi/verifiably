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

func TestSignInAndRequirementReadsAreUnimplemented(t *testing.T) {
	var s *Service
	ctx := context.Background()
	_, err := s.GetPresentationRequirement(ctx, connect.NewRequest(&backendv1.GetPresentationRequirementRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("get requirement code = %v", connect.CodeOf(err))
	}
	_, err = s.GetHolderSignInSource(ctx, connect.NewRequest(&backendv1.GetHolderSignInSourceRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("get source code = %v", connect.CodeOf(err))
	}
	_, err = s.SetHolderSignInSource(ctx, connect.NewRequest(&backendv1.SetHolderSignInSourceRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("set source code = %v", connect.CodeOf(err))
	}
}

func TestListConnectionsIsUnimplemented(t *testing.T) {
	var s *Service
	_, err := s.ListConnections(context.Background(), connect.NewRequest(&backendv1.ListConnectionsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("code = %v", connect.CodeOf(err))
	}
}
