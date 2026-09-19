// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.policy.v1.PolicyService (ADR-024).
// It stores named policy sets, lists the checks it knows, and evaluates
// one presentation against one policy set. The checks themselves are
// the pure functions of core/policy. This package only wires the ports
// and maps the messages.
package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/sets"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// BuiltInSetID names the set the service uses when the deployment
// configures none.
const BuiltInSetID = "built-in"

// Options configure the service.
type Options struct {
	// Sets stores the policy sets.
	Sets *sets.Store
	// Ports carries the injected effects of the checks: the key
	// resolver, the status fetcher, the schema fetcher, and the trust
	// lookup. Evaluate copies it and fills the expectations.
	Ports policy.Context
	// DefaultSetID is the set that an Evaluate request without a set id
	// uses. Empty uses the built in set.
	DefaultSetID string
	// Audience is the client id of this verifier.
	Audience string
	// StatusFailMode is open or closed. The built in set uses it.
	StatusFailMode string
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the PolicyService handler.
type Service struct {
	policyv1connect.UnimplementedPolicyServiceHandler
	opts Options
}

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Sets == nil {
		return nil, errors.New("service: a policy set store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	if opts.StatusFailMode == "" {
		opts.StatusFailMode = policy.FailClosed
	}
	return &Service{opts: opts}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil && s.opts.Sets != nil }

// BuiltInSet is the set the service uses when the deployment configures
// none. The mandatory checks always run, so the set only adds the
// checks a verifier can turn off.
func (s *Service) BuiltInSet() policy.Set {
	return policy.Set{
		ID:      BuiltInSetID,
		Version: 1,
		Settings: []policy.Setting{
			{Name: policy.NameStatus, Blocking: true,
				Params: map[string]string{policy.ParamFailMode: s.opts.StatusFailMode}},
			{Name: policy.NameTrustChain, Blocking: true},
			{Name: policy.NameSchema, Blocking: true},
		},
	}
}

// Evaluate runs one policy set over one presentation
// (ADR-024 decisions 1, 2, and 6).
func (s *Service) Evaluate(ctx context.Context, req *connect.Request[policyv1.EvaluateRequest]) (
	*connect.Response[policyv1.EvaluateResponse], error) {
	msg := req.Msg
	if msg.GetPresentation() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the request carries no presentation"))
	}
	set, err := s.resolveSet(ctx, msg.GetPolicySetId(), msg.GetPolicySetVersion())
	if err != nil {
		return nil, err
	}
	at := s.opts.Now()
	if msg.GetAt() != nil {
		at = msg.GetAt().AsTime()
	}
	pc := s.opts.Ports
	pc.Now = at
	pc.Audience = msg.GetAudience()
	if pc.Audience == "" {
		pc.Audience = s.opts.Audience
	}
	pc.Nonce = msg.GetNonce()
	if pc.Nonce == "" {
		pc.Nonce = msg.GetPresentation().GetNonce()
	}
	report := policy.Evaluate(ctx, ToPresentation(msg.GetPresentation()), pc, set)
	return connect.NewResponse(&policyv1.EvaluateResponse{
		Verdict:          VerdictOf(report.Verdict),
		Checks:           ToProtoResults(report.Results),
		PolicySetId:      report.SetID,
		PolicySetVersion: report.Version,
		EvaluatedAt:      timestamppb.New(at),
	}), nil
}

// resolveSet returns the core set the evaluation runs.
func (s *Service) resolveSet(ctx context.Context, id string, version int32) (policy.Set, error) {
	if id == "" {
		id = s.opts.DefaultSetID
	}
	if id == "" || id == BuiltInSetID {
		return s.BuiltInSet(), nil
	}
	stored, err := s.opts.Sets.Get(ctx, id, version)
	if errors.Is(err, sets.ErrNotFound) {
		return policy.Set{}, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("service: no policy set %s", id))
	}
	if err != nil {
		return policy.Set{}, connect.NewError(connect.CodeInternal, err)
	}
	return ToCoreSet(stored), nil
}

// ListChecks returns the checks the service knows
// (ADR-024 decisions 1 and 2).
func (s *Service) ListChecks(_ context.Context, _ *connect.Request[policyv1.ListChecksRequest]) (
	*connect.Response[policyv1.ListChecksResponse], error) {
	resp := &policyv1.ListChecksResponse{}
	for _, c := range policy.Checks() {
		resp.Checks = append(resp.Checks, &policyv1.ListChecksResponse_CheckInfo{
			Name:        c.Name,
			Description: c.Description,
			Params:      c.Params,
			Mandatory:   c.Mandatory,
		})
	}
	return connect.NewResponse(resp), nil
}

// CreatePolicySet stores a set as version 1.
func (s *Service) CreatePolicySet(ctx context.Context, req *connect.Request[policyv1.CreatePolicySetRequest]) (
	*connect.Response[policyv1.CreatePolicySetResponse], error) {
	set, err := s.write(ctx, req.Msg.GetPolicySet(), s.opts.Sets.Create)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&policyv1.CreatePolicySetResponse{PolicySet: set}), nil
}

// UpdatePolicySet stores the next version of a set (ADR-024 decision 6).
func (s *Service) UpdatePolicySet(ctx context.Context, req *connect.Request[policyv1.UpdatePolicySetRequest]) (
	*connect.Response[policyv1.UpdatePolicySetResponse], error) {
	if req.Msg.GetPolicySet().GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the set id is required"))
	}
	set, err := s.write(ctx, req.Msg.GetPolicySet(), s.opts.Sets.Update)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&policyv1.UpdatePolicySetResponse{PolicySet: set}), nil
}

// write validates a set and stores it with put.
func (s *Service) write(ctx context.Context, in *policyv1.PolicySet,
	put func(context.Context, *policyv1.PolicySet) (*policyv1.PolicySet, error)) (*policyv1.PolicySet, error) {
	if in == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the request carries no policy set"))
	}
	if err := checkNames(in); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	stored := &policyv1.PolicySet{
		Id:          in.GetId(),
		DisplayName: in.GetDisplayName(),
		Checks:      in.GetChecks(),
		TenantId:    in.GetTenantId(),
		CreatedBy:   in.GetCreatedBy(),
		CreatedAt:   timestamppb.New(s.opts.Now()),
	}
	out, err := put(ctx, stored)
	switch {
	case errors.Is(err, sets.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, sets.ErrBadID):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return out, nil
}

// checkNames rejects a set that names a check the service does not know.
func checkNames(set *policyv1.PolicySet) error {
	for _, c := range set.GetChecks() {
		if _, ok := policy.Find(c.GetName()); !ok {
			return fmt.Errorf("service: the check %q is not known", c.GetName())
		}
	}
	return nil
}

// GetPolicySet returns one version.
func (s *Service) GetPolicySet(ctx context.Context, req *connect.Request[policyv1.GetPolicySetRequest]) (
	*connect.Response[policyv1.GetPolicySetResponse], error) {
	set, err := s.opts.Sets.Get(ctx, req.Msg.GetId(), req.Msg.GetVersion())
	switch {
	case errors.Is(err, sets.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, sets.ErrBadID):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&policyv1.GetPolicySetResponse{PolicySet: set}), nil
}

// ListPolicySets returns the latest version of each set in pages.
func (s *Service) ListPolicySets(ctx context.Context, req *connect.Request[policyv1.ListPolicySetsRequest]) (
	*connect.Response[policyv1.ListPolicySetsResponse], error) {
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	offset := 0
	if tok := req.Msg.GetPage().GetPageToken(); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("service: page token %q is not valid", tok))
		}
		offset = n
	}
	all, err := s.opts.Sets.List(ctx, req.Msg.GetTenantId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &policyv1.ListPolicySetsResponse{Page: &commonv1.PageResult{TotalSize: int64(len(all))}}
	if offset > len(all) {
		offset = len(all)
	}
	end := offset + size
	if end < len(all) {
		resp.Page.NextPageToken = strconv.Itoa(end)
	} else {
		end = len(all)
	}
	resp.PolicySets = all[offset:end]
	return connect.NewResponse(resp), nil
}

// DeletePolicySet removes every version of a set.
func (s *Service) DeletePolicySet(ctx context.Context, req *connect.Request[policyv1.DeletePolicySetRequest]) (
	*connect.Response[policyv1.DeletePolicySetResponse], error) {
	err := s.opts.Sets.Delete(ctx, req.Msg.GetId())
	switch {
	case errors.Is(err, sets.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, sets.ErrBadID):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&policyv1.DeletePolicySetResponse{}), nil
}
