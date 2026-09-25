// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.combined.v1.CombinedService (ADR-026).
// It stores combined templates, merges the DCQL of the member templates
// into one query with credential sets, runs each credential through the
// policy service on its own, then runs the cross credential rules. The
// overall verdict is the conjunction (ADR-026 decision 3).
package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/combos"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/dcql"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/rules"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// RoleDelegation marks the delegation credential of a pair.
const RoleDelegation = "delegation"

// RoleSubject marks the subject credential of a pair.
const RoleSubject = "subject"

// Options configure the service.
type Options struct {
	// Templates stores the combined templates.
	Templates *combos.Store
	// Policy checks one credential. A nil client makes
	// EvaluateCombined report a failed precondition.
	Policy policyv1connect.PolicyServiceClient
	// Discovery reads the member presentation templates. A nil client
	// makes BuildDcql report a failed precondition.
	Discovery discoveryv1connect.DiscoveryServiceClient
	// Results stores the combined result. A nil client keeps the result
	// in the response only.
	Results resultsv1connect.ResultsServiceClient
	// DefaultPolicySet is the policy set a template without a set uses.
	DefaultPolicySet string
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the CombinedService handler.
type Service struct {
	combinedv1connect.UnimplementedCombinedServiceHandler
	opts Options
}

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Templates == nil {
		return nil, errors.New("service: a combined template store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	return &Service{opts: opts}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil && s.opts.Templates != nil }

// Create stores a combined template (ADR-026 decision 1).
func (s *Service) Create(ctx context.Context, req *connect.Request[combinedv1.CreateRequest]) (
	*connect.Response[combinedv1.CreateResponse], error) {
	in := req.Msg.GetTemplate()
	if in == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("service: the request carries no template"))
	}
	if err := checkTemplate(in); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	stored := &combinedv1.CombinedTemplate{
		Id:          in.GetId(),
		DisplayName: in.GetDisplayName(),
		Members:     in.GetMembers(),
		Rules:       in.GetRules(),
		PolicySetId: in.GetPolicySetId(),
		TenantId:    in.GetTenantId(),
		CreatedAt:   timestamppb.New(s.opts.Now()),
	}
	out, err := s.opts.Templates.Create(ctx, stored)
	if errors.Is(err, combos.ErrBadID) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&combinedv1.CreateResponse{Template: out}), nil
}

// checkTemplate rejects a template the service cannot evaluate.
func checkTemplate(t *combinedv1.CombinedTemplate) error {
	if len(t.GetMembers()) == 0 {
		return errors.New("service: a combined template needs at least one member")
	}
	for _, m := range t.GetMembers() {
		if m.GetTemplateId() == "" {
			return errors.New("service: every member needs a template id")
		}
	}
	for _, r := range t.GetRules() {
		if kindName(r.GetKind()) == "UNSPECIFIED" {
			return errors.New("service: every rule needs a kind")
		}
	}
	return nil
}

// Get returns one combined template.
func (s *Service) Get(ctx context.Context, req *connect.Request[combinedv1.GetRequest]) (
	*connect.Response[combinedv1.GetResponse], error) {
	t, err := s.template(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&combinedv1.GetResponse{Template: t}), nil
}

// template reads one template and maps the store errors.
func (s *Service) template(ctx context.Context, id string) (*combinedv1.CombinedTemplate, error) {
	t, err := s.opts.Templates.Get(ctx, id)
	switch {
	case errors.Is(err, combos.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, combos.ErrBadID):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return t, nil
}

// List returns combined templates in pages.
func (s *Service) List(ctx context.Context, req *connect.Request[combinedv1.ListRequest]) (
	*connect.Response[combinedv1.ListResponse], error) {
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
	all, err := s.opts.Templates.List(ctx, req.Msg.GetTenantId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &combinedv1.ListResponse{Page: &commonv1.PageResult{TotalSize: int64(len(all))}}
	if offset > len(all) {
		offset = len(all)
	}
	end := offset + size
	if end < len(all) {
		resp.Page.NextPageToken = strconv.Itoa(end)
	} else {
		end = len(all)
	}
	resp.Templates = all[offset:end]
	return connect.NewResponse(resp), nil
}

// Delete removes one combined template.
func (s *Service) Delete(ctx context.Context, req *connect.Request[combinedv1.DeleteRequest]) (
	*connect.Response[combinedv1.DeleteResponse], error) {
	err := s.opts.Templates.Delete(ctx, req.Msg.GetId())
	switch {
	case errors.Is(err, combos.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, combos.ErrBadID):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&combinedv1.DeleteResponse{}), nil
}

// BuildDcql merges the DCQL of the member templates into one query with
// credential_sets (ADR-026 decision 1).
func (s *Service) BuildDcql(ctx context.Context, req *connect.Request[combinedv1.BuildDcqlRequest]) (
	*connect.Response[combinedv1.BuildDcqlResponse], error) {
	query, err := s.query(ctx, req.Msg.GetTemplateId())
	if err != nil {
		return nil, err
	}
	raw, err := query.JSON()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&combinedv1.BuildDcqlResponse{Dcql: raw}), nil
}

// query builds the merged DCQL query of one combined template.
func (s *Service) query(ctx context.Context, id string) (dcql.Query, error) {
	t, err := s.template(ctx, id)
	if err != nil {
		return dcql.Query{}, err
	}
	if s.opts.Discovery == nil {
		return dcql.Query{}, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("service: no discovery service is configured"))
	}
	members := make([]dcql.Member, 0, len(t.GetMembers()))
	for _, m := range t.GetMembers() {
		resp, gerr := s.opts.Discovery.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{
			Id: m.GetTemplateId(), Version: m.GetTemplateVersion(),
		}))
		if gerr != nil {
			return dcql.Query{}, connect.NewError(connect.CodeFailedPrecondition,
				fmt.Errorf("service: member template %s: %w", m.GetTemplateId(), gerr))
		}
		members = append(members, dcql.Member{
			Group:   m.GetAlternativeGroup(),
			Queries: queriesOf(resp.Msg.GetTemplate()),
		})
	}
	query, berr := dcql.Build(members)
	if berr != nil {
		return dcql.Query{}, connect.NewError(connect.CodeFailedPrecondition, berr)
	}
	return query, nil
}

// queriesOf returns the DCQL credential queries of a presentation
// template. The structured view wins over the stored DCQL text, because
// it names the query ids the combination merges.
func queriesOf(t *discoveryv1.PresentationTemplate) []dcql.Credential {
	if len(t.GetQueries()) > 0 {
		out := make([]dcql.Credential, 0, len(t.GetQueries()))
		for i, q := range t.GetQueries() {
			credential := toDcqlCredential(q)
			if credential.ID == "" {
				credential.ID = t.GetId() + "-" + strconv.Itoa(i)
			}
			out = append(out, credential)
		}
		return out
	}
	if parsed, err := dcql.Parse(t.GetDcql()); err == nil {
		return parsed.Credentials
	}
	return nil
}

// EvaluateCombined runs the policy set per credential, then the cross
// rules (ADR-026 decisions 3 and 4).
func (s *Service) EvaluateCombined(ctx context.Context, req *connect.Request[combinedv1.EvaluateCombinedRequest]) (
	*connect.Response[combinedv1.EvaluateCombinedResponse], error) {
	msg := req.Msg
	if msg.GetPresentation() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("service: the request carries no presentation"))
	}
	if s.opts.Policy == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("service: no policy service is configured"))
	}
	t, err := s.template(ctx, msg.GetTemplateId())
	if err != nil {
		return nil, err
	}
	creds := msg.GetPresentation().GetCredentials()
	ids := s.queryIDs(ctx, msg, t, creds)
	at := s.opts.Now()
	if msg.GetAt() != nil {
		at = msg.GetAt().AsTime()
	}
	result := &resultsv1.VerificationResult{
		ReceivedAt:  msg.GetPresentation().GetReceivedAt(),
		EvaluatedAt: timestamppb.New(at),
		RawRef:      msg.GetPresentation().GetRef(),
		TemplateId:  t.GetId(),
		TenantId:    t.GetTenantId(),
		Carrier:     "oid4vp",
	}
	verdicts := map[string]policyv1.EvaluateResponse_Verdict{}
	order := make([]policyv1.EvaluateResponse_Verdict, 0, len(creds))
	ruleCreds := make([]rules.Credential, 0, len(creds))
	for i, cred := range creds {
		resp, eerr := s.evaluateOne(ctx, msg, t, cred, at)
		if eerr != nil {
			return nil, eerr
		}
		result.PolicySetId = resp.GetPolicySetId()
		result.PolicySetVersion = resp.GetPolicySetVersion()
		keepOldest(result, resp)
		parsed := parseOrEmpty(cred.GetPayload())
		role := roleOf(parsed)
		result.Credentials = append(result.Credentials, summary(ids[i], role, cred, resp))
		verdicts[ids[i]] = resp.GetVerdict()
		order = append(order, resp.GetVerdict())
		ruleCreds = append(ruleCreds, rules.Credential{QueryID: ids[i], VC: parsed})
	}
	crossResults := rules.Run(ctx, toRules(t), ruleCreds)
	result.CrossChecks = toCheckResults(crossResults)
	result.Verdict = worst(order, rules.Verdict(crossResults))
	stored, serr := s.store(ctx, result)
	if serr != nil {
		return nil, serr
	}
	return connect.NewResponse(&combinedv1.EvaluateCombinedResponse{
		Result: stored, CredentialVerdicts: verdicts, CrossChecks: result.GetCrossChecks(),
	}), nil
}

// evaluateOne sends one credential to the policy service on its own
// (ADR-026 decision 3).
func (s *Service) evaluateOne(ctx context.Context, msg *combinedv1.EvaluateCombinedRequest,
	t *combinedv1.CombinedTemplate, cred *commonv1.Credential, at time.Time) (
	*policyv1.EvaluateResponse, error) {
	set := t.GetPolicySetId()
	if set == "" {
		set = s.opts.DefaultPolicySet
	}
	single := &ingestv1.RawPresentation{
		Ref:          msg.GetPresentation().GetRef(),
		Carrier:      msg.GetPresentation().GetCarrier(),
		Format:       cred.GetFormat(),
		Nonce:        msg.GetPresentation().GetNonce(),
		ReceivedAt:   msg.GetPresentation().GetReceivedAt(),
		DetectedType: ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL,
		Credentials:  []*commonv1.Credential{cred},
	}
	resp, err := s.opts.Policy.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: single,
		PolicySetId:  set,
		Nonce:        msg.GetPresentation().GetNonce(),
		At:           timestamppb.New(at),
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("service: policy service: %w", err))
	}
	return resp.Msg, nil
}

// store writes the result through the results service. Without a client
// it returns the result unchanged (ADR-026 decision 4).
func (s *Service) store(ctx context.Context, result *resultsv1.VerificationResult) (
	*resultsv1.VerificationResult, error) {
	if s.opts.Results == nil {
		return result, nil
	}
	resp, err := s.opts.Results.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{Result: result}))
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("service: results service: %w", err))
	}
	return resp.Msg.GetResult(), nil
}

// queryIDs returns the DCQL query id of each credential, in
// presentation order. The request wins. The service then matches by
// credential type, and falls back to the position.
func (s *Service) queryIDs(ctx context.Context, msg *combinedv1.EvaluateCombinedRequest,
	t *combinedv1.CombinedTemplate, creds []*commonv1.Credential) []string {
	out := make([]string, len(creds))
	copy(out, msg.GetQueryIds())
	if complete(out) {
		return out
	}
	var query dcql.Query
	if _, err := s.opts.Templates.Get(ctx, t.GetId()); err == nil {
		if built, berr := s.query(ctx, t.GetId()); berr == nil {
			query = built
		}
	}
	taken := map[string]bool{}
	for _, id := range out {
		taken[id] = true
	}
	for i := range out {
		if out[i] != "" {
			continue
		}
		parsed := parseOrEmpty(creds[i].GetPayload())
		if id := matchQuery(query, parsed, taken); id != "" {
			out[i] = id
			taken[id] = true
			continue
		}
		out[i] = "credential-" + strconv.Itoa(i)
	}
	return out
}

// complete reports whether every credential already has a query id.
func complete(ids []string) bool {
	for _, id := range ids {
		if id == "" {
			return false
		}
	}
	return len(ids) > 0
}

// matchQuery returns the id of the first free query whose type matches
// the credential.
func matchQuery(query dcql.Query, parsed vc.Credential, taken map[string]bool) string {
	for _, q := range query.Credentials {
		if taken[q.ID] || q.Meta == nil {
			continue
		}
		for _, want := range q.Meta.VctValues {
			if typeMatches(parsed, want) {
				return q.ID
			}
		}
		for _, values := range q.Meta.TypeValues {
			for _, want := range values {
				if typeMatches(parsed, want) {
					return q.ID
				}
			}
		}
	}
	return ""
}

// typeMatches reports whether a credential carries the type.
func typeMatches(parsed vc.Credential, want string) bool {
	if want == "" || strings.EqualFold(want, "VerifiableCredential") {
		return false
	}
	for _, t := range parsed.Types {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// roleOf returns the role of a credential in a combined presentation.
// parseOrEmpty parses a credential payload. A payload that does not parse
// gives an empty credential. The caller then sees no claims.
func parseOrEmpty(payload []byte) vc.Credential {
	parsed, err := vc.Parse(payload)
	if err != nil {
		return vc.Credential{}
	}
	return parsed
}

func roleOf(parsed vc.Credential) string {
	if _, ok := delegation.ExtractCapability(parsed); ok {
		return RoleDelegation
	}
	if parsed.SubjectID != "" || len(parsed.Claims) > 0 {
		return RoleSubject
	}
	return ""
}

// keepOldest keeps the oldest cached material age of the evaluations of
// one presentation, and the stale mark of any (ADR-041 decision 3).
func keepOldest(result *resultsv1.VerificationResult, resp *policyv1.EvaluateResponse) {
	if age := resp.GetMaterialAge(); age != nil && age.AsDuration() > result.GetMaterialAge().AsDuration() {
		result.MaterialAge = age
	}
	result.MaterialStale = result.GetMaterialStale() || resp.GetMaterialStale()
}
