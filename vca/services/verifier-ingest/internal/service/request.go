// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/pex"
	cardsummary "github.com/centre-for-dpi/vc-adapters/core/summary"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// MaxRequestTTL caps the expiry a staff member picks for a request.
const MaxRequestTTL = time.Hour

// CarrierName is the carrier word of a stored result of a request.
const CarrierName = "oid4vp"

// Stack is one live verifier stack that can answer a request: the pair,
// the name its adapter reports, the internal URL of the adapter, and the
// protocols the adapter lists.
type Stack struct {
	// Pair is the pair name, for example verifier-inji.
	Pair string
	// Name is the display name of the stack.
	Name string
	// Adapter is the internal URL of the adapter.
	Adapter string
	// Protocols are the exchange protocols the adapter lists.
	Protocols []backendv1.Protocol
}

// StackVerifier is the verifier service of an adapter.
type StackVerifier interface {
	CreateRequest(context.Context, *connect.Request[backendv1.CreateRequestRequest]) (*connect.Response[backendv1.CreateRequestResponse], error)
	GetResult(context.Context, *connect.Request[backendv1.GetResultRequest]) (*connect.Response[backendv1.GetResultResponse], error)
}

// Evaluator runs the checks of a policy set. The policy service is one.
type Evaluator interface {
	Evaluate(context.Context, *connect.Request[policyv1.EvaluateRequest]) (*connect.Response[policyv1.EvaluateResponse], error)
}

// ResultStore keeps a verification result. The results service is one.
type ResultStore interface {
	Store(context.Context, *connect.Request[resultsv1.StoreRequest]) (*connect.Response[resultsv1.StoreResponse], error)
}

// VCAReads reports whether the VCA verifier can send a template: it
// needs a DCQL form.
func VCAReads(t *discoveryv1.PresentationTemplate) bool {
	return strings.TrimSpace(t.GetDcql()) != ""
}

// QueryFor returns what a stack gets for a template: the DCQL query when
// the adapter reads DCQL, else the PE definition when the adapter reads
// PE. A DCQL template goes to a PE stack only when its PE form loses
// nothing (ADR-042 decision 4). ok is false when the stack reads
// neither form of the template.
func QueryFor(t *discoveryv1.PresentationTemplate, protocols []backendv1.Protocol) (dcqlText, peText string, ok bool) {
	if slices.Contains(protocols, backendv1.Protocol_PROTOCOL_OID4VP_DCQL) && VCAReads(t) {
		return t.GetDcql(), "", true
	}
	if !slices.Contains(protocols, backendv1.Protocol_PROTOCOL_OID4VP_PEX) {
		return "", "", false
	}
	if t.GetKind() == discoveryv1.TemplateKind_TEMPLATE_KIND_PE {
		return "", t.GetPresentationDefinition(), t.GetPresentationDefinition() != ""
	}
	q, err := dcql.Parse([]byte(t.GetDcql()))
	if err != nil {
		return "", "", false
	}
	id := t.GetId()
	if id == "" {
		id = "presentation-request"
	}
	d, report, err := pex.FromDCQL(q, id, t.GetDisplayName(), t.GetPurpose())
	if err != nil || !report.Lossless() {
		return "", "", false
	}
	return "", string(pex.Marshal(d)), true
}

// template returns the template of a request: the one the discovery
// service holds, or a DCQL template of the query the request carries.
func (s *Service) template(ctx context.Context, msg *ingestv1.CreateOid4VpRequestRequest) (*discoveryv1.PresentationTemplate, error) {
	if raw := strings.TrimSpace(msg.GetDcql()); raw != "" {
		if err := checkQuery(raw); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return &discoveryv1.PresentationTemplate{Dcql: raw, Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL}, nil
	}
	id := strings.TrimSpace(msg.GetTemplateId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the request names no template and carries no query"))
	}
	if s.opts.Discovery == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("service: no discovery service is configured, so a template cannot be read"))
	}
	resp, err := s.opts.Discovery.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{
		Id: id, Version: msg.GetTemplateVersion(),
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: read the template %q: %w", id, err))
	}
	return resp.Msg.GetTemplate(), nil
}

// ttl returns how long a request works: the pick of the staff member,
// capped at MaxRequestTTL, or the default of the service.
func (s *Service) ttl(seconds int32) (time.Duration, error) {
	switch {
	case seconds < 0:
		return 0, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the expiry is negative"))
	case seconds == 0:
		return s.opts.RequestTTL, nil
	}
	return min(time.Duration(seconds)*time.Second, MaxRequestTTL), nil
}

// findStack returns the live stack of a pair.
func (s *Service) findStack(ctx context.Context, pair string) (Stack, bool) {
	if s.opts.Stacks == nil {
		return Stack{}, false
	}
	for _, st := range s.opts.Stacks(ctx) {
		if st.Pair == pair && st.Adapter != "" {
			return st, true
		}
	}
	return Stack{}, false
}

// createThroughStack asks the verifier of a stack for a request and
// keeps a transaction that polls it.
func (s *Service) createThroughStack(ctx context.Context, msg *ingestv1.CreateOid4VpRequestRequest, t *discoveryv1.PresentationTemplate, ttl time.Duration) (*connect.Response[ingestv1.CreateOid4VpRequestResponse], error) {
	stack, ok := s.findStack(ctx, msg.GetStack())
	if !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: the stack %q is not a live verifier", msg.GetStack()))
	}
	dcqlText, peText, ok := QueryFor(t, stack.Protocols)
	if !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: the stack %q reads no form of the query", msg.GetStack()))
	}
	id, idErr := txn.NewID()
	nonce, nonceErr := txn.NewID()
	if err := errors.Join(idErr, nonceErr); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp, err := s.opts.StackClient(stack.Adapter).CreateRequest(ctx, connect.NewRequest(&backendv1.CreateRequestRequest{
		Dcql: dcqlText, PresentationDefinition: peText, Nonce: nonce,
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("service: the stack %q did not create the request: %w", stack.Pair, err))
	}
	now := s.opts.Now()
	record := txn.Transaction{
		ID: id, Nonce: nonce, TemplateID: t.GetId(), TemplateVersion: t.GetVersion(), PolicySetID: t.GetPolicySetId(),
		State: txn.StatePending, CreatedAt: now, ExpiresAt: now.Add(ttl),
		Stack: stack.Pair, Adapter: stack.Adapter, StackState: resp.Msg.GetState(), RequestURI: resp.Msg.GetRequestUri(),
	}
	if at := resp.Msg.GetExpiresAt(); at != nil {
		record.ExpiresAt = at.AsTime()
	}
	if err := s.opts.Store.Put(ctx, record); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ingestv1.CreateOid4VpRequestResponse{
		TransactionId: id, RequestUri: record.RequestURI, QrPayload: record.RequestURI, Nonce: nonce,
		ExpiresAt: timestamppb.New(record.ExpiresAt),
	}), nil
}

// poll asks the stack of a pending request for the answer. A pending
// answer or a failed call leaves the record as it is. An answer with
// credentials is evaluated and stored like a direct post.
func (s *Service) poll(ctx context.Context, id string) (txn.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.opts.Store.Get(ctx, id)
	if err != nil || record.State != txn.StatePending || record.Expired(s.opts.Now()) {
		return record, err
	}
	resp, err := s.opts.StackClient(record.Adapter).GetResult(ctx, connect.NewRequest(&backendv1.GetResultRequest{State: record.StackState}))
	if err != nil {
		return record, nil
	}
	msg := resp.Msg
	now := s.opts.Now()
	switch msg.GetState() {
	case backendv1.GetResultResponse_STATE_EXPIRED:
		record.State = txn.StateExpired
	case backendv1.GetResultResponse_STATE_ACCEPTED, backendv1.GetResultResponse_STATE_REJECTED:
		for _, c := range msg.GetDpgChecks() {
			record.StackChecks = append(record.StackChecks, txn.StackCheck{Name: c.GetName(), Passed: c.GetPassed(), Reason: c.GetReason()})
		}
		record.AnsweredAt = now
		if at := msg.GetReceivedAt(); at != nil {
			record.AnsweredAt = at.AsTime()
		}
		if len(msg.GetPresented()) == 0 {
			record.State, record.Error = txn.StateRefused, "the stack rejected the answer"
			break
		}
		record.State = txn.StateReceived
		record.Presentation = presentationOf(msg.GetPresented(), record.ID, record.Nonce, record.AnsweredAt)
		s.finish(ctx, &record)
	default:
		return record, nil
	}
	if err := s.opts.Store.Put(ctx, record); err != nil {
		return record, connect.NewError(connect.CodeInternal, err)
	}
	return record, nil
}

// presentationOf stores the credentials a stack received.
func presentationOf(creds []*commonv1.Credential, ref, nonce string, at time.Time) *txn.Presentation {
	out := &txn.Presentation{
		Ref: ref, Carrier: string(ingest.CarrierOID4VPResponse), DetectedType: string(ingest.TypePresentation),
		Nonce: nonce, ReceivedAt: at, Format: formatWord(creds[0].GetFormat()), Payload: creds[0].GetPayload(),
	}
	for _, c := range creds {
		out.Credentials = append(out.Credentials, txn.Credential{Format: formatWord(c.GetFormat()), Payload: c.GetPayload()})
	}
	return out
}

// formatWord returns the format identifier of a proto format.
func formatWord(f commonv1.Format) string {
	for _, name := range []string{"vc+sd-jwt", "dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc"} {
		if ProtoFormat(name) == f {
			return name
		}
	}
	return ""
}

// finish evaluates the answer of a request with the policy set of the
// template and stores the result (ADR-042 decision 3). Without a policy
// service it does nothing. A failure keeps the answer and names the
// failure on the record.
func (s *Service) finish(ctx context.Context, record *txn.Transaction) {
	if s.opts.Policy == nil || record.Presentation == nil {
		return
	}
	raw := RecordToProto(record.Presentation, record.ID)
	resp, err := s.opts.Policy.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: raw, PolicySetId: record.PolicySetID, Nonce: record.Nonce, At: timestamppb.New(s.opts.Now()),
	}))
	if err != nil {
		record.Error = "the policy service did not evaluate the answer: " + err.Error()
		return
	}
	if s.opts.Results == nil {
		return
	}
	stored, err := s.opts.Results.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{Result: ResultOf(raw, resp.Msg, record)}))
	if err != nil {
		record.Error = "the results service did not store the result: " + err.Error()
		return
	}
	record.ResultID = stored.Msg.GetResult().GetId()
}

// ResultOf builds the verification result of an evaluated answer, with
// one card per credential.
func ResultOf(raw *ingestv1.RawPresentation, resp *policyv1.EvaluateResponse, record *txn.Transaction) *resultsv1.VerificationResult {
	out := &resultsv1.VerificationResult{
		Verdict: resp.GetVerdict(), PolicySetId: resp.GetPolicySetId(), PolicySetVersion: resp.GetPolicySetVersion(),
		EvaluatedAt: resp.GetEvaluatedAt(), ReceivedAt: raw.GetReceivedAt(), Carrier: CarrierName, RawRef: raw.GetRef(),
		TemplateId: record.TemplateID, TemplateVersion: record.TemplateVersion,
	}
	for _, c := range resp.GetChecks() {
		if c.GetCredentialIndex() < 0 {
			out.Checks = append(out.Checks, c)
		}
	}
	for i, cred := range raw.GetCredentials() {
		out.Credentials = append(out.Credentials, cardsummary.Build(cred, resp.GetChecks(), cardsummary.Options{Index: i}))
	}
	return out
}

// stackChecks returns the checks of a stack as proto messages.
func stackChecks(list []txn.StackCheck) []*backendv1.GetResultResponse_DpgCheck {
	out := make([]*backendv1.GetResultResponse_DpgCheck, 0, len(list))
	for _, c := range list {
		out = append(out, &backendv1.GetResultResponse_DpgCheck{Name: c.Name, Passed: c.Passed, Reason: c.Reason})
	}
	return out
}
