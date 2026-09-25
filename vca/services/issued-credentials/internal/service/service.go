// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.issued.v1.IssuedService
// (ADR-017 decisions 1 to 5). It reads the append only log, changes the
// status of a credential through the status service, and signs the head
// of the hash chain.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/export"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/head"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/retention"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
)

// Limits of the service.
const (
	// DefaultPageSize is the page size when the request gives none.
	DefaultPageSize = 50
	// StatusValueSet is the status list value of a revoked or suspended
	// credential.
	StatusValueSet = 1
	// StatusValueClear is the status list value of an active credential.
	StatusValueClear = 0
)

// Options configure the service.
type Options struct {
	// Store is the append only log. It is required.
	Store *store.Store
	// Status is the status list client. Revoke and Reinstate call it
	// (ADR-017 decision 3). Nil rejects every status change.
	Status statusv1connect.StatusServiceClient
	// Head signs the chain head (ADR-017 decision 4). Nil rejects
	// GetChainHead.
	Head *head.Signer
	// Retention holds the per schema retention rules
	// (ADR-017 decision 5).
	Retention retention.Policy
	// Salt keys the one way subject reference (ADR-017 decision 2).
	Salt string
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// ChunkSize is the size of one export stream chunk. Zero means
	// export.ChunkSize.
	ChunkSize int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Audit keeps one event for each revoke, suspend, reinstate, and
	// export (ADR-039 decision 1). Nil keeps the events in memory.
	Audit *auditlog.Log
	// Stack is the DPG adapter of the pair. A revoke goes through it when
	// the adapter lists FEATURE_REVOCATION (ADR-034 decision 5). Nil keeps every
	// change on the status services of VCA.
	Stack Stack
}

// Stack is the part of the DPG adapter of the pair that the service
// calls.
type Stack interface {
	// Has reports whether the adapter lists a feature now.
	Has(ctx context.Context, feature backendv1.Feature) bool
	// Revoke revokes the credential at a status entry in the stack.
	Revoke(ctx context.Context, binding *backendv1.StatusListBinding, reason string) error
}

// Name is the service name that every audit event carries.
const Name = "issued-credentials"

// The audit actions of the service.
const (
	ActionRevoke    = "issued.Revoke"
	ActionSuspend   = "issued.Suspend"
	ActionReinstate = "issued.Reinstate"
	ActionExport    = "issued.Export"
)

// Service is the IssuedService handler.
type Service struct {
	issuedv1connect.UnimplementedIssuedServiceHandler
	opts Options
}

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("service: store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = export.ChunkSize
	}
	if opts.Audit == nil {
		// A memory store with a clock cannot fail to open.
		opts.Audit = anyval.Must(auditlog.New(sharedstore.Memory(), opts.Now))
	}
	return &Service{opts: opts}, nil
}

// Audit returns the audit store of the service.
func (s *Service) Audit() *auditlog.Log { return s.opts.Audit }

// audit records one status change. The detail names the new status,
// and the stack when the stack made the change. It never names the
// reason, which is free text of the operator.
func (s *Service) audit(ctx context.Context, h http.Header, action, id string, status issuedv1.Status, stack bool, err error) {
	detail := ""
	if err == nil {
		key := "audit.issued.status"
		if stack {
			key = "audit.issued.stack"
		}
		detail = msg.T(key, string(StatusOf(status)))
	}
	s.opts.Audit.Record(ctx, h, action, id, detail, err)
}

// History returns the audit events of one record, oldest first: each
// revoke, suspend, and reinstate with its actor and outcome.
func (s *Service) History(ctx context.Context, id string) ([]auditlog.Record, error) {
	if _, err := s.get(id); err != nil {
		return nil, err
	}
	page, err := s.opts.Audit.Query(ctx, auditlog.Filter{Target: id, PageSize: auditlog.MaxPageSize})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := make([]auditlog.Record, 0, len(page.Records))
	for i := len(page.Records) - 1; i >= 0; i-- {
		out = append(out, page.Records[i])
	}
	return out, nil
}

// SchemaIDs returns the schema id of every record, sorted and once
// each. The schema filter of the pages offers them.
func (s *Service) SchemaIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range s.opts.Store.All() {
		if !seen[r.SchemaID] {
			seen[r.SchemaID] = true
			out = append(out, r.SchemaID)
		}
	}
	sort.Strings(out)
	return out
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return true }

// SubjectRef returns the salted, one way reference of subject
// (ADR-017 decision 2). The issuance path calls it before it appends.
func (s *Service) SubjectRef(subject string) string {
	return record.SubjectRef(s.opts.Salt, subject)
}

// AppendRecord writes one issuance to the log. The Append RPC and the
// in process issuance path both call it. It fills the retention time
// from the per schema rules (ADR-017 decision 5).
func (s *Service) AppendRecord(r record.Record) (record.Record, error) {
	if r.IssuedAt.IsZero() {
		r.IssuedAt = s.opts.Now()
	}
	if r.RetainUntil.IsZero() {
		r.RetainUntil = s.opts.Retention.RetainUntil(r.SchemaID, r.IssuedAt)
	}
	return s.opts.Store.Append(r)
}

// PruneDue drops every record whose retention ended
// (ADR-017 decision 5). The scheduled job of the app calls it.
func (s *Service) PruneDue() (int, error) { return s.opts.Store.Prune(s.opts.Now()) }

// Append records one issuance (ADR-017 decision 1). The issuance
// service calls it after a credential reaches the holder.
func (s *Service) Append(_ context.Context, req *connect.Request[issuedv1.AppendRequest]) (*connect.Response[issuedv1.AppendResponse], error) {
	in := req.Msg.GetRecord()
	if in == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the request needs a record"))
	}
	r := FromProto(in)
	if strings.TrimSpace(r.ID) == "" {
		r.ID = record.NewID(s.opts.Now(), r.SchemaID, r.Hash)
	}
	stored, err := s.AppendRecord(r)
	if err != nil {
		return nil, appendError(err)
	}
	return connect.NewResponse(&issuedv1.AppendResponse{Id: stored.ID, RecordHash: stored.RecordHash}), nil
}

// Prune runs the retention rules (ADR-017 decision 5). A dry run counts
// the records that are due and drops none.
func (s *Service) Prune(_ context.Context, req *connect.Request[issuedv1.PruneRequest]) (*connect.Response[issuedv1.PruneResponse], error) {
	pruned, err := s.opts.Store.PruneWhere(s.opts.Now(), req.Msg.GetSchemaId(), req.Msg.GetDryRun())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&issuedv1.PruneResponse{
		Pruned:    int64(pruned),
		Remaining: int64(s.opts.Store.Len()),
	}), nil
}

// appendError maps a store error of an append to a Connect error.
func appendError(err error) error {
	if errors.Is(err, store.ErrDuplicate) {
		return connect.NewError(connect.CodeAlreadyExists, err)
	}
	if errors.Is(err, record.ErrInvalid) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

// List returns records in pages, newest first.
func (s *Service) List(_ context.Context, req *connect.Request[issuedv1.ListRequest]) (*connect.Response[issuedv1.ListResponse], error) {
	all := s.match(FilterOf(req.Msg.GetFilter()), "")
	start, end, next, err := page(req.Msg.GetPage(), len(all), s.opts.PageSizeMax)
	if err != nil {
		return nil, err
	}
	resp := &issuedv1.ListResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(all))}}
	for _, r := range all[start:end] {
		resp.Records = append(resp.Records, ToProto(r))
	}
	return connect.NewResponse(resp), nil
}

// Search returns the records whose searchable claims match a text.
func (s *Service) Search(_ context.Context, req *connect.Request[issuedv1.SearchRequest]) (*connect.Response[issuedv1.SearchResponse], error) {
	query := strings.TrimSpace(req.Msg.GetQuery())
	if len(query) > record.MaxQuery {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the query must hold at most %d characters", record.MaxQuery))
	}
	all := s.match(FilterOf(req.Msg.GetFilter()), query)
	start, end, next, err := page(req.Msg.GetPage(), len(all), s.opts.PageSizeMax)
	if err != nil {
		return nil, err
	}
	resp := &issuedv1.SearchResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(all))}}
	for _, r := range all[start:end] {
		resp.Records = append(resp.Records, ToProto(r))
	}
	return connect.NewResponse(resp), nil
}

// Get returns one record. An active record whose validity window ended
// reads as expired, as in a list.
func (s *Service) Get(_ context.Context, req *connect.Request[issuedv1.GetRequest]) (*connect.Response[issuedv1.GetResponse], error) {
	r, err := s.get(req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	if r.Status == record.Active && r.Expired(s.opts.Now()) {
		r.Status = record.Expired
	}
	return connect.NewResponse(&issuedv1.GetResponse{Record: ToProto(r)}), nil
}

// Revoke sets the status of one credential to revoked or suspended. It
// calls the status service first and records the reason
// (ADR-017 decision 3).
// The audit log records the change, also when it fails.
func (s *Service) Revoke(ctx context.Context, req *connect.Request[issuedv1.RevokeRequest]) (res *connect.Response[issuedv1.RevokeResponse], err error) {
	want := StatusOf(req.Msg.GetStatus())
	stack := want == record.Revoked && s.stackRevokes(ctx)
	defer func() {
		action := ActionRevoke
		if want == record.Suspended {
			action = ActionSuspend
		}
		var status issuedv1.Status
		if res != nil {
			status = res.Msg.GetRecord().GetStatus()
		}
		s.audit(ctx, req.Header(), action, req.Msg.GetId(), status, stack, err)
	}()
	if want != record.Revoked && want != record.Suspended {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the status must be STATUS_REVOKED or STATUS_SUSPENDED"))
	}
	r, err := s.change(ctx, req.Msg.GetId(), want, req.Msg.GetReason(), StatusValueSet, stack)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&issuedv1.RevokeResponse{Record: ToProto(r)}), nil
}

// Reinstate clears a suspension and records the reason. The audit log
// records the change, also when it fails.
func (s *Service) Reinstate(ctx context.Context, req *connect.Request[issuedv1.ReinstateRequest]) (res *connect.Response[issuedv1.ReinstateResponse], err error) {
	defer func() {
		var status issuedv1.Status
		if res != nil {
			status = res.Msg.GetRecord().GetStatus()
		}
		s.audit(ctx, req.Header(), ActionReinstate, req.Msg.GetId(), status, false, err)
	}()
	current, err := s.get(req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	if current.Status != record.Suspended {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("only a suspended credential can go back to active"))
	}
	r, err := s.change(ctx, req.Msg.GetId(), record.Active, req.Msg.GetReason(), StatusValueClear, false)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&issuedv1.ReinstateResponse{Record: ToProto(r)}), nil
}

// Sender takes one export chunk. A Connect server stream satisfies it.
type Sender interface {
	Send(*issuedv1.ExportResponse) error
}

// Export streams the records that match a filter. The audit log names
// the actor of the X-Vca-Actor header.
func (s *Service) Export(ctx context.Context, req *connect.Request[issuedv1.ExportRequest], stream *connect.ServerStream[issuedv1.ExportResponse]) error {
	if actor := auditlog.ActorFrom(req.Header()); actor != "" {
		ctx = auditlog.WithActor(ctx, actor)
	}
	return s.ExportTo(ctx, req.Msg, stream)
}

// ExportTo streams the export to out. Export and the pages call it. The
// audit log records the actor of ctx, the count, and the encoding.
func (s *Service) ExportTo(ctx context.Context, m *issuedv1.ExportRequest, out Sender) (err error) {
	var rs []record.Record
	encoding := "csv"
	defer func() {
		s.opts.Audit.Record(ctx, nil, ActionExport, "", msg.T("audit.issued.export", strconv.Itoa(len(rs)), encoding), err)
	}()
	query := strings.TrimSpace(m.GetQuery())
	if len(query) > record.MaxQuery {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the query must hold at most %d characters", record.MaxQuery))
	}
	rs = s.match(FilterOf(m.GetFilter()), query)
	write := export.CSV
	switch m.GetEncoding() {
	case issuedv1.ExportRequest_ENCODING_UNSPECIFIED, issuedv1.ExportRequest_ENCODING_CSV:
	case issuedv1.ExportRequest_ENCODING_JSON:
		write, encoding = export.JSON, "json"
	default:
		return connect.NewError(connect.CodeInvalidArgument, errors.New("the encoding must be CSV or JSON"))
	}
	data, err := export.Bytes(rs, write)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	chunks := export.Chunks(data, s.opts.ChunkSize)
	for i, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := out.Send(&issuedv1.ExportResponse{Chunk: chunk, Done: i == len(chunks)-1}); err != nil {
			return err
		}
	}
	return nil
}

// GetChainHead returns the latest signed head (ADR-017 decision 4).
func (s *Service) GetChainHead(_ context.Context, _ *connect.Request[issuedv1.GetChainHeadRequest]) (*connect.Response[issuedv1.GetChainHeadResponse], error) {
	h, err := s.signedHead()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&issuedv1.GetChainHeadResponse{Head: HeadToProto(h)}), nil
}

// VerifyChain walks the chain and reports the first broken link.
func (s *Service) VerifyChain(_ context.Context, req *connect.Request[issuedv1.VerifyChainRequest]) (*connect.Response[issuedv1.VerifyChainResponse], error) {
	checked, broken, err := s.opts.Store.Verify(req.Msg.GetFromRecordId())
	if err != nil {
		return nil, notFound(err)
	}
	resp := &issuedv1.VerifyChainResponse{Ok: broken == "", Checked: checked, BrokenRecordId: broken}
	if h, herr := s.signedHead(); herr == nil {
		resp.Head = HeadToProto(h)
	}
	return connect.NewResponse(resp), nil
}

// SignedHead returns the signed head. The HTTP endpoint calls it.
func (s *Service) SignedHead() (*issuedv1.ChainHead, error) {
	h, err := s.signedHead()
	if err != nil {
		return nil, err
	}
	return HeadToProto(h), nil
}

// signedHead signs the tip of the chain.
func (s *Service) signedHead() (headView, error) {
	if s.opts.Head == nil {
		return headView{}, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the service has no head signing key"))
	}
	tip, ok := s.opts.Store.Head()
	if !ok {
		return headView{}, connect.NewError(connect.CodeNotFound, errors.New("the log is empty"))
	}
	signed, err := s.opts.Head.Sign(head.Tip{RecordID: tip.RecordID, Hash: tip.Hash, Length: tip.Length}, s.opts.Now())
	if err != nil {
		return headView{}, connect.NewError(connect.CodeInternal, err)
	}
	return headView{
		RecordID:   signed.Tip.RecordID,
		RecordHash: signed.Tip.Hash,
		Length:     signed.Tip.Length,
		SignedAt:   signed.SignedAt,
		JWS:        signed.JWS,
		KeyID:      signed.KeyID,
	}, nil
}

// change writes one status change. It calls the status service first, so
// the log never claims a change the status list does not hold.
// With stack set, the DPG adapter makes the change in place of the
// status service.
func (s *Service) change(ctx context.Context, id string, want record.Status, reason string, value int32, stack bool) (record.Record, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return record.Record{}, connect.NewError(connect.CodeInvalidArgument, record.ErrNoReason)
	}
	current, err := s.get(id)
	if err != nil {
		return record.Record{}, err
	}
	if serr := record.NextStatus(current.Status, want); serr != nil {
		return record.Record{}, connect.NewError(connect.CodeFailedPrecondition, serr)
	}
	if current.Binding.IsZero() {
		return record.Record{}, connect.NewError(connect.CodeFailedPrecondition, record.ErrNoBinding)
	}
	if stack {
		return s.revokeInStack(ctx, id, current, reason)
	}
	if s.opts.Status == nil {
		return record.Record{}, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the service has no status list client"))
	}
	req := connect.NewRequest(&statusv1.SetStatusRequest{
		ListId: current.Binding.ListID,
		Index:  current.Binding.Index,
		Value:  value,
		Reason: reason,
	})
	if _, serr := s.opts.Status.SetStatus(ctx, req); serr != nil {
		return record.Record{}, unavailable("the status service", serr)
	}
	changed, err := s.opts.Store.SetStatus(id, want, reason, s.opts.Now())
	if err != nil {
		return record.Record{}, connect.NewError(connect.CodeInternal, err)
	}
	return changed, nil
}

// revokeInStack revokes the credential through the DPG adapter, which
// lists FEATURE_REVOCATION (ADR-034 decision 5). The log writes the event only
// after the stack took the change, as with the status service.
func (s *Service) revokeInStack(ctx context.Context, id string, current record.Record, reason string) (record.Record, error) {
	if err := s.opts.Stack.Revoke(ctx, bindingProto(current.Binding), reason); err != nil {
		return record.Record{}, unavailable("the DPG adapter", err)
	}
	changed, err := s.opts.Store.SetStatus(id, record.Revoked, reason, s.opts.Now())
	if err != nil {
		return record.Record{}, connect.NewError(connect.CodeInternal, err)
	}
	return changed, nil
}

// stackRevokes reports whether the DPG adapter of the pair revokes a
// credential itself: it lists FEATURE_REVOCATION (ADR-034 decision 5).
func (s *Service) stackRevokes(ctx context.Context) bool {
	return s.opts.Stack != nil && s.opts.Stack.Has(ctx, backendv1.Feature_FEATURE_REVOCATION)
}

// get returns one record with its status brought up to date.
func (s *Service) get(id string) (record.Record, error) {
	r, ok := s.opts.Store.Get(id)
	if !ok {
		return record.Record{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("no record with id %s", id))
	}
	return r, nil
}

// match returns every record that passes f and query, newest first. It
// reports an active record whose validity window ended as expired.
func (s *Service) match(f record.Filter, query string) []record.Record {
	now := s.opts.Now()
	var out []record.Record
	for _, r := range s.opts.Store.All() {
		if r.Status == record.Active && r.Expired(now) {
			r.Status = record.Expired
		}
		if !f.Match(r) || !r.Matches(query) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// notFound maps a store error to a Connect error.
func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

// unavailable returns a VCA-401 error for a service the call cannot reach.
func unavailable(name string, cause error) error {
	err := connect.NewError(connect.CodeUnavailable, fmt.Errorf("the service cannot reach %s: %w", name, cause))
	detail, derr := connect.NewErrorDetail(&commonv1.Error{
		Code:     "VCA-401",
		Message:  err.Message(),
		NextStep: "Wait one minute, then try again. If the problem stays, contact the operator.",
		Params:   map[string]string{"service": name},
	})
	if derr == nil {
		err.AddDetail(detail)
	}
	return err
}

// page returns the slice bounds of a page and the next token.
func page(p *commonv1.Pagination, total, max int) (start, end int, next string, err error) {
	size := int(p.GetPageSize())
	if size <= 0 || size > max {
		size = max
	}
	if tok := p.GetPageToken(); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 {
			return 0, 0, "", connect.NewError(connect.CodeInvalidArgument, errors.New("page_token is not valid"))
		}
		start = n
	}
	if start > total {
		start = total
	}
	end = start + size
	if end >= total {
		return start, total, "", nil
	}
	return start, end, strconv.Itoa(end), nil
}
