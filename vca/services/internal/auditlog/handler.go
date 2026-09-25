// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// ErrNoAuthorizer reports a handler without an authorizer. Such a
// handler answers no call.
var ErrNoAuthorizer = errors.New("auditlog: the service accepts no caller")

// Handler serves one log as vca.audit.v1.AuditService (ADR-039
// decision 1). Only the admin opens it: the caller passes Authorize,
// which each service builds from the admin session key set and the
// admin service token. A session of the issuer, the holder, or the
// verifier never opens it.
type Handler struct {
	auditv1connect.UnimplementedAuditServiceHandler
	// Log is the store the handler reads.
	Log *Log
	// Service names the service that writes the log, for example
	// issuer-auth. Every event carries it.
	Service string
	// Pair names the pair of the service when it knows it. Empty lets
	// the admin fill the pair from the peer it asked.
	Pair string
	// Authorize checks the headers of each call. Nil refuses every call.
	Authorize func(ctx context.Context, h http.Header) error
}

// NewHandler returns the Connect path and handler of h.
func NewHandler(h Handler) (string, http.Handler) {
	return auditv1connect.NewAuditServiceHandler(h)
}

// Query implements AuditServiceHandler.
func (h Handler) Query(ctx context.Context, req *connect.Request[auditv1.QueryRequest]) (*connect.Response[auditv1.QueryResponse], error) {
	if err := h.authorize(ctx, req.Header()); err != nil {
		return nil, err
	}
	page, err := h.Log.Query(ctx, FilterOf(req.Msg))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	res := &auditv1.QueryResponse{Page: &commonv1.PageResult{
		NextPageToken: page.NextPageToken, TotalSize: int64(page.TotalSize),
	}}
	for _, rec := range page.Records {
		res.Events = append(res.Events, ToProto(rec, h.Service, h.Pair))
	}
	return connect.NewResponse(res), nil
}

// SetRetention implements AuditServiceHandler.
func (h Handler) SetRetention(ctx context.Context, req *connect.Request[auditv1.SetRetentionRequest]) (*connect.Response[auditv1.SetRetentionResponse], error) {
	if err := h.authorize(ctx, req.Header()); err != nil {
		return nil, err
	}
	removed, err := h.Log.SetRetention(ctx, int(req.Msg.GetDays()))
	switch {
	case errors.Is(err, ErrRetention):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&auditv1.SetRetentionResponse{Days: req.Msg.GetDays(), Removed: int64(removed)}), nil
}

// authorize runs the authorizer and maps a refusal to a Connect error.
func (h Handler) authorize(ctx context.Context, header http.Header) error {
	if h.Authorize == nil {
		return connect.NewError(connect.CodeUnauthenticated, ErrNoAuthorizer)
	}
	err := h.Authorize(ctx, header)
	if err == nil {
		return nil
	}
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return cerr
	}
	return connect.NewError(connect.CodeUnauthenticated, err)
}

// FilterOf turns a query request into a filter.
func FilterOf(req *auditv1.QueryRequest) Filter {
	f := Filter{
		Actor:     req.GetActor(),
		Action:    req.GetAction(),
		Outcome:   OutcomeName(req.GetOutcome()),
		PageSize:  int(req.GetPage().GetPageSize()),
		PageToken: req.GetPage().GetPageToken(),
	}
	if req.GetFrom() != nil {
		f.From = req.GetFrom().AsTime()
	}
	if req.GetTo() != nil {
		f.To = req.GetTo().AsTime()
	}
	return f
}

// OutcomeName returns the filter value of an outcome. An unspecified
// outcome gives an empty string, which filters nothing.
func OutcomeName(o auditv1.Outcome) string {
	switch o {
	case auditv1.Outcome_OUTCOME_SUCCESS:
		return OutcomeSuccess
	case auditv1.Outcome_OUTCOME_FAILURE:
		return OutcomeFailure
	default:
		return ""
	}
}

// OutcomeOf returns the proto outcome of a filter value. Any other
// value gives OUTCOME_UNSPECIFIED.
func OutcomeOf(name string) auditv1.Outcome {
	switch name {
	case OutcomeSuccess:
		return auditv1.Outcome_OUTCOME_SUCCESS
	case OutcomeFailure:
		return auditv1.Outcome_OUTCOME_FAILURE
	default:
		return auditv1.Outcome_OUTCOME_UNSPECIFIED
	}
}

// ToProto returns the event of one record with its source.
func ToProto(rec Record, service, pair string) *auditv1.AuditEvent {
	return &auditv1.AuditEvent{
		Id:            rec.ID,
		Time:          timestamppb.New(rec.At),
		Actor:         rec.Actor,
		Action:        rec.Action,
		Target:        rec.Target,
		Outcome:       OutcomeOf(rec.Outcome()),
		Detail:        rec.Detail,
		RequestId:     rec.RequestID,
		SourceService: service,
		Pair:          pair,
	}
}
