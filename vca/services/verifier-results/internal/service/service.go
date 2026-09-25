// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.results.v1.ResultsService (ADR-025).
// It stores one VerificationResult per verification, answers queries and
// exports, and purges personal data when the retention window ends.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/export"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/query"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/results"
)

// DefaultPageSize is the page size when the request gives none.
const DefaultPageSize = 50

// ChunkBytes is the size of one export chunk.
const ChunkBytes = 32 << 10

// Options configure the service.
type Options struct {
	// Store holds the results.
	Store *results.Store
	// Retention is how long a result stays readable.
	Retention time.Duration
	// RawRetention is how long the raw presentation stays readable.
	RawRetention time.Duration
	// PageSizeMax caps the page size. Zero means DefaultPageSize.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Audit keeps one event for each stored result (ADR-039 decision
	// 1). Nil keeps the events in memory.
	Audit *auditlog.Log
}

// Name is the service name that every audit event carries.
const Name = "verifier-results"

// ActionStore is the audit action of a stored result.
const ActionStore = "results.Store"

// Service is the ResultsService handler.
type Service struct {
	resultsv1connect.UnimplementedResultsServiceHandler
	opts Options
}

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("service: a result store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = DefaultPageSize
	}
	if opts.Retention <= 0 {
		return nil, errors.New("service: the retention window must be positive")
	}
	if opts.RawRetention <= 0 || opts.RawRetention > opts.Retention {
		return nil, errors.New("service: the raw retention window must be positive and not longer than the retention window")
	}
	if opts.Audit == nil {
		// A memory store with a clock cannot fail to open.
		opts.Audit = anyval.Must(auditlog.New(store.Memory(), opts.Now))
	}
	return &Service{opts: opts}, nil
}

// Audit returns the audit store of the service.
func (s *Service) Audit() *auditlog.Log { return s.opts.Audit }

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil && s.opts.Store != nil }

// Store writes one result (ADR-025 decision 1). The audit log records
// the result id and the verdict, also when the store fails. It never
// records a claim of the presentation.
func (s *Service) Store(ctx context.Context, req *connect.Request[resultsv1.StoreRequest]) (
	res *connect.Response[resultsv1.StoreResponse], err error) {
	defer func() {
		target, detail := "", ""
		if res != nil {
			target = res.Msg.GetResult().GetId()
			detail = msg.T("audit.results.verdict", verdictName(res.Msg.GetResult().GetVerdict()))
		}
		s.opts.Audit.Record(ctx, req.Header(), ActionStore, target, detail, err)
	}()
	in := req.Msg.GetResult()
	if in == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the request carries no result"))
	}
	now := s.opts.Now()
	out := in
	out.Id = ""
	if out.GetEvaluatedAt() == nil {
		out.EvaluatedAt = timestamppb.New(now)
	}
	if out.GetReceivedAt() == nil {
		out.ReceivedAt = out.GetEvaluatedAt()
	}
	out.RetainUntil = timestamppb.New(out.GetEvaluatedAt().AsTime().Add(s.opts.Retention))
	stored, err := s.opts.Store.Put(ctx, out)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&resultsv1.StoreResponse{Result: stored}), nil
}

// verdictName returns the short name of a verdict, for example valid.
func verdictName(v policyv1.EvaluateResponse_Verdict) string {
	return strings.ToLower(strings.TrimPrefix(v.String(), "VERDICT_"))
}

// Get returns one result.
func (s *Service) Get(ctx context.Context, req *connect.Request[resultsv1.GetRequest]) (
	*connect.Response[resultsv1.GetResponse], error) {
	r, err := s.opts.Store.Get(ctx, req.Msg.GetId())
	switch {
	case errors.Is(err, results.ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, results.ErrBadID):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&resultsv1.GetResponse{Result: r}), nil
}

// Query returns the results that match a filter (ADR-025 decision 4).
func (s *Service) Query(ctx context.Context, req *connect.Request[resultsv1.QueryRequest]) (
	*connect.Response[resultsv1.QueryResponse], error) {
	matched, err := s.matching(ctx, req.Msg.GetFilter())
	if err != nil {
		return nil, err
	}
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	offset := 0
	if tok := req.Msg.GetPage().GetPageToken(); tok != "" {
		n, cerr := strconv.Atoi(tok)
		if cerr != nil || n < 0 {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("service: page token %q is not valid", tok))
		}
		offset = n
	}
	resp := &resultsv1.QueryResponse{Page: &commonv1.PageResult{TotalSize: int64(len(matched))}}
	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + size
	if end < len(matched) {
		resp.Page.NextPageToken = strconv.Itoa(end)
	} else {
		end = len(matched)
	}
	resp.Results = matched[offset:end]
	return connect.NewResponse(resp), nil
}

// QueryAll returns every stored result that matches the filter, newest
// first. The portal pages use it.
func (s *Service) QueryAll(ctx context.Context, filter *resultsv1.Filter) ([]*resultsv1.VerificationResult, error) {
	return s.matching(ctx, filter)
}

// Read returns one result. The portal detail page uses it.
func (s *Service) Read(ctx context.Context, id string) (*resultsv1.VerificationResult, error) {
	return s.opts.Store.Get(ctx, id)
}

// matching returns every stored result that matches the filter.
func (s *Service) matching(ctx context.Context, filter *resultsv1.Filter) ([]*resultsv1.VerificationResult, error) {
	all, err := s.opts.Store.All(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return query.Apply(filter, all), nil
}

// Sender takes one export chunk. The Connect server stream satisfies it.
type Sender interface {
	Send(*resultsv1.ExportResponse) error
}

// Export streams the matching results as CSV or as JSON lines
// (ADR-025 decision 4).
func (s *Service) Export(ctx context.Context, req *connect.Request[resultsv1.ExportRequest],
	stream *connect.ServerStream[resultsv1.ExportResponse]) error {
	return s.SendExport(ctx, req.Msg, stream)
}

// SendExport writes the export to any sender. Tests inject a fake.
func (s *Service) SendExport(ctx context.Context, req *resultsv1.ExportRequest, out Sender) error {
	matched, err := s.matching(ctx, req.GetFilter())
	if err != nil {
		return err
	}
	body, err := Encode(req.GetEncoding(), matched)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	for len(body) > ChunkBytes {
		if serr := out.Send(&resultsv1.ExportResponse{Chunk: body[:ChunkBytes]}); serr != nil {
			return serr
		}
		body = body[ChunkBytes:]
	}
	return out.Send(&resultsv1.ExportResponse{Chunk: body, Done: true})
}

// Encode writes the results in one encoding. The portal download uses it
// too.
func Encode(encoding resultsv1.ExportRequest_Encoding, list []*resultsv1.VerificationResult) ([]byte, error) {
	var buf bytes.Buffer
	if encoding == resultsv1.ExportRequest_ENCODING_JSON {
		if err := export.JSONLines(&buf, list); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	if err := export.CSV(&buf, list); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Purge deletes the raw presentations first, then the results whose
// retention window ended (ADR-025 decision 3).
func (s *Service) Purge(ctx context.Context, req *connect.Request[resultsv1.PurgeRequest]) (
	*connect.Response[resultsv1.PurgeResponse], error) {
	counts, err := s.purge(ctx, req.Msg.GetBefore().AsTime(), req.Msg.GetBefore() != nil,
		req.Msg.GetRawOnly(), req.Msg.GetDryRun())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(counts), nil
}

// PurgeNow runs the purge with the current time. The scheduled job and
// the tests call it.
func (s *Service) PurgeNow(ctx context.Context) (*resultsv1.PurgeResponse, error) {
	return s.purge(ctx, time.Time{}, false, false, false)
}

func (s *Service) purge(ctx context.Context, before time.Time, hasBefore, rawOnly, dryRun bool) (
	*resultsv1.PurgeResponse, error) {
	at := s.opts.Now()
	if hasBefore {
		at = before
	}
	all, err := s.opts.Store.All(ctx)
	if err != nil {
		return nil, err
	}
	out := &resultsv1.PurgeResponse{}
	for _, r := range all {
		evaluated := r.GetEvaluatedAt().AsTime()
		if holdsRaw(r) && !evaluated.Add(s.opts.RawRetention).After(at) {
			out.RawDeleted++
			if !dryRun {
				if derr := s.clearRaw(ctx, r); derr != nil {
					return nil, derr
				}
			}
		}
		if rawOnly || retainUntil(r, s.opts.Retention).After(at) {
			continue
		}
		out.ResultsDeleted++
		if !dryRun {
			if derr := s.opts.Store.Delete(ctx, r.GetId()); derr != nil {
				return nil, derr
			}
		}
	}
	return out, nil
}

// clearRaw deletes the raw presentation and the decoded credentials.
func (s *Service) clearRaw(ctx context.Context, r *resultsv1.VerificationResult) error {
	if err := s.opts.Store.DeleteRaw(ctx, r.GetId()); err != nil {
		return err
	}
	r.RawRef = ""
	for _, c := range r.GetCredentials() {
		c.DecodedJson = ""
	}
	_, err := s.opts.Store.Put(ctx, r)
	return err
}

// holdsRaw reports whether a result still holds raw personal data.
func holdsRaw(r *resultsv1.VerificationResult) bool {
	if r.GetRawRef() != "" {
		return true
	}
	for _, c := range r.GetCredentials() {
		if c.GetDecodedJson() != "" {
			return true
		}
	}
	return false
}

// retainUntil returns the end of the retention window of a result.
func retainUntil(r *resultsv1.VerificationResult, window time.Duration) time.Time {
	if r.GetRetainUntil() != nil {
		return r.GetRetainUntil().AsTime()
	}
	return r.GetEvaluatedAt().AsTime().Add(window)
}
