// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
)

// IssueBatch issues many credentials in one job and streams progress.
//
// The rows come from the request, or from the data source service when
// the request names a source job (ADR-014). A row keeps the JSON types
// of its subject data, as a single issue does. The stream carries one
// message per row and one final message. With native set, the rows go
// to the bulk import of the DPG in one call (ADR-043 decision 4).
func (s *Service) IssueBatch(
	ctx context.Context, req *connect.Request[issuancev1.IssueBatchRequest],
	stream *connect.ServerStream[issuancev1.IssueBatchResponse],
) error {
	msg := req.Msg
	ctx = auditlog.WithActor(ctx, auditlog.ActorFrom(req.Header()))
	items, err := s.batchItems(ctx, msg)
	if err != nil {
		return err
	}
	var bulk *nativeRun
	if msg.GetNative() {
		if bulk, err = s.prepareNative(ctx, msg); err != nil {
			return err
		}
	}
	run := &batchRun{s: s, stream: stream, job: offers.Job{
		ID:        s.opts.NewID(),
		Total:     int64(len(items)),
		CreatedAt: s.opts.Now().UTC(),
	}}
	if perr := s.opts.Store.PutJob(ctx, run.job); perr != nil {
		return internal("store the job", perr)
	}
	if serr := stream.Send(progress(run.job)); serr != nil {
		return serr
	}
	if bulk != nil {
		err = s.runNative(ctx, run, bulk, items)
	} else {
		err = s.runRows(ctx, run, msg, items)
	}
	if err != nil {
		return err
	}
	run.job.Done = true
	if perr := s.opts.Store.PutJob(ctx, run.job); perr != nil {
		return internal("store the job", perr)
	}
	return stream.Send(progress(run.job))
}

// batchRun is one batch job while it runs.
type batchRun struct {
	s      *Service
	stream *connect.ServerStream[issuancev1.IssueBatchResponse]
	job    offers.Job
}

// done stores the result of one row, counts it, and sends the progress.
// A nil cause marks the row issued.
func (b *batchRun) done(ctx context.Context, row offers.Row, cause error) error {
	if cause != nil {
		row.Code = "VCA-ISSUANCE-ROW"
		row.Message = cause.Error()
		b.job.Rejected++
	} else {
		b.job.Accepted++
	}
	b.job.Processed++
	if perr := b.s.opts.Store.PutRow(ctx, b.job.ID, row); perr != nil {
		return internal("store the row", perr)
	}
	if perr := b.s.opts.Store.PutJob(ctx, b.job); perr != nil {
		return internal("store the job", perr)
	}
	return b.stream.Send(progress(b.job))
}

// runRows issues the rows one at a time through the path of a single
// issue.
func (s *Service) runRows(ctx context.Context, run *batchRun, msg *issuancev1.IssueBatchRequest,
	items []*issuancev1.IssueBatchRequest_Item,
) error {
	for _, item := range items {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		row := offers.Row{Row: item.GetRow()}
		claims, values, cerr := readTypedClaims(item.GetSubjectData())
		if cerr == nil {
			row.Label = label(claims)
			offer, ierr := s.issueOne(ctx, request{
				schemaID:      msg.GetSchemaId(),
				schemaVersion: msg.GetSchemaVersion(),
				claims:        claims,
				values:        values,
				format:        msg.GetFormat(),
				channel:       msg.GetChannel(),
				delivery:      item.GetDelivery(),
			})
			cerr = ierr
			row.OfferID = offer.ID
		}
		if derr := run.done(ctx, row, cerr); derr != nil {
			return derr
		}
	}
	return nil
}

// nativeRun is what a native batch reads once: the schema version and
// the format.
type nativeRun struct {
	schema *schemav1.Schema
	format commonv1.Format
}

// prepareNative checks that the stack has a bulk import and reads the
// schema of the batch.
func (s *Service) prepareNative(ctx context.Context, msg *issuancev1.IssueBatchRequest) (*nativeRun, error) {
	caps, err := s.opts.Capabilities.Get(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !caps.Has(backendv1.Feature_FEATURE_BULK_NATIVE) {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the DPG adapter has no bulk import, so run the batch without native"))
	}
	if c := msg.GetChannel(); c != backendv1.Channel_CHANNEL_UNSPECIFIED && c != backendv1.Channel_CHANNEL_PDF {
		return nil, badRequest("a native batch gives each row a document, so the channel is CHANNEL_PDF")
	}
	schema, err := s.schema(ctx, msg.GetSchemaId(), msg.GetSchemaVersion())
	if err != nil {
		return nil, err
	}
	format := formatOf(msg.GetFormat(), schema.GetFormats(), caps)
	if !caps.SupportsFormat(format) {
		return nil, badRequest(fmt.Sprintf("the DPG adapter cannot issue the format %s", format))
	}
	return &nativeRun{schema: schema, format: format}, nil
}

// nativeRow is one row of a native batch that passed the schema.
type nativeRow struct {
	row     offers.Row
	claims  map[string]string
	binding *backendv1.StatusListBinding
	spec    *backendv1.IssueSpec
}

// runNative checks every row against the schema, sends the rows that
// pass to the bulk import of the stack in one call, and turns each
// credential into a document. A row the schema or the stack refuses
// fails alone.
func (s *Service) runNative(ctx context.Context, run *batchRun, bulk *nativeRun,
	items []*issuancev1.IssueBatchRequest_Item,
) error {
	var ready []nativeRow
	for _, item := range items {
		n := nativeRow{row: offers.Row{Row: item.GetRow()}}
		claims, values, err := readTypedClaims(item.GetSubjectData())
		if err == nil {
			n.claims, n.row.Label = claims, label(claims)
			err = checkClaims(bulk.schema, values)
		}
		if err == nil {
			n.binding, err = s.allocateStatus(ctx, "", bulk.format)
		}
		if err != nil {
			s.opts.Audit.Record(ctx, nil, ActionIssue, bulk.schema.GetId(), "", err)
			if derr := run.done(ctx, n.row, err); derr != nil {
				return derr
			}
			continue
		}
		n.spec = &backendv1.IssueSpec{
			ConfigurationId: configurationOf(bulk.schema), Format: bulk.format,
			SubjectData: request{values: values}.subjectData(), Status: n.binding,
		}
		ready = append(ready, n)
	}
	if len(ready) == 0 {
		return nil
	}
	specs := make([]*backendv1.IssueSpec, 0, len(ready))
	for _, n := range ready {
		specs = append(specs, n.spec)
	}
	resp, callErr := s.opts.Issuer.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{Specs: specs}))
	results := map[int32]*backendv1.IssueBatchResponse_Item{}
	if callErr == nil {
		for _, item := range resp.Msg.GetItems() {
			results[item.GetPosition()] = item
		}
	}
	for i, n := range ready {
		item := results[int32(i)] //nolint:gosec // i counts the rows of one request
		var err error
		switch {
		case callErr != nil:
			err = fmt.Errorf("the bulk import of the stack failed: %w", callErr)
		case item == nil:
			err = errors.New("the bulk import of the stack returned no result for the row")
		case item.GetError() != nil:
			err = fmt.Errorf("the stack refused the row: %s", item.GetError().GetMessage())
		default:
			var offer offers.Offer
			offer, err = s.keepNative(ctx, bulk, n, item.GetCredential())
			n.row.OfferID = offer.ID
		}
		s.recordIssue(ctx, bulk.schema.GetId(), n.row.OfferID, bulk.schema.GetVersion(), backendv1.Channel_CHANNEL_PDF.String(), err)
		if derr := run.done(ctx, n.row, err); derr != nil {
			return derr
		}
	}
	return nil
}

// keepNative stores the credential of one native row as a document
// offer with its issued record, as the document channel does.
func (s *Service) keepNative(ctx context.Context, bulk *nativeRun, n nativeRow, credential *commonv1.Credential) (offers.Offer, error) {
	now := s.opts.Now().UTC()
	offer := offers.Offer{
		ID:            s.opts.NewID(),
		Channel:       backendv1.Channel_CHANNEL_PDF.String(),
		State:         offers.StatePending,
		SchemaID:      bulk.schema.GetId(),
		SchemaVersion: bulk.schema.GetVersion(),
		Format:        int32(bulk.format),
		Claims:        searchable(bulk.schema, n.claims),
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.opts.OfferTTL),
	}
	r := request{claims: n.claims, channel: backendv1.Channel_CHANNEL_PDF}
	if err := s.credentialDocument(ctx, &offer, credential, bulk.schema, r); err != nil {
		return offers.Offer{}, err
	}
	if rerr := s.record(ctx, &offer, n.binding, nil); rerr != nil {
		s.opts.Log.Warn("the issued record did not reach the log", "error", rerr)
	}
	if perr := s.opts.Store.PutOffer(ctx, offer); perr != nil {
		return offers.Offer{}, internal("store the offer", perr)
	}
	return offer, nil
}

// batchItems returns the items of a batch. A request with a source job
// id reads its rows from the data source service.
func (s *Service) batchItems(ctx context.Context, msg *issuancev1.IssueBatchRequest) (
	[]*issuancev1.IssueBatchRequest_Item, error,
) {
	items := msg.GetItems()
	sourceJob := strings.TrimSpace(msg.GetSourceJobId())
	if sourceJob == "" {
		if len(items) == 0 {
			return nil, badRequest("the request needs items or a source_job_id")
		}
		return items, nil
	}
	if s.opts.Rows == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment has no data source service, so a source job has no rows"))
	}
	rows, err := s.opts.Rows.Rows(ctx, sourceJob)
	if err != nil {
		return nil, connect.NewError(connect.CodeOf(err),
			fmt.Errorf("read the rows of the source job: %w", err))
	}
	if len(rows) == 0 {
		return nil, badRequest("the source job has no row")
	}
	out := make([]*issuancev1.IssueBatchRequest_Item, 0, len(rows))
	for i, row := range rows {
		out = append(out, &issuancev1.IssueBatchRequest_Item{
			Row:         int64(i + 1),
			SubjectData: mustJSON(row),
		})
	}
	return out, nil
}

// progress returns the progress message of a job.
func progress(j offers.Job) *issuancev1.IssueBatchResponse {
	return &issuancev1.IssueBatchResponse{
		JobId:     j.ID,
		Processed: j.Processed,
		Accepted:  j.Accepted,
		Rejected:  j.Rejected,
		Total:     j.Total,
		Done:      j.Done,
	}
}

// GetBatch returns one page of the rows of a batch job.
func (s *Service) GetBatch(
	ctx context.Context, req *connect.Request[issuancev1.GetBatchRequest],
) (*connect.Response[issuancev1.GetBatchResponse], error) {
	id := strings.TrimSpace(req.Msg.GetJobId())
	if id == "" {
		return nil, badRequest("the request needs a job_id")
	}
	job, err := s.opts.Store.Job(ctx, id)
	if errors.Is(err, offers.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, internal("read the job", err)
	}
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	start, terr := offers.ParseToken(req.Msg.GetPage().GetPageToken())
	if terr != nil {
		return nil, badRequest(terr.Error())
	}
	rows, next, rerr := s.opts.Store.Rows(ctx, id, start, size, req.Msg.GetFailedOnly())
	if rerr != nil {
		return nil, internal("read the rows", rerr)
	}
	out := &issuancev1.GetBatchResponse{
		Page:     &commonv1.PageResult{NextPageToken: next, TotalSize: job.Total},
		Progress: progress(job),
	}
	for _, r := range rows {
		row := &issuancev1.BatchRow{Row: r.Row, Label: r.Label}
		if r.Failed() {
			row.Error = &commonv1.Error{
				Code:     r.Code,
				Message:  r.Message,
				NextStep: "Check the claims of the row against the schema.",
			}
		} else if r.OfferID != "" {
			offer, oerr := s.opts.Store.Offer(ctx, r.OfferID)
			if oerr == nil {
				row.Offer = view(offer)
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return connect.NewResponse(out), nil
}
