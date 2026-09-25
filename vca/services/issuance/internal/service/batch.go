// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
)

// IssueBatch issues many credentials in one job and streams progress.
//
// The rows come from the request, or from the data source service when
// the request names a source job (ADR-014). The stream carries one
// message per row and one final message.
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
	job := offers.Job{
		ID:        s.opts.NewID(),
		Total:     int64(len(items)),
		CreatedAt: s.opts.Now().UTC(),
	}
	if perr := s.opts.Store.PutJob(ctx, job); perr != nil {
		return internal("store the job", perr)
	}
	if serr := stream.Send(progress(job)); serr != nil {
		return serr
	}
	for _, item := range items {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		row := offers.Row{Row: item.GetRow(), Label: ""}
		claims, cerr := readClaims(item.GetSubjectData())
		if cerr == nil {
			row.Label = label(claims)
			offer, ierr := s.issueOne(ctx, request{
				schemaID:      msg.GetSchemaId(),
				schemaVersion: msg.GetSchemaVersion(),
				claims:        claims,
				format:        msg.GetFormat(),
				channel:       msg.GetChannel(),
				delivery:      item.GetDelivery(),
			})
			if ierr != nil {
				cerr = ierr
			} else {
				row.OfferID = offer.ID
			}
		}
		if cerr != nil {
			row.Code = "VCA-ISSUANCE-ROW"
			row.Message = cerr.Error()
			job.Rejected++
		} else {
			job.Accepted++
		}
		job.Processed++
		if perr := s.opts.Store.PutRow(ctx, job.ID, row); perr != nil {
			return internal("store the row", perr)
		}
		if perr := s.opts.Store.PutJob(ctx, job); perr != nil {
			return internal("store the job", perr)
		}
		if serr := stream.Send(progress(job)); serr != nil {
			return serr
		}
	}
	job.Done = true
	if perr := s.opts.Store.PutJob(ctx, job); perr != nil {
		return internal("store the job", perr)
	}
	return stream.Send(progress(job))
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
