// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"sort"
	"strconv"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// DefaultListPageSize is the page size of ListTransactions when the
// caller sets none.
const DefaultListPageSize = 50

// MaxListPageSize caps the page size of ListTransactions.
const MaxListPageSize = 200

// ListTransactions lists the transactions, newest first. The state of a
// pending request past its expiry reads as expired, and the state
// filter uses that reading. The page token is the offset in the list.
func (s *Service) ListTransactions(ctx context.Context, req *connect.Request[ingestv1.ListTransactionsRequest]) (*connect.Response[ingestv1.ListTransactionsResponse], error) {
	offset := 0
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		n, err := strconv.Atoi(token)
		if err != nil || n < 0 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the page token is not an offset"))
		}
		offset = n
	}
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 {
		size = DefaultListPageSize
	}
	size = min(size, MaxListPageSize)
	list, err := s.opts.Store.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	now := s.opts.Now()
	want := req.Msg.GetState()
	matches := make([]*ingestv1.TransactionSummary, 0, len(list))
	for _, t := range list {
		state := txn.ProtoState(t.StateAt(now))
		if want != ingestv1.GetTransactionResponse_STATE_UNSPECIFIED && state != want {
			continue
		}
		matches = append(matches, summary(t, state))
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].GetCreatedAt().AsTime().After(matches[j].GetCreatedAt().AsTime())
	})
	page := &commonv1.PageResult{TotalSize: int64(len(matches))}
	start := min(offset, len(matches))
	end := min(start+size, len(matches))
	if end < len(matches) {
		page.NextPageToken = strconv.Itoa(end)
	}
	return connect.NewResponse(&ingestv1.ListTransactionsResponse{Transactions: matches[start:end], Page: page}), nil
}

// summary returns the list entry of one transaction.
func summary(t txn.Transaction, state ingestv1.GetTransactionResponse_State) *ingestv1.TransactionSummary {
	out := &ingestv1.TransactionSummary{
		TransactionId: t.ID, State: state, TemplateId: t.TemplateID, TemplateVersion: t.TemplateVersion,
		CreatedAt: timestamppb.New(t.CreatedAt), ExpiresAt: timestamppb.New(t.ExpiresAt),
		ResultId: t.ResultID, Stack: t.Stack,
	}
	if !t.AnsweredAt.IsZero() {
		out.AnsweredAt = timestamppb.New(t.AnsweredAt)
	}
	return out
}
