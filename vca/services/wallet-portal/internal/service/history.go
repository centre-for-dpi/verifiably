// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// KindHistory is the prefix of the presentation records (spec HO4).
const KindHistory = "history"

// MaxHistory is the number of presentation records a wallet keeps. The
// oldest record goes first.
const MaxHistory = 100

// history is one presentation record in the store. It holds claim names
// and never a claim value.
type history struct {
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	Verifier     string    `json:"verifier"`
	VerifierName string    `json:"verifier_name,omitempty"`
	Claims       []string  `json:"claims,omitempty"`
	Result       string    `json:"result"`
}

// proto returns the record as the RPC returns it.
func (h history) proto() *walletportalv1.PresentationRecord {
	return &walletportalv1.PresentationRecord{
		Id: h.ID, At: timestamppb.New(h.At), Verifier: h.Verifier, VerifierName: h.VerifierName,
		Claims: h.Claims, Result: walletportalv1.PresentationRecord_Result(walletportalv1.PresentationRecord_Result_value[h.Result]),
	}
}

// remember writes one presentation record and drops the oldest records
// above MaxHistory. A store fault loses the record but not the answer,
// which the verifier already has.
func (s *Service) remember(ctx context.Context, citizen session.Citizen, parsed present.Request,
	claims []string, result walletportalv1.PresentationRecord_Result,
) *walletportalv1.PresentationRecord {
	now := s.opts.Now().UTC()
	h := history{
		ID: fmt.Sprintf("%020d-%09d-%s", now.UnixNano(), s.seq.Add(1), s.opts.NewID()), At: now, Verifier: parsed.ClientID,
		VerifierName: present.TrustOf(ctx, s.opts.Trust, parsed.ClientID).Name, Claims: claims, Result: result.String(),
	}
	if k, err := key(KindHistory, citizen.WalletKey(), h.ID); err == nil {
		if raw, merr := json.Marshal(h); merr == nil && s.opts.Store.Put(ctx, k, raw) == nil {
			s.trim(ctx, citizen)
		}
	}
	return h.proto()
}

// trim drops the oldest records above MaxHistory.
func (s *Service) trim(ctx context.Context, citizen session.Citizen) {
	keys, err := s.opts.Store.List(ctx, KindHistory+"/"+citizen.WalletKey()+"/")
	if err != nil {
		return
	}
	slices.Sort(keys)
	for len(keys) > MaxHistory {
		ignored := s.opts.Store.Delete(ctx, keys[0])
		_ = ignored
		keys = keys[1:]
	}
}

// requestedNames returns every claim name a request asks for.
func requestedNames(parsed present.Request) []string {
	var out []string
	for _, cq := range parsed.Query.Credentials {
		for _, c := range cq.Claims {
			out = append(out, c.Path.String())
		}
	}
	return out
}

// PresentDecline refuses a presentation request (spec HO4). The wallet
// tells the verifier with the OID4VP error access_denied, keeps a record
// of the refusal, and forgets the request. A verifier that does not
// answer still leaves the record.
func (s *Service) PresentDecline(ctx context.Context, req *connect.Request[walletportalv1.PresentDeclineRequest],
) (*connect.Response[walletportalv1.PresentDeclineResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	id, parsed, err := s.request(ctx, citizen, req.Msg.GetPresentationId())
	if err != nil {
		return nil, err
	}
	if parsed.ResponseURI != "" && s.opts.Post != nil {
		form := url.Values{"error": {"access_denied"}}
		if parsed.State != "" {
			form.Set("state", parsed.State)
		}
		_, told := s.opts.Post(ctx, parsed.ResponseURI, form)
		_ = told
	}
	record := s.remember(ctx, citizen, parsed, nil, walletportalv1.PresentationRecord_RESULT_DECLINED)
	ignored := s.drop(ctx, KindPresentation, citizen.WalletKey(), id)
	_ = ignored
	return connect.NewResponse(&walletportalv1.PresentDeclineResponse{Record: record}), nil
}

// ListPresentations returns the presentation records, newest first.
func (s *Service) ListPresentations(ctx context.Context, req *connect.Request[walletportalv1.ListPresentationsRequest],
) (*connect.Response[walletportalv1.ListPresentationsResponse], error) {
	citizen, err := session.Require(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := s.opts.Store.List(ctx, KindHistory+"/"+citizen.WalletKey()+"/")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("the wallet could not read its records"))
	}
	slices.Sort(keys)
	slices.Reverse(keys)
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.opts.PageSizeMax {
		size = s.opts.PageSizeMax
	}
	out := make([]*walletportalv1.PresentationRecord, 0, min(size, len(keys)))
	for _, k := range keys {
		if len(out) == size {
			break
		}
		raw, gerr := s.opts.Store.Get(ctx, k)
		if gerr != nil {
			continue
		}
		var h history
		if json.Unmarshal(raw, &h) != nil {
			continue
		}
		out = append(out, h.proto())
	}
	return connect.NewResponse(&walletportalv1.ListPresentationsResponse{
		Records: out, Page: &commonv1.PageResult{TotalSize: int64(len(keys))},
	}), nil
}
