// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// Finding 2.1 of the CREDEBL review: a stack wallet that answers with
// every claim of a query (FEATURE_WALLET_WHOLE_QUERY) must not offer an
// optional claim on the consent screen, and the history must name what
// the stack shared.

// claimSetRequest is an OID4VP request object whose claim sets make
// birth_date optional.
func claimSetRequest(context.Context, string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"client_id": "https://verifier.example", "nonce": "n-1",
		"response_uri": "https://verifier.example/direct_post", "state": "s-1",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "licence", "format": "dc+sd-jwt",
			"meta": map[string]any{"vct_values": []string{"DriverLicence"}},
			"claims": []any{
				map[string]any{"id": "g", "path": []string{"given_name"}},
				map[string]any{"id": "b", "path": []string{"birth_date"}},
			},
			"claim_sets": [][]string{{"g", "b"}, {"g"}},
		}}},
	})
}

// wholeHolder is the fake holder of a stack that shares every claim.
type wholeHolder struct {
	fakeHolder
	shared []string
}

func (h *wholeHolder) Present(ctx context.Context, req *connect.Request[backendv1.PresentRequest],
) (*connect.Response[backendv1.PresentResponse], error) {
	res, err := h.fakeHolder.Present(ctx, req)
	if err != nil {
		return nil, err
	}
	res.Msg.SharedClaims = h.shared
	return res, nil
}

// startClaims opens the request and returns the mandatory flag of each
// claim by path.
func startClaims(t *testing.T, svc *service.Service) (string, map[string]bool) {
	t.Helper()
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetPresentationId()
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id}))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, c := range start.Msg.GetRequested()[0].GetClaims() {
		out[c.GetPath()] = c.GetMandatory()
	}
	return id, out
}

// TestConsentMarksEveryClaimWhenTheStackSharesTheWholeQuery: with the
// feature every claim is required; without it the claim sets decide.
func TestConsentMarksEveryClaimWhenTheStackSharesTheWholeQuery(t *testing.T) {
	holder := &fakeHolder{credential: credential(t), accepted: true}
	plain := build(t, func(o *service.Options) { o.Holder, o.Fetch = holder, claimSetRequest })
	if _, claims := startClaims(t, plain); !claims["given_name"] || claims["birth_date"] {
		t.Fatalf("without the feature: %v", claims)
	}
	whole := build(t, func(o *service.Options) {
		o.Holder, o.Fetch = holder, claimSetRequest
		o.WholeQuery = func(context.Context) bool { return true }
	})
	if _, claims := startClaims(t, whole); !claims["given_name"] || !claims["birth_date"] {
		t.Fatalf("with the feature: %v", claims)
	}
}

// TestHistoryNamesWhatTheStackShared: the record of a presentation
// through the stack names the claims the stack reports.
func TestHistoryNamesWhatTheStackShared(t *testing.T) {
	holder := &wholeHolder{fakeHolder: fakeHolder{credential: credential(t), accepted: true}, shared: []string{"given_name", "birth_date"}}
	svc := build(t, func(o *service.Options) { o.Holder, o.Fetch = holder, claimSetRequest })
	id, _ := startClaims(t, svc)
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: id, SelectedCards: map[string]string{"licence": "c1"},
		Disclosed: map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{"licence": {Paths: []string{"given_name"}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(confirm.Msg.GetRecord().GetClaims(), ","); got != "given_name,birth_date" {
		t.Fatalf("record claims = %q", got)
	}
}

// TestStackRefusalOfAConsentReachesTheHolder: a stack that refuses the
// consent says why, and the holder sees that reason.
func TestStackRefusalOfAConsentReachesTheHolder(t *testing.T) {
	reason := "this wallet shares every claim the verifier asks for (birth_date); tick them all or decline"
	holder := &fakeHolder{credential: credential(t), presentErr: connect.NewError(connect.CodeFailedPrecondition, errors.New(reason))}
	svc := build(t, func(o *service.Options) { o.Holder, o.Fetch = holder, claimSetRequest })
	id, _ := startClaims(t, svc)
	_, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: id, SelectedCards: map[string]string{"licence": "c1"},
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "tick them all") {
		t.Fatalf("refusal: %v", err)
	}
}
