// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// The carriers of a presented credential that staff gave the page
// themselves, as the result names them.
const (
	// CarrierScan names a QR code that the camera read.
	CarrierScan = "qr scan"
	// CarrierUpload names an uploaded image or document.
	CarrierUpload = "upload"
	// CarrierLink names a link that the service fetched.
	CarrierLink = "link"
	// CarrierPaste names pasted text.
	CarrierPaste = "paste"
)

// Check evaluates a presentation that staff scanned, uploaded, linked
// or pasted, with the default policy set, and stores the result (spec:
// QR scanning, document uploads and link pasting). The presentation
// answers no request, so no nonce binds it. The result names the
// carrier.
func (s *Service) Check(ctx context.Context, raw *ingestv1.RawPresentation, carrier string) (*resultsv1.VerificationResult, error) {
	if len(raw.GetCredentials()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the input holds no credential to check"))
	}
	if s.opts.Policy == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no policy service is configured, so the page cannot check the credential"))
	}
	resp, err := s.opts.Policy.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: raw, At: timestamppb.New(s.opts.Now()),
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the policy service did not check the credential"))
	}
	result := ResultOf(raw, resp.Msg, &txn.Transaction{})
	result.Carrier = carrier
	if s.opts.Results == nil {
		return result, nil
	}
	stored, err := s.opts.Results.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{Result: result}))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the results service did not store the result"))
	}
	return stored.Msg.GetResult(), nil
}
