// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// The reasons of a failed check, as the scanner shows them.
const (
	reasonInvalid = "The proof or the structure of the credential failed."
	reasonExpired = "The credential expired."
	reasonRevoked = "The issuer revoked the credential."
	reasonOther   = "The stack gave a status the adapter does not know."
)

// VerifyCredential checks an uploaded or scanned credential through the
// credential check of Inji Verify 0.16.0 (FEATURE_VERIFY_UPLOAD). The
// adapter reads the carrier first: a QR image, a PDF, a PixelPass text,
// a JSON-LD document, or an SD-JWT. It sends each credential it finds
// and maps the one status of the answer onto the checks it covers. VCA
// runs its own checks too (ADR-024 decision 2).
func (s *Service) VerifyCredential(
	ctx context.Context, req *connect.Request[backendv1.VerifyCredentialRequest],
) (*connect.Response[backendv1.VerifyCredentialResponse], error) {
	if s.verify == nil {
		return nil, unimplemented("this adapter has no Inji Verify URL, so it checks no credential")
	}
	res, err := ingest.Decode(req.Msg.GetPayload(), ingest.Options{MediaType: req.Msg.GetMediaType()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the input did not decode: %w", err))
	}
	creds := res.Credentials
	if len(creds) == 0 && res.Detected == ingest.TypeCredential {
		creds = []ingest.Credential{{Format: res.Format, Payload: res.Payload}}
	}
	if len(creds) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the input holds no credential"))
	}
	out := &backendv1.VerifyCredentialResponse{Verified: true}
	for _, c := range creds {
		contentType, ok := checkContentType(c.Format)
		if !ok {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"the credential check of Inji Verify 0.16.0 takes JSON-LD and SD-JWT credentials, not %q", c.Format))
		}
		status, err := s.verify.CheckCredential(ctx, c.Payload, contentType)
		if err != nil {
			return nil, failed("check the credential", err)
		}
		if status != inji.StatusSuccess {
			out.Verified = false
		}
		out.DpgChecks = append(out.DpgChecks, statusChecks(status)...)
	}
	return connect.NewResponse(out), nil
}

// checkContentType returns the Content-Type that selects the format in
// the credential check, or false for a format it does not check.
func checkContentType(f vc.Format) (string, bool) {
	switch f {
	case vc.FormatJSONLD, vc.FormatJSON:
		return "application/json", true
	case vc.FormatSDJWT:
		return "application/vc+sd-jwt", true
	}
	return "", false
}

// statusChecks maps one verification status onto the checks it covers.
// A status says nothing of a check it does not name, so that check stays
// out of the answer.
func statusChecks(status string) []*backendv1.GetResultResponse_DpgCheck {
	check := func(name string, passed bool, reason string) *backendv1.GetResultResponse_DpgCheck {
		return &backendv1.GetResultResponse_DpgCheck{Name: name, Passed: passed, Reason: reason}
	}
	first := check("inji-verification-status", status == inji.StatusSuccess, "")
	if status != inji.StatusSuccess {
		first.Reason = "The stack answered " + status + "."
	}
	out := []*backendv1.GetResultResponse_DpgCheck{first}
	switch status {
	case inji.StatusSuccess:
		out = append(out, check("signature", true, ""), check("expiry", true, ""), check("revocation", true, ""))
	case inji.StatusExpired:
		out = append(out, check("signature", true, ""), check("expiry", false, reasonExpired))
	case inji.StatusRevoked:
		out = append(out, check("revocation", false, reasonRevoked))
	case inji.StatusInvalid:
		out = append(out, check("signature", false, reasonInvalid))
	default:
		out[0].Reason = reasonOther
	}
	return out
}
