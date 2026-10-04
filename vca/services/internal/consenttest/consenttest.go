// SPDX-License-Identifier: Apache-2.0

// Package consenttest is the guard of ADR-081 decision 6. Every holder
// adapter runs Run against its holder service and the test double of
// its wallet, so no adapter reports or sends a claim the holder did not
// consent to. The guard test of this package fails when an adapter
// package does not call Run.
package consenttest

import (
	"context"
	"slices"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/disclosure"
)

// Exchange is one answer of a stack wallet that the contract checks.
type Exchange struct {
	// Present calls the holder service of the adapter.
	Present func(ctx context.Context, req *backendv1.PresentRequest) (*backendv1.PresentResponse, error)
	// Narrow asks for an answer whose disclosed_claims leave out at
	// least one claim the wallet sends.
	Narrow *backendv1.PresentRequest
	// Full asks for the same answer with consent to every claim the
	// wallet sends.
	Full *backendv1.PresentRequest
	// Sent returns the claim names the verifier received through the
	// test double, or none when the wallet sent nothing. It returns
	// disclosure.Whole among them when the wallet sent a whole
	// credential.
	Sent func() []string
	// Reset forgets what the double received, between the two answers.
	Reset func()
}

// T is the part of testing.T that Run uses.
type T interface {
	Helper()
	Errorf(format string, args ...any)
}

// Run checks the contract of ADR-081 decision 5. The narrow answer is
// refused with FailedPrecondition and sends nothing, or it sends only
// consented claims. The full answer goes, and shared_claims names
// exactly what the wallet sent.
func Run(t T, ex Exchange) {
	t.Helper()
	ctx := context.Background()
	resp, err := ex.Present(ctx, ex.Narrow)
	sent := ex.Sent()
	switch {
	case err != nil && connect.CodeOf(err) != connect.CodeFailedPrecondition:
		t.Errorf("the narrow answer failed with %v, want failed_precondition or an answer", err)
	case err != nil && len(sent) > 0:
		t.Errorf("the adapter refused the narrow answer, yet the wallet sent %v", sent)
	case err == nil:
		check(t, "narrow", ex.Narrow, resp, sent)
	}
	if ex.Reset != nil {
		ex.Reset()
	}
	resp, err = ex.Present(ctx, ex.Full)
	sent = ex.Sent()
	switch {
	case err != nil:
		t.Errorf("the full answer: %v", err)
	case len(sent) == 0:
		t.Errorf("the full answer sent no claim")
	default:
		check(t, "full", ex.Full, resp, sent)
	}
}

// check compares one answer with what the double received.
func check(t T, name string, req *backendv1.PresentRequest, resp *backendv1.PresentResponse, sent []string) {
	t.Helper()
	if missing := disclosure.Missing(sent, req.GetDisclosedClaims()); len(missing) > 0 {
		t.Errorf("the %s answer sent %v without consent; the holder ticked %v", name, missing, req.GetDisclosedClaims())
	}
	shared := slices.Sorted(slices.Values(resp.GetSharedClaims()))
	want := slices.Sorted(slices.Values(sent))
	if !slices.Equal(shared, want) {
		t.Errorf("the %s answer reports %v as shared, the verifier received %v", name, shared, want)
	}
}
