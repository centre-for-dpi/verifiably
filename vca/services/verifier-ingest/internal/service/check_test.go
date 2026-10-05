// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
)

// TestCheckEvaluatesAPresentedCredential runs the checks of VCA on a
// credential that staff gave the page, with the default policy set and
// no nonce, and stores the result under its carrier.
func TestCheckEvaluatesAPresentedCredential(t *testing.T) {
	raw := &ingestv1.RawPresentation{Credentials: []*commonv1.Credential{{Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte("x")}}}
	pol, res := &evaluator{}, &keeper{}
	svc, _ := build(t, service.Options{Policy: pol, Results: res})
	got, err := svc.Check(context.Background(), raw, service.CarrierUpload)
	if err != nil || got.GetId() != "res-7" || res.kept.GetCarrier() != service.CarrierUpload || len(res.kept.GetCredentials()) != 1 {
		t.Fatalf("Check = %+v, %v", got, err)
	}
	if pol.sets[0] != "" || pol.nonces[0] != "" {
		t.Fatalf("the check named the set %q and the nonce %q", pol.sets[0], pol.nonces[0])
	}
	unsaved, _ := build(t, service.Options{Policy: &evaluator{}})
	if got, err := unsaved.Check(context.Background(), raw, service.CarrierPaste); err != nil || got.GetCarrier() != service.CarrierPaste {
		t.Fatalf("a check without a results service: %+v, %v", got, err)
	}
	for name, c := range map[string]struct {
		opts service.Options
		raw  *ingestv1.RawPresentation
		code connect.Code
	}{
		"no credential": {service.Options{Policy: &evaluator{}}, &ingestv1.RawPresentation{}, connect.CodeInvalidArgument},
		"no policy":     {service.Options{}, raw, connect.CodeFailedPrecondition},
		"policy fails":  {service.Options{Policy: &evaluator{err: errors.New("down")}}, raw, connect.CodeUnavailable},
		"store fails":   {service.Options{Policy: &evaluator{}, Results: &keeper{err: errors.New("down")}}, raw, connect.CodeUnavailable},
	} {
		svc, _ := build(t, c.opts)
		if _, err := svc.Check(context.Background(), c.raw, service.CarrierLink); connect.CodeOf(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
}
