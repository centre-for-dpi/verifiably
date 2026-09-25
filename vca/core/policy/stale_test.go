// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// errStaleCopy is what a trust cache port returns for material older than
// the offline window (ADR-041 decisions 3 and 4).
var errStaleCopy = fmt.Errorf("cache: %w", ErrStale)

func TestStatusStaleFailsInEveryMode(t *testing.T) {
	for _, mode := range []string{FailOpen, FailClosed} {
		pc := base()
		pc.Params = map[string]string{ParamFailMode: mode}
		pc.Status = func(context.Context, string) ([]byte, error) { return nil, errStaleCopy }
		got := only(t, status(context.Background(), pres(bitstringCred(1)), pc))
		wantOutcome(t, got, Fail)
		if got.Detail != staleStatusDetail || got.Evidence["stale"] != "true" {
			t.Fatalf("mode %s: want the stale detail and evidence, got %q %v", mode, got.Detail, got.Evidence)
		}
	}
}

func TestSignatureStaleKeysFail(t *testing.T) {
	b := newBuilder(t)
	pc := base()
	pc.Keys = func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, errStaleCopy }
	got := only(t, signature(context.Background(), pres(b.jwtCred(t, map[string]any{"iss": "did:web:issuer"})), pc))
	wantOutcome(t, got, Fail)
	if got.Detail != staleKeysDetail || got.Evidence["stale"] != "true" {
		t.Fatalf("want the stale detail and evidence, got %q %v", got.Detail, got.Evidence)
	}
}

func TestTrustStaleListFails(t *testing.T) {
	pc := base()
	pc.Trust = func(context.Context, string, string) (Trust, error) { return Trust{}, errStaleCopy }
	got := trustChain(context.Background(), pres(objectCred(vc.FormatJSONLD, map[string]any{"issuer": "did:web:a"})), pc)
	wantOutcome(t, got[0], Fail)
	if got[0].Detail != staleTrustDetail || got[0].Evidence["stale"] != "true" {
		t.Fatalf("want the stale detail and evidence, got %q %v", got[0].Detail, got[0].Evidence)
	}
}

func TestTrustEvidenceNamesTheRegistry(t *testing.T) {
	pc := base()
	pc.Trust = func(context.Context, string, string) (Trust, error) {
		return Trust{Trusted: true, DisplayName: "Ministry", Registry: "National registry"}, nil
	}
	got := trustChain(context.Background(), pres(objectCred(vc.FormatJSONLD, map[string]any{"issuer": "did:web:a"})), pc)
	wantOutcome(t, got[0], Pass)
	if got[0].Evidence["registry"] != "National registry" {
		t.Fatalf("want the registry as evidence, got %v", got[0].Evidence)
	}
}
