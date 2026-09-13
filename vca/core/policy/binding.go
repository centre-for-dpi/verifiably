// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// audience checks that the presentation names this verifier
// (ADR-024 decision 2).
func audience(_ context.Context, p Presentation, pc Context) []CheckResult {
	return echoed(p, NameAudience, "audience", pc.Audience, p.Audience, "aud")
}

// nonce checks that the presentation echoes the nonce of the request.
func nonce(_ context.Context, p Presentation, pc Context) []CheckResult {
	return echoed(p, NameNonce, "nonce", pc.Nonce, p.Nonce, "nonce")
}

// echoed compares an expected value with the value the wallet echoed.
// A key binding JWT carries the value per credential. A carrier without
// key binding carries it once for the presentation.
func echoed(p Presentation, name, label, want, carried, claim string) []CheckResult {
	if want == "" {
		return []CheckResult{result(name, Skip, WholePresentation, "the verifier expects no "+label, nil)}
	}
	var out []CheckResult
	for i, c := range p.Credentials {
		got, ok := kbClaim(c, claim)
		if !ok {
			continue
		}
		out = append(out, compare(name, label, i, want, got))
	}
	if len(out) > 0 {
		return out
	}
	if carried == "" {
		return []CheckResult{result(name, Skip, WholePresentation, "the presentation carries no "+label, nil)}
	}
	return []CheckResult{compare(name, label, WholePresentation, want, carried)}
}

// compare returns PASS when got equals want.
func compare(name, label string, index int, want, got string) CheckResult {
	ev := map[string]string{"expected": want, "presented": got}
	if want == got {
		return result(name, Pass, index, "the presentation names the expected "+label, ev)
	}
	return result(name, Fail, index, "the presentation names another "+label, ev)
}

// kbClaim reads one string claim of the key binding JWT of c. The
// signature of that JWT is the work of the key binding check.
func kbClaim(c Credential, name string) (string, bool) {
	if c.Format != vc.FormatSDJWT {
		return "", false
	}
	pres, err := sdjwt.Parse(c.Token)
	if err != nil || pres.KeyBindingJWT == "" {
		return "", false
	}
	payload, err := jose.PeekPayload(pres.KeyBindingJWT)
	if err != nil {
		return "", false
	}
	v, ok := payload[name].(string)
	return v, ok
}
