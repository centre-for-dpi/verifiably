// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"time"
)

// notBefore checks that every credential is already valid.
func notBefore(_ context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameNotBefore)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	now, skew := pc.At(), pc.Skew()
	for i, c := range p.Credentials {
		start, _ := c.VC.TemporalBounds()
		switch {
		case start.IsZero():
			out = append(out, result(NameNotBefore, Skip, i, "the credential names no start of validity", nil))
		case now.Add(skew).Before(start):
			out = append(out, result(NameNotBefore, Fail, i, "the credential is not valid yet", stamp(start)))
		default:
			out = append(out, result(NameNotBefore, Pass, i, "the credential is already valid", stamp(start)))
		}
	}
	return out
}

// expiry checks that no credential is expired.
func expiry(_ context.Context, p Presentation, pc Context) []CheckResult {
	if len(p.Credentials) == 0 {
		return noCredentials(NameExpiry)
	}
	out := make([]CheckResult, 0, len(p.Credentials))
	now, skew := pc.At(), pc.Skew()
	for i, c := range p.Credentials {
		_, end := c.VC.TemporalBounds()
		switch {
		case end.IsZero():
			out = append(out, result(NameExpiry, Skip, i, "the credential names no end of validity", nil))
		case now.After(end.Add(skew)):
			out = append(out, result(NameExpiry, Fail, i, "the credential is expired", stamp(end)))
		default:
			out = append(out, result(NameExpiry, Pass, i, "the credential is not expired", stamp(end)))
		}
	}
	return out
}

// stamp returns the evidence of a temporal check.
func stamp(t time.Time) map[string]string {
	return map[string]string{"time": t.UTC().Format(time.RFC3339)}
}
