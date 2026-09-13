// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// dated returns a credential with a validity window.
func dated(from, until string) Credential {
	obj := map[string]any{}
	if from != "" {
		obj["validFrom"] = from
	}
	if until != "" {
		obj["validUntil"] = until
	}
	return objectCred(vc.FormatJSONLD, obj)
}

func TestNotBefore(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		want Outcome
	}{
		{"no start", dated("", ""), Skip},
		{"already valid", dated("2026-01-01T00:00:00Z", ""), Pass},
		{"not yet valid", dated("2027-01-01T00:00:00Z", ""), Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantOutcome(t, only(t, notBefore(context.Background(), pres(tc.cred), base())), tc.want)
		})
	}
	wantOutcome(t, only(t, notBefore(context.Background(), Presentation{}, base())), Skip)
}

func TestExpiry(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		want Outcome
	}{
		{"no end", dated("", ""), Skip},
		{"not expired", dated("", "2027-01-01T00:00:00Z"), Pass},
		{"expired", dated("", "2025-01-01T00:00:00Z"), Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantOutcome(t, only(t, expiry(context.Background(), pres(tc.cred), base())), tc.want)
		})
	}
	wantOutcome(t, only(t, expiry(context.Background(), Presentation{}, base())), Skip)
}

func TestSkewAndAt(t *testing.T) {
	if got := (Context{}).Skew(); got != DefaultLeeway {
		t.Fatalf("want the default leeway, got %s", got)
	}
	if got := (Context{Leeway: time.Second}).Skew(); got != time.Second {
		t.Fatalf("want one second, got %s", got)
	}
	if (Context{}).At().IsZero() {
		t.Fatal("want the wall clock time")
	}
	if got := base().At(); !got.Equal(testNow) {
		t.Fatalf("want the fixed clock, got %s", got)
	}
}
