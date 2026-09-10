package handlers

import (
	"errors"
	"fmt"
	"testing"
)

// This file covers the small error-handling and formatting paths introduced by
// the lint pass, so the gate's new-code coverage measures tested behaviour
// rather than untested defensive branches.

// ── isRevocationError ────────────────────────────────────────────────────────
//
// The handler layer stays adapter-neutral: it does not import the walt.id
// package, so the contract with the adapters is the surface text of the error,
// probed through errors.As rather than a bare type assertion. The errors.As
// form matters because adapters wrap — a `fmt.Errorf("%w", …)` around the
// revocation error used to defeat the old assertion silently, turning a revoked
// credential into a generic failure toast.

type wrappedErr struct{ inner error }

func (w wrappedErr) Error() string { return "adapter: " + w.inner.Error() }
func (w wrappedErr) Unwrap() error { return w.inner }

func TestIsRevocationError(t *testing.T) {
	revoked := errors.New("credential has been revoked by the issuer")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated", errors.New("connection refused"), false},
		{"direct", revoked, true},
		{"wrapped once", fmt.Errorf("verify: %w", revoked), true},
		{"wrapped in a custom type", wrappedErr{inner: revoked}, true},
		{"wrapped twice", fmt.Errorf("outer: %w", wrappedErr{inner: revoked}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRevocationError(tt.err); got != tt.want {
				t.Errorf("isRevocationError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ── deriveTitleFromPath ──────────────────────────────────────────────────────
//
// The docs TOC falls back to the file path when a markdown file has no H1.
// Title-casing goes through golang.org/x/text/cases because strings.Title is
// deprecated and mishandles Unicode word boundaries — this repo's docs tree
// carries Spanish filenames, so that is not hypothetical.

func TestDeriveTitleFromPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"README.md", "README"},
		{"testdata/bulk-issuance/README.md", "Testdata / Bulk Issuance / README"},
		{"docs/k8s/values-schema.md", "Docs / K8s / Values Schema"},
		{"docs/dpg/inji_certify_preauth.md", "Docs / Dpg / Inji Certify Preauth"},
		{"emisión-federada.md", "Emisión Federada"},
	}
	for _, tt := range tests {
		if got := deriveTitleFromPath(tt.in); got != tt.want {
			t.Errorf("deriveTitleFromPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
