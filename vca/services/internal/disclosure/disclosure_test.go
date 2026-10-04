// SPDX-License-Identifier: Apache-2.0

package disclosure_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/disclosure"
)

func TestMissing(t *testing.T) {
	for _, tc := range []struct {
		sent, consented, want []string
	}{
		{[]string{"fullName", "city"}, []string{"fullName", "city"}, nil},
		{[]string{"fullName", "city"}, []string{"fullName"}, []string{"city"}},
		{[]string{"address.city"}, []string{"city"}, nil},
		{[]string{"city"}, []string{"address.city"}, nil},
		{[]string{"a", "b"}, []string{disclosure.Whole}, nil},
		{[]string{disclosure.Whole}, []string{"a"}, []string{disclosure.Whole}},
		{nil, nil, nil},
	} {
		if got := disclosure.Missing(tc.sent, tc.consented); !slices.Equal(got, tc.want) {
			t.Errorf("Missing(%v, %v) = %v, want %v", tc.sent, tc.consented, got, tc.want)
		}
	}
}

func TestRefusalNamesTheClaims(t *testing.T) {
	if got := disclosure.Refusal([]string{"a", "b"}); !strings.Contains(got, "a, b") || !strings.Contains(got, "decline") {
		t.Fatalf("refusal = %q", got)
	}
}
