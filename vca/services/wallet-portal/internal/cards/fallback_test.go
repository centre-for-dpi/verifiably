// SPDX-License-Identifier: Apache-2.0

package cards_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
)

// midCapital finds a word with a capital first letter after the first
// word of a sentence.
var midCapital = regexp.MustCompile(`\S\s+([A-Z][a-z]+)`)

// TestTrustSentencesKeepTheFallbackInLowerCase: an issuer with no name
// on the trust list reads as "the issuer" in the middle of a sentence,
// and as "The issuer" only at its start. Every outcome of the message
// family passes.
func TestTrustSentencesKeepTheFallbackInLowerCase(t *testing.T) {
	outcomes := []trustv1.TrustLookupResponse_Outcome{
		trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED, trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
		trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED, trustv1.TrustLookupResponse_OUTCOME_UNKNOWN,
		trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE,
	}
	for _, outcome := range outcomes {
		b := cards.New(cards.Options{Now: now, Trust: func(context.Context, string, string) (cards.Trust, error) {
			return cards.Trust{Outcome: outcome}, nil
		}})
		text := b.Card(context.Background(), held("c-"+outcome.String(), nil)).GetStatusText()
		for _, sentence := range strings.Split(text, ". ") {
			if m := midCapital.FindStringSubmatch(sentence); m != nil {
				t.Errorf("%v: %q holds %q in the middle of a sentence", outcome, sentence, m[1])
			}
		}
	}
	unknown := cards.New(cards.Options{Now: now, Trust: func(context.Context, string, string) (cards.Trust, error) {
		return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_UNKNOWN}, nil
	}})
	if text := unknown.Card(context.Background(), held("c-unknown", nil)).GetStatusText(); !strings.Contains(text, "No trust list names the issuer.") {
		t.Errorf("status text = %q", text)
	}
}
