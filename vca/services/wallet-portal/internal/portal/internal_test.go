// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
)

// TestCardStatusWords checks the status word and tone of every state of
// a card.
func TestCardStatusWords(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	past, future := timestamppb.New(now.Add(-time.Hour)), timestamppb.New(now.Add(time.Hour))
	for want, card := range map[string]*walletportalv1.Card{
		"bad Revoked":        {Revocation: walletportalv1.Card_REVOCATION_STATE_REVOKED},
		"bad Expired":        {Validity: &commonv1.ValidityWindow{ValidUntil: past}},
		"warn Suspended":     {Revocation: walletportalv1.Card_REVOCATION_STATE_SUSPENDED},
		"warn Not yet valid": {Validity: &commonv1.ValidityWindow{ValidFrom: future}},
		"info Not checked":   {Revocation: walletportalv1.Card_REVOCATION_STATE_UNKNOWN},
		"ok Valid":           {Revocation: walletportalv1.Card_REVOCATION_STATE_NONE},
	} {
		status, word := cardStatus(card, now)
		if status+" "+word != want {
			t.Errorf("%s: got %s %s", want, status, word)
		}
	}
	if got := cardMeta(&walletportalv1.Card{}); got != "This credential names no end date." {
		t.Errorf("meta = %q", got)
	}
	if got := cardMeta(&walletportalv1.Card{ReceivedAt: timestamppb.New(now)}); got != "Received 19 Sep 2026" {
		t.Errorf("meta = %q", got)
	}
}

// TestSmallWords checks the words of the discover and present pages.
func TestSmallWords(t *testing.T) {
	for outcome, want := range map[trustv1.TrustLookupResponse_Outcome]string{
		trustv1.TrustLookupResponse_OUTCOME_TRUSTED:     "On the trust list",
		trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:   "Removed from the list",
		trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:     "Not on the list",
		trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE: "Trust not checked",
	} {
		if got := trustLine(outcome); got != want {
			t.Errorf("%v: %q", outcome, got)
		}
	}
	for result, want := range map[walletportalv1.PresentationRecord_Result]string{
		walletportalv1.PresentationRecord_RESULT_ACCEPTED: "ok Accepted",
		walletportalv1.PresentationRecord_RESULT_REJECTED: "bad Refused",
		walletportalv1.PresentationRecord_RESULT_DECLINED: "info Declined",
		walletportalv1.PresentationRecord_RESULT_FAILED:   "warn Not sent",
	} {
		if status, word := resultBadge(result); status+" "+word != want {
			t.Errorf("%v: %s %s", result, status, word)
		}
	}
	if got := matchName(&walletportalv1.Card{Title: "Licence"}); got != "Licence" {
		t.Errorf("match = %q", got)
	}
	if got := matchName(&walletportalv1.Card{Title: "Licence", Issuer: "did:web:x"}); got != "Licence from did:web:x" {
		t.Errorf("match = %q", got)
	}
	if linkText("openid4vp://x") != "openid4vp://x" || linkText("{\"a\":1}") != "" {
		t.Error("linkText keeps the wrong text")
	}
	o := &walletportalv1.Offering{Schema: &schemav1.PublicSchema{Id: "farmer",
		Formats: []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}, ConfigurationIds: map[string]string{"FORMAT_LDP_VC": "farmer_ldp"}}}
	if configurationOf(o) != "farmer_ldp" {
		t.Errorf("configuration = %q", configurationOf(o))
	}
	o.Schema.ConfigurationIds = nil
	if configurationOf(o) != "farmer" {
		t.Errorf("configuration = %q", configurationOf(o))
	}
	if unique([]string{"a", " a", "", "b"})[1] != "b" {
		t.Error("unique keeps a repeat")
	}
}
