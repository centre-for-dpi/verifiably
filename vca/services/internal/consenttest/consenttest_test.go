// SPDX-License-Identifier: Apache-2.0

package consenttest_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/consenttest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/disclosure"
)

// recorder keeps the findings of Run.
type recorder struct{ errs []string }

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

// wallet is a test double that sends the claims it holds.
type wallet struct {
	holds []string
	sent  []string
	// refuse makes the adapter refuse an unconsented claim.
	refuse bool
	// report overrides the shared claims the adapter reports.
	report []string
	// fail fails every answer with the error.
	fail error
}

func (w *wallet) present(_ context.Context, req *backendv1.PresentRequest) (*backendv1.PresentResponse, error) {
	if w.fail != nil {
		return nil, w.fail
	}
	if missing := disclosure.Missing(w.holds, req.GetDisclosedClaims()); w.refuse && len(missing) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(disclosure.Refusal(missing)))
	}
	w.sent = slices.Clone(w.holds)
	shared := w.holds
	if w.report != nil {
		shared = w.report
	}
	return &backendv1.PresentResponse{Accepted: true, SharedClaims: shared}, nil
}

func (w *wallet) exchange() consenttest.Exchange {
	return consenttest.Exchange{
		Present: w.present,
		Narrow:  &backendv1.PresentRequest{DisclosedClaims: []string{"a"}},
		Full:    &backendv1.PresentRequest{DisclosedClaims: []string{"a", "b"}},
		Sent:    func() []string { return w.sent },
		Reset:   func() { w.sent = nil },
	}
}

// TestRunPassesAnHonestAdapter accepts a refusal of the narrow answer and
// shared claims that name what left.
func TestRunPassesAnHonestAdapter(t *testing.T) {
	r := &recorder{}
	consenttest.Run(r, (&wallet{holds: []string{"a", "b"}, refuse: true}).exchange())
	if len(r.errs) > 0 {
		t.Fatalf("an honest adapter got %v", r.errs)
	}
}

// TestRunCatchesEachBreach names each way an adapter breaks the rule.
func TestRunCatchesEachBreach(t *testing.T) {
	for name, tc := range map[string]struct {
		w    *wallet
		want string
	}{
		"sends without consent": {&wallet{holds: []string{"a", "b"}}, "without consent"},
		"reports the ticks":     {&wallet{holds: []string{"a", "b"}, refuse: true, report: []string{"a"}}, "reports"},
		"fails otherwise":       {&wallet{fail: connect.NewError(connect.CodeUnavailable, errors.New("down"))}, "want failed_precondition"},
		"sends nothing":         {&wallet{holds: nil}, "sent no claim"},
	} {
		r := &recorder{}
		consenttest.Run(r, tc.w.exchange())
		if !strings.Contains(strings.Join(r.errs, "|"), tc.want) {
			t.Errorf("%s: findings %v, want %q", name, r.errs, tc.want)
		}
	}
	// An adapter that refuses yet lets the wallet send breaks the rule.
	w := &wallet{holds: []string{"a", "b"}, refuse: true}
	ex := w.exchange()
	ex.Sent = func() []string { return w.holds }
	r := &recorder{}
	consenttest.Run(r, ex)
	if !strings.Contains(strings.Join(r.errs, "|"), "yet the wallet sent") {
		t.Errorf("findings %v", r.errs)
	}
}
