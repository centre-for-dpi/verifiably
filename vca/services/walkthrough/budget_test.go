// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"testing"
	"time"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// TestTheWalkDeadlineStartsAfterTheBuild: the walk builds the commands
// of the services first. Under the race detector and a loaded machine
// the build takes most of a minute. A deadline that started before the
// build then ended during the walk: it stopped the services in the
// middle of a request, and the proxy of a pair read an unexpected EOF.
// The context of the walk starts once the build is done, so the walk
// gets its whole time.
func TestTheWalkDeadlineStartsAfterTheBuild(t *testing.T) {
	w := newWalk(t, configv1.Dpg_DPG_WALTID, "walt.id Community Stack", nil)
	if w.ctx != nil {
		t.Fatal("the walk holds a context before it begins")
	}
	built := time.Now()
	cancel := w.begin(2 * budget)
	defer cancel()
	deadline, ok := w.ctx.Deadline()
	if !ok || deadline.Before(built.Add(2*budget)) {
		t.Fatalf("the walk ends at %v, before %s after the build", deadline, 2*budget)
	}
	for _, b := range []*browser{w.staff, w.citizen, w.checker, w.operator} {
		if b == nil || b.ctx != w.ctx {
			t.Fatal("a browser of the walk does not use the context of the walk")
		}
	}
}
