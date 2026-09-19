// SPDX-License-Identifier: Apache-2.0

package anyval

import (
	"errors"
	"testing"
)

func TestAs(t *testing.T) {
	if got := As[string](any("a")); got != "a" {
		t.Fatalf("As = %q", got)
	}
	if got := As[string](any(1)); got != "" {
		t.Fatalf("As of the wrong type = %q", got)
	}
	if got := As[map[string]any](nil); got != nil {
		t.Fatalf("As of nil = %v", got)
	}
}

func TestOrZero(t *testing.T) {
	if got := OrZero(7, nil); got != 7 {
		t.Fatalf("OrZero = %d", got)
	}
	if got := OrZero(7, errors.New("boom")); got != 0 {
		t.Fatalf("OrZero with an error = %d", got)
	}
}

func TestMust(t *testing.T) {
	if got := Must(7, nil); got != 7 {
		t.Fatalf("Must = %d", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Must must panic on an error")
		}
	}()
	Must(7, errors.New("boom"))
}

func TestMustDo(t *testing.T) {
	MustDo(nil)
	defer func() {
		if recover() == nil {
			t.Fatal("MustDo must panic on an error")
		}
	}()
	MustDo(errors.New("boom"))
}

type failingCloser struct{}

func (failingCloser) Close() error { return errors.New("boom") }

func TestClose(t *testing.T) {
	Close(failingCloser{})
}
