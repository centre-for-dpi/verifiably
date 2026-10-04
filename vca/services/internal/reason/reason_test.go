// SPDX-License-Identifier: Apache-2.0

package reason_test

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/services/internal/reason"
)

func TestOf(t *testing.T) {
	refusal := []connect.Code{connect.CodeInvalidArgument, connect.CodeFailedPrecondition}
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"prefixes go", connect.NewError(connect.CodeInvalidArgument, errors.New("service: store: the key does not match")), "The key does not match."},
		{"a sentence keeps its stop", connect.NewError(connect.CodeFailedPrecondition, errors.New("Pick a method.")), "Pick a method."},
		{"a head with capitals stays", connect.NewError(connect.CodeInvalidArgument, errors.New("DID: bad value")), "DID: bad value."},
		{"wrapped", fmt.Errorf("call: %w", connect.NewError(connect.CodeInvalidArgument, errors.New("no key"))), "No key."},
		{"another code", connect.NewError(connect.CodeInternal, errors.New("pq: refused")), ""},
		{"no message", connect.NewError(connect.CodeInvalidArgument, errors.New(" ")), ""},
		{"empty head", connect.NewError(connect.CodeInvalidArgument, errors.New(": x")), ": x."},
		{"not Connect", errors.New("plain"), ""},
	} {
		if got := reason.Of(c.err, refusal...); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
