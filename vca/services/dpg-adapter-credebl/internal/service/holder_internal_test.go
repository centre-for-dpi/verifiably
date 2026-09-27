// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// TestHolderHelpers pins the helpers of the holder wallet: the form of
// a stored W3C credential, the invitation check, and the poll.
func TestHolderHelpers(t *testing.T) {
	jwt := credebl.AgentW3c{ID: "w-1", Legacy: json.RawMessage(`"eyJhbGciOiJFZERTQSJ9.e30.c2ln"`)}
	if got := w3cCredential(jwt); got.GetCredential().GetFormat().String() != "FORMAT_JWT_VC_JSON" || string(got.GetCredential().GetPayload()) != "eyJhbGciOiJFZERTQSJ9.e30.c2ln" {
		t.Errorf("jwt = %+v", got)
	}
	object := credebl.AgentW3c{ID: "w-2", Legacy: json.RawMessage(`{"type":["VerifiableCredential","Licence"],"issuer":{"id":"did:web:ministry"}}`)}
	if got := w3cCredential(object); got.GetIssuer() != "did:web:ministry" || got.GetType() != "Licence" {
		t.Errorf("object issuer = %+v", got)
	}
	for uri, want := range map[string]bool{
		"didcomm://invite?oob=abc": true, "https://agent/?c_i=abc": true, "http://agent?d_m=abc": true,
		"https://agent/": false, "ftp://agent?oob=abc": false, "%": false,
	} {
		if isInvitation(uri) != want {
			t.Errorf("isInvitation(%q) != %v", uri, want)
		}
	}
	s := &Service{pollAttempts: 3, pollInterval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if _, err := s.poll(ctx, func() (bool, error) { calls++; return false, nil }); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Errorf("a cancelled poll: %v after %d calls", err, calls)
	}
}
