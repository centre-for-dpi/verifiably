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

// TestOid4vcHelpers pins the helpers of the OID4VC side of the wallet
// (ADR-062 decision 8): the offer and request checks and the form of
// each stored record.
func TestOid4vcHelpers(t *testing.T) {
	for uri, want := range map[string]bool{
		"openid-credential-offer://?credential_offer_uri=x": true, "https://wallet.example/?credential_offer=%7B%7D": true,
		"https://issuer.example/": false, "%": false,
	} {
		if isOid4vciOffer(uri) != want {
			t.Errorf("isOid4vciOffer(%q) != %v", uri, want)
		}
	}
	for uri, want := range map[string]string{
		"openid4vp://?request_uri=x":             "openid4vp://?request_uri=x",
		"haip://?request_uri=x":                  "haip://?request_uri=x",
		"https://verifier.example/request/1":     "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1",
		"https://verifier.example/?client_id=v1": "https://verifier.example/?client_id=v1",
		"https://verifier.example/?page=2":       "",
		"https://agent.example/?oob=abc":         "",
		"ftp://verifier.example/x":               "",
		"%":                                      "",
	} {
		if got, ok := oid4vpRequest(uri); got != want || ok != (want != "") {
			t.Errorf("oid4vpRequest(%q) = %q, %v", uri, got, ok)
		}
	}
	w3c := credebl.AgentStored{ID: "w-1", Type: credebl.RecordW3c}
	w3c.Instances = append(w3c.Instances, struct {
		SdJwt      string          `json:"compactSdJwtVc"`
		Mdoc       string          `json:"issuerSignedBase64Url"`
		Credential json.RawMessage `json:"credential"`
	}{Credential: json.RawMessage(`{"type":["VerifiableCredential","Licence"],"issuer":"did:web:ministry"}`)})
	if got := storedCredential(w3c); got.GetId() != "w3c:w-1" || got.GetType() != "Licence" {
		t.Errorf("w3c = %+v", got)
	}
	if got := storedCredential(credebl.AgentStored{ID: "w-2", Type: credebl.RecordW3c}); got.GetId() != "w3c:w-2" {
		t.Errorf("an empty w3c record = %+v", got)
	}
	vc := credebl.AgentStored{ID: "s-1", Type: credebl.RecordSdJwt, Tags: map[string]any{"vct": 7}}
	vc.Instances = append(vc.Instances, struct {
		SdJwt      string          `json:"compactSdJwtVc"`
		Mdoc       string          `json:"issuerSignedBase64Url"`
		Credential json.RawMessage `json:"credential"`
	}{SdJwt: "eyJ0eXAiOiJ2YytzZC1qd3QifQ.eyJpc3MiOiJodHRwczovL2kiLCJ2Y3QiOiJMaWNlbmNlIn0.c2ln~"})
	if got := storedCredential(vc); got.GetCredential().GetFormat().String() != "FORMAT_VC_SD_JWT" || got.GetIssuer() != "https://i" || got.GetType() != "Licence" {
		t.Errorf("vc+sd-jwt = %+v", got)
	}
	vc.Instances[0].SdJwt = "not a token"
	if got := storedCredential(vc); got.GetIssuer() != "" || got.GetType() != "" {
		t.Errorf("a bad token = %+v", got)
	}
}
