// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"slices"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// A VCA status service signs the lists of an issuer whose key sits in a
// DPG, so the issuer keys do not verify the list. The issuer names the
// list address in the signed credential, and the service publishes its
// key set under the same address. The check then reads that key set.

// listKeys answers the issuer keys for the issuer and the service keys
// for the key set under the list address. It records each question.
func listKeys(t *testing.T, issuer, service builder, asked *[]string) KeyResolver {
	t.Helper()
	issuerSet, serviceSet := issuer.jwks(t), service.jwks(t)
	return func(_ context.Context, who, _ string) (jose.JWKS, error) {
		*asked = append(*asked, who)
		if who == "https://issuer.example" {
			return serviceSet, nil
		}
		return issuerSet, nil
	}
}

// TestStatusListSignedUnderItsAddress reads the key set under the list
// address when the issuer keys do not verify the list.
func TestStatusListSignedUnderItsAddress(t *testing.T) {
	issuer, service := newBuilder(t), newBuilder(t)
	var asked []string
	pc := base()
	pc.Keys = listKeys(t, issuer, service, &asked)
	pc.Status = bytesFetch(tokenDoc(t, service, 5, 1))
	got := only(t, status(context.Background(), pres(tokenCred(5)), pc))
	wantOutcome(t, got, Fail)
	if got.Detail != "the issuer set the status of the credential" || got.Evidence["signature"] != SignedByListKeys {
		t.Errorf("result = %+v", got)
	}
	if !slices.Equal(asked, []string{"did:web:issuer", "https://issuer.example"}) {
		t.Errorf("asked = %v", asked)
	}
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(6)), pc)), Pass)
}

// TestStatusListKeysNeedTheListAddress: a list address with no status
// segment has no key set of its own, and a list that no key set verifies
// fails.
func TestStatusListKeysNeedTheListAddress(t *testing.T) {
	issuer, service, stranger := newBuilder(t), newBuilder(t), newBuilder(t)
	var asked []string
	other := objectCred(vc.FormatSDJWT, map[string]any{
		"iss":    "did:web:issuer",
		"status": map[string]any{"status_list": map[string]any{"uri": "https://issuer.example/lists/1", "idx": float64(5)}},
	})
	pc := base()
	pc.Keys = listKeys(t, issuer, service, &asked)
	pc.Status = bytesFetch(tokenDoc(t, service, 5, 1))
	got := only(t, status(context.Background(), pres(other), pc))
	if got.Result != Fail || got.Detail != "the status list signature is not valid" {
		t.Errorf("a list with no key set of its own = %+v", got)
	}
	if !slices.Equal(asked, []string{"did:web:issuer"}) {
		t.Errorf("asked = %v", asked)
	}
	pc.Status = bytesFetch(tokenDoc(t, stranger, 5, 1))
	got = only(t, status(context.Background(), pres(tokenCred(5)), pc))
	if got.Result != Fail || got.Detail != "the status list signature is not valid" {
		t.Errorf("a list of a stranger = %+v", got)
	}
}

// TestStatusListKeysWhenTheIssuerHasNone: an issuer whose keys do not
// resolve still gets its list checked with the key set of the list.
func TestStatusListKeysWhenTheIssuerHasNone(t *testing.T) {
	service := newBuilder(t)
	serviceSet := service.jwks(t)
	pc := base()
	pc.Keys = func(_ context.Context, who, _ string) (jose.JWKS, error) {
		if who == "https://issuer.example" {
			return serviceSet, nil
		}
		return jose.JWKS{}, errNoKeys
	}
	pc.Status = bytesFetch(tokenDoc(t, service, 5, 1))
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(6)), pc)), Pass)
	pc.Keys = func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, errNoKeys }
	got := only(t, status(context.Background(), pres(tokenCred(6)), pc))
	if got.Result != Fail || got.Detail != "the status list keys are not available" {
		t.Errorf("no key set at all = %+v", got)
	}
}

// TestListBase finds the base address of a list at <base>/status/<id>.
func TestListBase(t *testing.T) {
	for uri, want := range map[string]string{
		"https://issuer.example/status-token/status/abc": "https://issuer.example/status-token",
		"http://localhost:8080/status/1":                 "http://localhost:8080",
		"https://issuer.example/status/1/extra":          "",
		"https://issuer.example/lists/1":                 "",
		"did:web:issuer.example/status/1":                "",
	} {
		got, ok := listBase(uri)
		if got != want || ok != (want != "") {
			t.Errorf("listBase(%q) = %q, %v, want %q", uri, got, ok, want)
		}
	}
}
