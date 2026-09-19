// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

const listURL = "https://issuer.example/status/1"

// bitstringCred returns a credential with a Bitstring Status List entry.
func bitstringCred(index int) Credential {
	return objectCred(vc.FormatJSONLD, map[string]any{
		"issuer":           "did:web:issuer",
		"credentialStatus": bitstring.Entry(listURL, index, bitstring.Revocation),
	})
}

// bitstringDoc returns a status list credential with one bit set.
func bitstringDoc(t *testing.T, set int) []byte {
	t.Helper()
	l := bitstring.New(bitstring.MinSize)
	if set >= 0 {
		if err := l.Set(set, true); err != nil {
			t.Fatal(err)
		}
	}
	return jsonBytes(t, bitstring.Credential(listURL, "did:web:issuer", bitstring.Revocation, l, testNow))
}

// tokenCred returns a credential with a Token Status List reference.
func tokenCred(index int) Credential {
	return objectCred(vc.FormatSDJWT, map[string]any{
		"iss":    "did:web:issuer",
		"status": map[string]any{"status_list": map[string]any{"uri": listURL, "idx": float64(index)}},
	})
}

// tokenDoc returns a signed Status List Token.
func tokenDoc(t *testing.T, b builder, set int, value uint8) []byte {
	t.Helper()
	l, lErr := token.New(1, bitstring.MinSize)
	if lErr != nil {
		t.Fatal(lErr)
	}
	if err := l.Set(set, value); err != nil {
		t.Fatal(err)
	}
	claims := token.JWTClaims(token.Claims{
		Issuer: "did:web:issuer", Subject: listURL, IssuedAt: testNow, TTL: time.Hour,
	}, l)
	tok, err := jose.Sign(b.issuerKey, "issuer-key", token.TypeJWT, claims)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

func TestStatusNoCredentials(t *testing.T) {
	wantOutcome(t, only(t, status(context.Background(), Presentation{}, base())), Skip)
}

func TestStatusNoEntry(t *testing.T) {
	got := only(t, status(context.Background(), pres(objectCred(vc.FormatJSONLD, nil)), base()))
	wantOutcome(t, got, Skip)
}

func TestStatusBitstring(t *testing.T) {
	pc := base()
	pc.Status = bytesFetch(bitstringDoc(t, 7))
	wantOutcome(t, only(t, status(context.Background(), pres(bitstringCred(3)), pc)), Pass)
	got := only(t, status(context.Background(), pres(bitstringCred(7)), pc))
	wantOutcome(t, got, Fail)
	if got.Evidence["signature"] != "not checked" {
		t.Fatalf("want the signature evidence, got %v", got.Evidence)
	}
}

func TestStatusToken(t *testing.T) {
	b := newBuilder(t)
	pc := base()
	pc.Keys = b.keys(t)
	pc.Status = bytesFetch(tokenDoc(t, b, 5, 1))
	got := only(t, status(context.Background(), pres(tokenCred(5)), pc))
	wantOutcome(t, got, Fail)
	if got.Evidence["signature"] != "valid" {
		t.Fatalf("want a checked signature, got %v", got.Evidence)
	}
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(6)), pc)), Pass)
}

func TestStatusFailModes(t *testing.T) {
	open := base()
	open.Params = map[string]string{ParamFailMode: "fail-open"}
	open.Status = failFetch
	wantOutcome(t, only(t, status(context.Background(), pres(bitstringCred(1)), open)), Error)

	closed := base()
	closed.Status = failFetch
	wantOutcome(t, only(t, status(context.Background(), pres(bitstringCred(1)), closed)), Fail)

	none := base()
	wantOutcome(t, only(t, status(context.Background(), pres(bitstringCred(1)), none)), Fail)
}

func TestStatusBadDocuments(t *testing.T) {
	b := newBuilder(t)
	cases := []struct {
		name string
		doc  []byte
		cred Credential
		pc   Context
	}{
		{"broken json", []byte("{oops"), bitstringCred(1), base()},
		{"not a credential", []byte(`{"hello":"world"}`), bitstringCred(1), base()},
		{"index too high", bitstringDoc(t, 1), bitstringCred(bitstring.MinSize + 1), base()},
		{"not a token", []byte("not.a.token"), tokenCred(1), base()},
		{"token index too high", tokenDoc(t, b, 1, 1), tokenCred(bitstring.MinSize + 1), base()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := tc.pc
			pc.Status = bytesFetch(tc.doc)
			wantOutcome(t, only(t, status(context.Background(), pres(tc.cred), pc)), Fail)
		})
	}
}

func TestStatusSignatureProblems(t *testing.T) {
	b, other := newBuilder(t), newBuilder(t)
	doc := tokenDoc(t, b, 1, 1)

	wrongKey := base()
	wrongKey.Keys = other.keys(t)
	wrongKey.Status = bytesFetch(doc)
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(1)), wrongKey)), Fail)

	noKeys := base()
	noKeys.Keys = func(context.Context, string, string) (jose.JWKS, error) { return jose.JWKS{}, errNoKeys }
	noKeys.Status = bytesFetch(doc)
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(1)), noKeys)), Fail)

	badHeader := base()
	badHeader.Keys = b.keys(t)
	badHeader.Status = bytesFetch([]byte("not-a-jws"))
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(1)), badHeader)), Fail)
}

func TestStatusTokenPayloadNotAnObject(t *testing.T) {
	pc := base()
	pc.Status = bytesFetch([]byte("aGVhZGVy.bm90LWpzb24.c2ln"))
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(1)), pc)), Fail)
}

func TestFailClosedModes(t *testing.T) {
	for _, mode := range []string{"", FailClosed, "fail-closed", "anything"} {
		if !failClosed(mode) {
			t.Fatalf("want fail closed for %q", mode)
		}
	}
	for _, mode := range []string{FailOpen, "fail-open", " OPEN "} {
		if failClosed(mode) {
			t.Fatalf("want fail open for %q", mode)
		}
	}
}

func TestParamFallback(t *testing.T) {
	pc := Context{Params: map[string]string{"a": "b"}}
	if got := pc.Param("a", "z"); got != "b" {
		t.Fatalf("want b, got %s", got)
	}
	if got := pc.Param("c", "z"); got != "z" {
		t.Fatalf("want the fallback, got %s", got)
	}
}

func TestStatusTokenNotAStatusList(t *testing.T) {
	b := newBuilder(t)
	tok, err := jose.Sign(b.issuerKey, "issuer-key", token.TypeJWT, map[string]any{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	pc := base()
	pc.Status = bytesFetch([]byte(tok))
	wantOutcome(t, only(t, status(context.Background(), pres(tokenCred(1)), pc)), Fail)
}
