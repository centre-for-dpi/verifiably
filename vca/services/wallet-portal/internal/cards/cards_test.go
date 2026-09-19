// SPDX-License-Identifier: Apache-2.0

package cards_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func now() time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-09-19T00:00:00Z")
	return t
}

// held builds one wallet credential with a JSON-LD payload.
func held(id string, extra map[string]any) *backendv1.WalletCredential {
	doc := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "DriverLicence"},
		"issuer":            "did:web:issuer.example",
		"validFrom":         "2026-01-01T00:00:00Z",
		"validUntil":        "2027-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": "did:jwk:abc", "given_name": "Ada", "age": 36},
	}
	for k, v := range extra {
		doc[k] = v
	}
	raw, _ := json.Marshal(doc)
	return &backendv1.WalletCredential{
		Id:         id,
		Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_LDP_VC, Payload: raw},
		ReceivedAt: timestamppb.New(now()),
	}
}

// bitstringList returns a status list credential with index set.
func bitstringList(t *testing.T, index int) []byte {
	t.Helper()
	list := bitstring.New(0)
	if err := list.Set(index, true); err != nil {
		t.Fatal(err)
	}
	doc := bitstring.Credential("https://issuer.example/sl/1", "did:web:issuer.example",
		bitstring.Purpose("revocation"), list, now())
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func trusted(_ context.Context, _, _ string) (cards.Trust, error) {
	return cards.Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED, Name: "Road Agency"}, nil
}

func TestCardTrustedAndValid(t *testing.T) {
	b := cards.New(cards.Options{
		Trust: trusted,
		Display: func(context.Context, string, string) *schemav1.Display {
			return &schemav1.Display{Name: "Driver licence"}
		},
		Now: now,
	})
	card := b.Card(context.Background(), held("c1", nil))
	if card.GetTitle() != "Driver licence" {
		t.Fatalf("title = %q", card.GetTitle())
	}
	if card.GetType() != "DriverLicence" || card.GetIssuer() != "did:web:issuer.example" {
		t.Fatalf("card = %+v", card)
	}
	if card.GetClaims()["given_name"] != "Ada" || card.GetClaims()["age"] != "36" {
		t.Fatalf("claims = %v", card.GetClaims())
	}
	if card.GetValidity().GetValidUntil().AsTime().Year() != 2027 {
		t.Fatalf("validity = %v", card.GetValidity())
	}
	if card.GetRevocation() != walletportalv1.Card_REVOCATION_STATE_NONE {
		t.Fatalf("revocation = %v", card.GetRevocation())
	}
	if card.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatalf("trust = %v", card.GetTrust())
	}
	text := card.GetStatusText()
	for _, want := range []string{"no withdrawal list", "valid until 2027-01-01", "Road Agency is on the trust list"} {
		if !strings.Contains(text, want) {
			t.Fatalf("status text %q misses %q", text, want)
		}
	}
	if !cards.Usable(card, now()) {
		t.Fatal("want a usable card")
	}
	if got := cards.ClaimNames(card); len(got) != 2 || got[0] != "age" {
		t.Fatalf("claim names = %v", got)
	}
}

func TestCardRevoked(t *testing.T) {
	status := map[string]any{
		"type": "BitstringStatusListEntry", "statusListCredential": "https://issuer.example/sl/1",
		"statusListIndex": "7", "statusPurpose": "revocation",
	}
	b := cards.New(cards.Options{
		Trust: trusted,
		Status: func(_ context.Context, url string) ([]byte, error) {
			if url != "https://issuer.example/sl/1" {
				t.Fatalf("url = %q", url)
			}
			return bitstringList(t, 7), nil
		},
		Now: now,
	})
	card := b.Card(context.Background(), held("c2", map[string]any{"credentialStatus": status}))
	if card.GetRevocation() != walletportalv1.Card_REVOCATION_STATE_REVOKED {
		t.Fatalf("revocation = %v", card.GetRevocation())
	}
	if !strings.Contains(card.GetStatusText(), "withdrew this credential") {
		t.Fatalf("status text = %q", card.GetStatusText())
	}
	if cards.Usable(card, now()) {
		t.Fatal("want an unusable card")
	}
	if cards.RevocationWord(card.GetRevocation()) != "withdrawn" ||
		cards.RevocationStatus(card.GetRevocation()) != "bad" {
		t.Fatal("want the withdrawn words")
	}
}

func TestCardStatusNotSet(t *testing.T) {
	status := map[string]any{
		"type": "BitstringStatusListEntry", "statusListCredential": "https://issuer.example/sl/1",
		"statusListIndex": "3", "statusPurpose": "revocation",
	}
	b := cards.New(cards.Options{
		Status: func(context.Context, string) ([]byte, error) { return bitstringList(t, 9), nil },
		Now:    now,
	})
	card := b.Card(context.Background(), held("c3", map[string]any{"credentialStatus": status}))
	if card.GetRevocation() != walletportalv1.Card_REVOCATION_STATE_VALID {
		t.Fatalf("revocation = %v", card.GetRevocation())
	}
	if card.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE {
		t.Fatalf("trust = %v", card.GetTrust())
	}
	if !strings.Contains(card.GetStatusText(), "could not check the trust list") {
		t.Fatalf("status text = %q", card.GetStatusText())
	}
}

func TestCardStatusProblems(t *testing.T) {
	status := map[string]any{
		"type": "BitstringStatusListEntry", "statusListCredential": "https://issuer.example/sl/1",
		"statusListIndex": "3",
	}
	cases := map[string]cards.Fetcher{
		"no fetcher": nil,
		"fetch fails": func(context.Context, string) ([]byte, error) {
			return nil, errors.New("down")
		},
		"broken document": func(context.Context, string) ([]byte, error) {
			return []byte("{oops"), nil
		},
		"not a list": func(context.Context, string) ([]byte, error) {
			return []byte(`{"credentialSubject":{}}`), nil
		},
	}
	for name, fetch := range cases {
		b := cards.New(cards.Options{Status: fetch, Now: now})
		card := b.Card(context.Background(), held("c4", map[string]any{"credentialStatus": status}))
		if card.GetRevocation() != walletportalv1.Card_REVOCATION_STATE_UNKNOWN {
			t.Fatalf("%s: revocation = %v", name, card.GetRevocation())
		}
		if !strings.Contains(card.GetStatusText(), "could not read the withdrawal list") {
			t.Fatalf("%s: status text = %q", name, card.GetStatusText())
		}
	}
}

// tokenList returns a compact Status List Token with index set to value.
func tokenList(t *testing.T, index int, value uint8) []byte {
	t.Helper()
	list, err := token.New(2, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.Set(index, value); err != nil {
		t.Fatal(err)
	}
	claims := token.JWTClaims(token.Claims{
		Issuer: "did:web:issuer.example", Subject: "https://issuer.example/sl/2", IssuedAt: now(),
	}, list)
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(key, "k1", "statuslist+jwt", claims)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(compact)
}

func TestCardSuspendedByTokenList(t *testing.T) {
	status := map[string]any{"status_list": map[string]any{
		"uri": "https://issuer.example/sl/2", "idx": 4,
	}}
	b := cards.New(cards.Options{
		Status: func(context.Context, string) ([]byte, error) { return tokenList(t, 4, 2), nil },
		Now:    now,
	})
	card := b.Card(context.Background(), held("c11", map[string]any{"status": status}))
	if card.GetRevocation() != walletportalv1.Card_REVOCATION_STATE_SUSPENDED {
		t.Fatalf("revocation = %v", card.GetRevocation())
	}
}

func TestStatusValueTokenList(t *testing.T) {
	ref := delegation.StatusRef{Type: "TokenStatusList", URI: "u", Index: 2}
	if _, err := cards.StatusValue(ref, []byte("not-a-token")); err == nil {
		t.Fatal("want a parse error")
	}
	if _, err := cards.StatusValue(ref, []byte(`{"status_list":{"bits":1}}`)); err == nil {
		t.Fatal("want a list error")
	}
	short := delegation.StatusRef{Type: "BitstringStatusListEntry", URI: "u", Index: 1 << 30}
	if _, err := cards.StatusValue(short, bitstringList(t, 1)); err == nil {
		t.Fatal("want a length error")
	}
	shortToken := delegation.StatusRef{Type: "TokenStatusList", URI: "u", Index: 1 << 30}
	if _, err := cards.StatusValue(shortToken, tokenList(t, 1, 1)); err == nil {
		t.Fatal("want a token length error")
	}
	value, err := cards.StatusValue(delegation.StatusRef{Type: "TokenStatusList", URI: "u", Index: 1},
		tokenList(t, 1, 1))
	if err != nil || value != 1 {
		t.Fatalf("value = %d %v", value, err)
	}
}

func TestCardsAndUnreadableCredential(t *testing.T) {
	b := cards.New(cards.Options{Now: now})
	list := b.Cards(context.Background(), []*backendv1.WalletCredential{
		held("c5", nil),
		{Id: "c6", Credential: &commonv1.Credential{Payload: []byte("not a credential")}},
	})
	if len(list) != 2 {
		t.Fatalf("cards = %d", len(list))
	}
	if !strings.Contains(list[1].GetStatusText(), "cannot read this credential") {
		t.Fatalf("status text = %q", list[1].GetStatusText())
	}
	if list[1].GetTitle() != "" {
		t.Fatalf("title = %q", list[1].GetTitle())
	}
}

func TestBuilderDefaultsAndTrustErrors(t *testing.T) {
	b := cards.New(cards.Options{Trust: func(context.Context, string, string) (cards.Trust, error) {
		return cards.Trust{}, errors.New("down")
	}})
	card := b.Card(context.Background(), held("c7", nil))
	if card.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE {
		t.Fatalf("trust = %v", card.GetTrust())
	}
	unspecified := cards.New(cards.Options{Now: now, Trust: func(context.Context, string, string) (cards.Trust, error) {
		return cards.Trust{}, nil
	}})
	card = unspecified.Card(context.Background(), held("c8", nil))
	if card.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_UNKNOWN {
		t.Fatalf("trust = %v", card.GetTrust())
	}
	if !strings.Contains(card.GetStatusText(), "No trust list names The issuer") {
		t.Fatalf("status text = %q", card.GetStatusText())
	}
}

func TestStatusTextWindows(t *testing.T) {
	future := &walletportalv1.Card{
		Validity: &commonv1.ValidityWindow{ValidFrom: timestamppb.New(now().Add(48 * time.Hour))},
	}
	if !strings.Contains(cards.StatusText(future, now()), "starts on 2026-09-21") {
		t.Fatalf("text = %q", cards.StatusText(future, now()))
	}
	if cards.Usable(future, now()) {
		t.Fatal("want an unusable card")
	}
	past := &walletportalv1.Card{
		Validity: &commonv1.ValidityWindow{ValidUntil: timestamppb.New(now().Add(-48 * time.Hour))},
	}
	if !strings.Contains(cards.StatusText(past, now()), "ended on 2026-09-17") {
		t.Fatalf("text = %q", cards.StatusText(past, now()))
	}
	if cards.Usable(past, now()) {
		t.Fatal("want an ended card")
	}
	open := &walletportalv1.Card{
		Validity: &commonv1.ValidityWindow{ValidFrom: timestamppb.New(now().Add(-time.Hour))},
	}
	if !strings.Contains(cards.StatusText(open, now()), "names no end date") {
		t.Fatalf("text = %q", cards.StatusText(open, now()))
	}
}

func TestWordsAndStates(t *testing.T) {
	trustWords := map[trustv1.TrustLookupResponse_Outcome]string{
		trustv1.TrustLookupResponse_OUTCOME_TRUSTED:     "trusted",
		trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:   "not trusted",
		trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:     "not listed",
		trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE: "not checked",
		trustv1.TrustLookupResponse_Outcome(9):          "not checked",
	}
	for outcome, want := range trustWords {
		if got := cards.TrustWord(outcome); got != want {
			t.Fatalf("%v = %q, want %q", outcome, got, want)
		}
	}
	if cards.TrustStatus(trustv1.TrustLookupResponse_OUTCOME_TRUSTED) != "ok" ||
		cards.TrustStatus(trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED) != "bad" ||
		cards.TrustStatus(trustv1.TrustLookupResponse_OUTCOME_UNKNOWN) != "warn" {
		t.Fatal("want the trust badge statuses")
	}
	untrusted := &walletportalv1.Card{
		Trust: trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED, IssuerName: "Old Agency",
	}
	if !strings.Contains(cards.StatusText(untrusted, now()), "Old Agency is not on the trust list now") {
		t.Fatalf("text = %q", cards.StatusText(untrusted, now()))
	}
	states := map[walletportalv1.Card_RevocationState]string{
		walletportalv1.Card_REVOCATION_STATE_VALID:     "in force",
		walletportalv1.Card_REVOCATION_STATE_SUSPENDED: "stopped",
		walletportalv1.Card_REVOCATION_STATE_REVOKED:   "withdrawn",
		walletportalv1.Card_REVOCATION_STATE_NONE:      "no list",
		walletportalv1.Card_RevocationState(9):         "not checked",
	}
	for state, want := range states {
		if got := cards.RevocationWord(state); got != want {
			t.Fatalf("%v = %q, want %q", state, got, want)
		}
	}
	if cards.RevocationStatus(walletportalv1.Card_REVOCATION_STATE_NONE) != "ok" ||
		cards.RevocationStatus(walletportalv1.Card_REVOCATION_STATE_SUSPENDED) != "warn" {
		t.Fatal("want the revocation badge statuses")
	}
	suspended := &walletportalv1.Card{Revocation: walletportalv1.Card_REVOCATION_STATE_SUSPENDED}
	if !strings.Contains(cards.StatusText(suspended, now()), "stopped this credential") {
		t.Fatalf("text = %q", cards.StatusText(suspended, now()))
	}
	if cards.Usable(suspended, now()) {
		t.Fatal("want an unusable card")
	}
	valid := &walletportalv1.Card{Revocation: walletportalv1.Card_REVOCATION_STATE_VALID}
	if !strings.Contains(cards.StatusText(valid, now()), "still supports") {
		t.Fatalf("text = %q", cards.StatusText(valid, now()))
	}
	odd := &walletportalv1.Card{Revocation: walletportalv1.Card_RevocationState(9),
		Trust: trustv1.TrustLookupResponse_Outcome(9)}
	if !strings.Contains(cards.StatusText(odd, now()), "could not read") {
		t.Fatalf("text = %q", cards.StatusText(odd, now()))
	}
}

func TestStateOf(t *testing.T) {
	if cards.StateOf(0, "revocation") != walletportalv1.Card_REVOCATION_STATE_VALID {
		t.Fatal("want valid")
	}
	if cards.StateOf(2, "revocation") != walletportalv1.Card_REVOCATION_STATE_SUSPENDED {
		t.Fatal("want suspended")
	}
	if cards.StateOf(1, "suspension") != walletportalv1.Card_REVOCATION_STATE_SUSPENDED {
		t.Fatal("want suspended by purpose")
	}
	if cards.StateOf(1, "revocation") != walletportalv1.Card_REVOCATION_STATE_REVOKED {
		t.Fatal("want revoked")
	}
}

func TestCardKeepsTypeAndTitleFallback(t *testing.T) {
	b := cards.New(cards.Options{Now: now, Display: func(context.Context, string, string) *schemav1.Display {
		return nil
	}})
	given := held("c9", nil)
	given.Type = "Licence"
	given.Issuer = "https://issuer.example"
	card := b.Card(context.Background(), given)
	if card.GetType() != "Licence" || card.GetIssuer() != "https://issuer.example" {
		t.Fatalf("card = %+v", card)
	}
	if card.GetTitle() != "Licence" {
		t.Fatalf("title = %q", card.GetTitle())
	}
	bare := &backendv1.WalletCredential{
		Id: "c10", Credential: &commonv1.Credential{Payload: []byte(`{"hello":"there"}`)},
	}
	if got := b.Card(context.Background(), bare).GetTitle(); got != "Credential" {
		t.Fatalf("title = %q", got)
	}
}
