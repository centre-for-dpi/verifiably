// SPDX-License-Identifier: Apache-2.0

// Package cards builds the card of one credential (ADR-021 decision 6).
// A card carries the issuer trust status, the validity window, and the
// revocation state. It also carries one status line in plain language,
// so a citizen reads the state without a glossary (ADR-028).
//
// The package holds the decoding and the wording. The two side effects,
// the trust lookup and the status list fetch, come in as function
// values. A test injects a fake for each one.
package cards

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
)

// Trust is the trust outcome of one issuer, with its display name.
type Trust struct {
	// Outcome is the answer of the trust registry.
	Outcome trustv1.TrustLookupResponse_Outcome
	// Name is the display name of the issuer, when the list has one.
	Name string
}

// TrustLookup asks the trust registry about one issuer
// (ADR-011 decision 7).
type TrustLookup func(ctx context.Context, issuer, credentialType string) (Trust, error)

// Fetcher reads one status list document. The caller wraps it with a
// cache (ADR-021 decision 6).
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Display returns the display metadata of one credential type, when the
// catalogue knows it.
type Display func(ctx context.Context, issuer, credentialType string) *schemav1.Display

// Options configure a Builder.
type Options struct {
	// Trust asks the trust registry. Nil makes every outcome
	// unavailable.
	Trust TrustLookup
	// Status reads a status list. Nil makes every revocation state
	// unknown.
	Status Fetcher
	// Display returns the card metadata of a type. Nil leaves it empty.
	Display Display
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Builder makes cards.
type Builder struct {
	opts Options
}

// New returns a builder.
func New(opts Options) *Builder {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Builder{opts: opts}
}

// Card builds the card of one wallet credential. It never fails: a
// credential the wallet cannot decode still gets a card that says so.
func (b *Builder) Card(ctx context.Context, held *backendv1.WalletCredential) *walletportalv1.Card {
	payload := held.GetCredential().GetPayload()
	card := &walletportalv1.Card{
		Id:         held.GetId(),
		Type:       held.GetType(),
		Format:     held.GetCredential().GetFormat(),
		Issuer:     held.GetIssuer(),
		ReceivedAt: held.GetReceivedAt(),
		Claims:     map[string]string{},
		Trust:      trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE,
		Revocation: walletportalv1.Card_REVOCATION_STATE_UNKNOWN,
	}
	if len(payload) == 0 && held.GetType() != "" {
		// Some stack wallets list names only. The card names the type
		// and the issuer and points at the document.
		card.Title = vc.TypeTitle(held.GetType())
		card.IssuerName = held.GetIssuer()
		card.StatusText = "The wallet of the stack keeps this credential. Open its document to read what it says."
		return card
	}
	parsed, err := vc.Parse(payload)
	if err != nil {
		card.StatusText = "The wallet cannot read this credential. Ask the issuer for a new one."
		return card
	}
	if card.GetType() == "" {
		card.Type = parsed.PrimaryType()
	}
	if card.GetIssuer() == "" {
		card.Issuer = parsed.Issuer
	}
	card.Claims = claimsOf(parsed)
	card.Validity = validityOf(parsed)
	card.Revocation = b.revocation(ctx, parsed)
	trust := b.trust(ctx, card.GetIssuer(), card.GetType())
	card.Trust = trust.Outcome
	card.IssuerName = trust.Name
	if b.opts.Display != nil {
		card.Display = b.opts.Display(ctx, card.GetIssuer(), card.GetType())
	}
	card.Title = titleOf(card)
	card.StatusText = StatusText(card, b.opts.Now())
	return card
}

// Cards builds one card per held credential.
func (b *Builder) Cards(ctx context.Context, held []*backendv1.WalletCredential) []*walletportalv1.Card {
	out := make([]*walletportalv1.Card, 0, len(held))
	for _, h := range held {
		out = append(out, b.Card(ctx, h))
	}
	return out
}

// trust asks the trust registry about the issuer.
func (b *Builder) trust(ctx context.Context, issuer, credentialType string) Trust {
	if b.opts.Trust == nil || issuer == "" {
		return Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE}
	}
	got, err := b.opts.Trust(ctx, issuer, credentialType)
	if err != nil {
		return Trust{Outcome: trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE}
	}
	if got.Outcome == trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED {
		got.Outcome = trustv1.TrustLookupResponse_OUTCOME_UNKNOWN
	}
	return got
}

// revocation reads the status list of the credential.
func (b *Builder) revocation(ctx context.Context, parsed vc.Credential) walletportalv1.Card_RevocationState {
	ref, ok := delegation.StatusRefOf(parsed)
	if !ok || ref.URI == "" {
		return walletportalv1.Card_REVOCATION_STATE_NONE
	}
	if b.opts.Status == nil {
		return walletportalv1.Card_REVOCATION_STATE_UNKNOWN
	}
	raw, err := b.opts.Status(ctx, ref.URI)
	if err != nil {
		return walletportalv1.Card_REVOCATION_STATE_UNKNOWN
	}
	value, err := StatusValue(ref, raw)
	if err != nil {
		return walletportalv1.Card_REVOCATION_STATE_UNKNOWN
	}
	return StateOf(value, ref.Purpose)
}

// StatusValue reads the status value of one entry from a list document.
// The document is a JSON status list credential or a compact token.
func StatusValue(ref delegation.StatusRef, raw []byte) (uint8, error) {
	claims, err := statusClaims(raw)
	if err != nil {
		return 0, err
	}
	if strings.Contains(strings.ToLower(ref.Type), "bitstring") {
		_, list, perr := bitstring.ParseCredential(claims)
		if perr != nil {
			return 0, errors.New("cards: the status list credential does not parse")
		}
		set, gerr := list.Get(int(ref.Index))
		if gerr != nil {
			return 0, errors.New("cards: the status list is too short")
		}
		if set {
			return 1, nil
		}
		return 0, nil
	}
	_, list, perr := token.ParseJWTClaims(claims)
	if perr != nil {
		return 0, errors.New("cards: the status list token does not parse")
	}
	value, gerr := list.Get(int(ref.Index))
	if gerr != nil {
		return 0, errors.New("cards: the status list is too short")
	}
	return value, nil
}

// statusClaims decodes a status list document into its claim set.
func statusClaims(raw []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("{")) {
		var doc map[string]any
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return nil, errors.New("cards: the status list document does not parse")
		}
		return doc, nil
	}
	payload, err := jose.PeekPayload(string(trimmed))
	if err != nil {
		return nil, errors.New("cards: the status list token does not parse")
	}
	return payload, nil
}

// StateOf maps a status list value to a card state. The Token Status
// List reserves 1 for revoked and 2 for suspended.
func StateOf(value uint8, purpose string) walletportalv1.Card_RevocationState {
	switch {
	case value == 0:
		return walletportalv1.Card_REVOCATION_STATE_VALID
	case value == 2 || strings.Contains(strings.ToLower(purpose), "suspen"):
		return walletportalv1.Card_REVOCATION_STATE_SUSPENDED
	default:
		return walletportalv1.Card_REVOCATION_STATE_REVOKED
	}
}

// claimsOf returns the visible claims of a credential, keyed by name.
func claimsOf(parsed vc.Credential) map[string]string {
	out := make(map[string]string, len(parsed.Claims))
	for name, value := range parsed.Claims {
		out[name] = value
	}
	return out
}

// ClaimNames returns the claim names of a card in sorted order, so a
// page always lists them in the same order.
func ClaimNames(card *walletportalv1.Card) []string {
	names := make([]string, 0, len(card.GetClaims()))
	for name := range card.GetClaims() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validityOf reads the validity window of a credential.
func validityOf(parsed vc.Credential) *commonv1.ValidityWindow {
	from, until := parsed.TemporalBounds()
	if from.IsZero() && until.IsZero() {
		return nil
	}
	out := &commonv1.ValidityWindow{}
	if !from.IsZero() {
		out.ValidFrom = timestamppb.New(from.UTC())
	}
	if !until.IsZero() {
		out.ValidUntil = timestamppb.New(until.UTC())
	}
	return out
}

// titleOf returns the card title. The display name wins. The type name,
// as words, is the fallback.
func titleOf(card *walletportalv1.Card) string {
	if name := strings.TrimSpace(card.GetDisplay().GetName()); name != "" {
		return name
	}
	if t := vc.TypeTitle(card.GetType()); t != "" {
		return t
	}
	return "Credential"
}

// StatusText returns the status line of a card in plain language. It
// names the worst problem first, so a citizen reads the important
// sentence at the start.
func StatusText(card *walletportalv1.Card, now time.Time) string {
	parts := []string{revocationSentence(card.GetRevocation()), validitySentence(card.GetValidity(), now)}
	parts = append(parts, trustSentence(card.GetTrust(), card.GetIssuerName()))
	return strings.Join(parts, " ")
}

// revocationSentence says what the status list reports.
func revocationSentence(state walletportalv1.Card_RevocationState) string {
	switch state {
	case walletportalv1.Card_REVOCATION_STATE_REVOKED:
		return "The issuer withdrew this credential. You cannot use it."
	case walletportalv1.Card_REVOCATION_STATE_SUSPENDED:
		return "The issuer stopped this credential for now. Ask the issuer to start it again."
	case walletportalv1.Card_REVOCATION_STATE_VALID:
		return "The issuer still supports this credential."
	case walletportalv1.Card_REVOCATION_STATE_NONE:
		return "This credential has no withdrawal list."
	case walletportalv1.Card_REVOCATION_STATE_UNKNOWN, walletportalv1.Card_REVOCATION_STATE_UNSPECIFIED:
		return "The wallet could not read the withdrawal list. Try again later."
	}
	return "The wallet could not read the withdrawal list. Try again later."
}

// validitySentence says whether the credential is inside its window.
func validitySentence(window *commonv1.ValidityWindow, now time.Time) string {
	if window == nil {
		return "The credential names no end date."
	}
	if from := window.GetValidFrom(); from != nil && now.Before(from.AsTime()) {
		return "This credential starts on " + day(from.AsTime()) + "."
	}
	until := window.GetValidUntil()
	if until == nil {
		return "The credential names no end date."
	}
	if now.After(until.AsTime()) {
		return "This credential ended on " + day(until.AsTime()) + "."
	}
	return "This credential is valid until " + day(until.AsTime()) + "."
}

// trustSentence says whether relying parties trust the issuer.
func trustSentence(outcome trustv1.TrustLookupResponse_Outcome, name string) string {
	who := strings.TrimSpace(name)
	if who == "" {
		who = "The issuer"
	}
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return who + " is on the trust list."
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return who + " is not on the trust list now."
	case trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:
		return "No trust list names " + who + "."
	case trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE,
		trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED:
		return "The wallet could not check the trust list."
	}
	return "The wallet could not check the trust list."
}

// day formats a time as a plain date.
func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// TrustWord returns one word for a trust outcome. A badge shows it.
func TrustWord(outcome trustv1.TrustLookupResponse_Outcome) string {
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return "trusted"
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return "not trusted"
	case trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:
		return "not listed"
	case trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE,
		trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED:
		return "not checked"
	}
	return "not checked"
}

// TrustStatus maps a trust outcome to a UI badge status.
func TrustStatus(outcome trustv1.TrustLookupResponse_Outcome) string {
	switch outcome {
	case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
		return "ok"
	case trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:
		return "bad"
	default:
		return "warn"
	}
}

// RevocationWord returns one word for a revocation state.
func RevocationWord(state walletportalv1.Card_RevocationState) string {
	switch state {
	case walletportalv1.Card_REVOCATION_STATE_VALID:
		return "in force"
	case walletportalv1.Card_REVOCATION_STATE_SUSPENDED:
		return "stopped"
	case walletportalv1.Card_REVOCATION_STATE_REVOKED:
		return "withdrawn"
	case walletportalv1.Card_REVOCATION_STATE_NONE:
		return "no list"
	default:
		return "not checked"
	}
}

// RevocationStatus maps a revocation state to a UI badge status.
func RevocationStatus(state walletportalv1.Card_RevocationState) string {
	switch state {
	case walletportalv1.Card_REVOCATION_STATE_VALID, walletportalv1.Card_REVOCATION_STATE_NONE:
		return "ok"
	case walletportalv1.Card_REVOCATION_STATE_REVOKED:
		return "bad"
	default:
		return "warn"
	}
}

// Usable reports whether a citizen can present the credential now.
func Usable(card *walletportalv1.Card, now time.Time) bool {
	switch card.GetRevocation() {
	case walletportalv1.Card_REVOCATION_STATE_REVOKED, walletportalv1.Card_REVOCATION_STATE_SUSPENDED:
		return false
	}
	window := card.GetValidity()
	if from := window.GetValidFrom(); from != nil && now.Before(from.AsTime()) {
		return false
	}
	if until := window.GetValidUntil(); until != nil && now.After(until.AsTime()) {
		return false
	}
	return true
}
