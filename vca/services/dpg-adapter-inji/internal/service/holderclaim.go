// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The Service is the issuer side of the holder authorization server
// (ADR-052): it keeps the offers of the authorization code channel and
// writes the claims row of a holder who signed in.
var _ authz.Offers = (*Service)(nil)

// defaultBinding is the binding rule of an offer that names none: the
// email of the ID token equals the email of the subject.
var defaultBinding = authz.Binding{TokenClaim: "email", SubjectClaim: "email"}

// bindingOf returns the binding rule of a spec, or the default one.
func bindingOf(spec *backendv1.IssueSpec) authz.Binding {
	r := spec.GetBindingRule()
	b := authz.Binding{TokenClaim: strings.TrimSpace(r.GetTokenClaim()), SubjectClaim: strings.TrimSpace(r.GetSubjectClaim())}
	if b.TokenClaim == "" && b.SubjectClaim == "" {
		return defaultBinding
	}
	return b
}

// holderOffer builds an authorization code offer that the holder
// authorization server of the adapter serves. It checks the claims and
// the binding rule now, so an issuer learns of a bad offer before a
// holder does. The row waits for the sign in.
func (s *Service) holderOffer(ctx context.Context, spec *backendv1.IssueSpec, issuer string) (
	*connect.Response[backendv1.CreateOfferResponse], error,
) {
	binding := bindingOf(spec)
	if binding.TokenClaim == "" || binding.SubjectClaim == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the binding rule needs the claim of the ID token and the claim of the subject"))
	}
	if _, _, err := s.buildRow(ctx, spec, "check"); err != nil {
		return nil, err
	}
	subject, err := subjectOf(spec)
	if err != nil {
		return nil, err
	}
	if v, ok := subject[binding.SubjectClaim].(string); !ok || strings.TrimSpace(v) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"the claim %q of the subject holds no text, so no holder can match the offer; name another claim in binding_rule",
			binding.SubjectClaim))
	}
	raw, err := protojson.Marshal(spec)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return s.hostOffer(ctx, spec, issuer, s.authzIssuer, hostedOffer{Spec: string(raw), Binding: &binding})
}

// subjectOf reads the subject claims of a spec.
func subjectOf(spec *backendv1.IssueSpec) (map[string]any, error) {
	subject := map[string]any{}
	if err := json.Unmarshal([]byte(spec.GetSubjectData()), &subject); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("subject_data is not a JSON object: %w", err))
	}
	return subject, nil
}

// openOffer reads a stored offer that a holder may still claim.
func (s *Service) openOffer(ctx context.Context, id string) (hostedOffer, []byte, *backendv1.IssueSpec, bool) {
	raw, err := s.store.Get(ctx, offerKey(id))
	if err != nil {
		return hostedOffer{}, nil, nil, false
	}
	var offer hostedOffer
	if err := json.Unmarshal(raw, &offer); err != nil || offer.Spec == "" || offer.Binding == nil || offer.Claimed ||
		!s.now().UTC().Before(offer.ExpiresAt) {
		return hostedOffer{}, nil, nil, false
	}
	spec := &backendv1.IssueSpec{}
	if err := protojson.Unmarshal([]byte(offer.Spec), spec); err != nil {
		return hostedOffer{}, nil, nil, false
	}
	return offer, raw, spec, true
}

// Offer returns an open offer of the holder authorization server.
func (s *Service) Offer(ctx context.Context, id string) (authz.Offer, bool) {
	offer, _, spec, ok := s.openOffer(ctx, id)
	if !ok {
		return authz.Offer{}, false
	}
	subject, err := subjectOf(spec)
	if err != nil {
		return authz.Offer{}, false
	}
	return authz.Offer{ConfigID: spec.GetConfigurationId(), Subject: subject, Binding: *offer.Binding}, true
}

// StageOffer writes the claims row of an offer under key and closes the
// offer. The row lives until expires, the end the authorization server
// gives it (ADR-056 decision 3). The compare and swap lets one holder
// claim it, once.
func (s *Service) StageOffer(ctx context.Context, id, key string, expires time.Time) error {
	offer, raw, spec, ok := s.openOffer(ctx, id)
	if !ok {
		return errors.New("the offer is not open")
	}
	row, _, err := s.buildRow(ctx, spec, key)
	if err != nil {
		return err
	}
	row.ExpiresAt = expires
	offer.Claimed = true
	next, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	if err := s.store.CompareAndSwap(ctx, offerKey(id), raw, next); err != nil {
		return fmt.Errorf("close the offer: %w", err)
	}
	return s.claims.Put(row)
}

// StageSubject writes the claims row of a holder that a sign in source
// found, for one configuration. The row lives until expires.
func (s *Service) StageSubject(ctx context.Context, configID, subject, key string, expires time.Time) error {
	row, _, err := s.buildRow(ctx, &backendv1.IssueSpec{ConfigurationId: configID, SubjectData: subject}, key)
	if err != nil {
		return err
	}
	row.ExpiresAt = expires
	if err := s.claims.Put(row); err != nil {
		return fmt.Errorf("write the claims row: %w", err)
	}
	return nil
}

// Reopen opens a claimed offer again whose code failed before any
// token (ADR-056 decision 4). An offer that dropped its subject, or
// that the sweep removed, cannot open again.
func (s *Service) Reopen(ctx context.Context, id string) error {
	raw, err := s.store.Get(ctx, offerKey(id))
	if err != nil {
		return fmt.Errorf("read the offer: %w", err)
	}
	var offer hostedOffer
	if uerr := json.Unmarshal(raw, &offer); uerr != nil {
		return fmt.Errorf("read the offer: %w", uerr)
	}
	if offer.Spec == "" || offer.Binding == nil {
		return errors.New("the offer holds no subject any more")
	}
	offer.Claimed = false
	next, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	return s.store.CompareAndSwap(ctx, offerKey(id), raw, next)
}

// Finish drops the subject and the binding rule of a claimed offer once
// the holder has the token (ADR-056 decision 4). The claims row serves
// the credential, so the offer keeps only its document until it
// expires. A missing offer is not an error: the sweep removed it.
func (s *Service) Finish(ctx context.Context, id string) error {
	raw, err := s.store.Get(ctx, offerKey(id))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var offer hostedOffer
	if uerr := json.Unmarshal(raw, &offer); uerr != nil {
		return fmt.Errorf("read the offer: %w", uerr)
	}
	if offer.Spec == "" && offer.Binding == nil {
		return nil
	}
	next, err := json.Marshal(hostedOffer{Document: offer.Document, ExpiresAt: offer.ExpiresAt, Claimed: true})
	if err != nil {
		return err
	}
	return s.store.CompareAndSwap(ctx, offerKey(id), raw, next)
}

// SweepOffers deletes every hosted offer whose end has passed, and every
// document that does not read as an offer. It returns the number it
// deleted. The subject of an offer never claimed goes with it (ADR-056
// decision 4).
func (s *Service) SweepOffers(ctx context.Context) (int, error) {
	keys, err := s.store.List(ctx, offerKey(""))
	if err != nil {
		return 0, err
	}
	now := s.now().UTC()
	removed := 0
	for _, k := range keys {
		raw, gerr := s.store.Get(ctx, k)
		if gerr != nil {
			continue
		}
		var offer hostedOffer
		if json.Unmarshal(raw, &offer) == nil && now.Before(offer.ExpiresAt) {
			continue
		}
		if s.store.Delete(ctx, k) == nil {
			removed++
		}
	}
	return removed, nil
}

// Unstage removes the claims row under key.
func (s *Service) Unstage(_ context.Context, key string) error {
	if s.claims == nil {
		return nil
	}
	return s.claims.Delete(key)
}
