// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Kinds of pending record. Each kind has its own key prefix.
const (
	// KindOffer is a credential offer the citizen has not accepted.
	KindOffer = "offer"
	// KindPresentation is a presentation request on the consent screen.
	KindPresentation = "vp"
	// KindHeld is a credential the citizen pasted into the wallet.
	KindHeld = "held"
	// KindSignIn is an authorization code flow that waits for the issuer.
	KindSignIn = "authz"
)

// ErrExpired reports a record that is too old to use.
var ErrExpired = errors.New("service: the record expired")

// ErrNoRecord reports a record that does not exist.
var ErrNoRecord = errors.New("service: no such record")

// record is one short lived document of the service.
type record struct {
	// ID is the record id.
	ID string `json:"id"`
	// URI is the offer URI or the presentation request URI.
	URI string `json:"uri,omitempty"`
	// Issuer is the issuer URL of an offer.
	Issuer string `json:"issuer,omitempty"`
	// Types are the credential types of an offer.
	Types []string `json:"types,omitempty"`
	// NeedsPIN says whether an offer needs a transaction code.
	NeedsPIN bool `json:"needs_pin,omitempty"`
	// Payload is the credential bytes of a pasted credential.
	Payload []byte `json:"payload,omitempty"`
	// Format is the wire format of Payload.
	Format commonv1.Format `json:"format,omitempty"`
	// Verifier is the PKCE code verifier of a sign in.
	Verifier string `json:"verifier,omitempty"`
	// Token is the token endpoint of a sign in.
	Token string `json:"token,omitempty"`
	// Redirect is the redirect URI of a sign in.
	Redirect string `json:"redirect,omitempty"`
	// Interactive is the interactive authorization endpoint of an issuer
	// that asks for a presentation before it issues.
	Interactive string `json:"interactive,omitempty"`
	// AuthSession is the session id of that endpoint.
	AuthSession string `json:"auth_session,omitempty"`
	// Request is the OpenID4VP request of that endpoint, as JSON.
	Request string `json:"request,omitempty"`
	// Offer is the credential offer the wallet claims after the
	// presentation.
	Offer string `json:"offer,omitempty"`
	// ExpiresAt is the time the record stops working.
	ExpiresAt time.Time `json:"expires_at"`
}

// key returns the store key of one record. A slash in the wallet key or
// in the id is not allowed, so one record never reaches another wallet.
func key(kind, wallet, id string) (string, error) {
	if strings.ContainsAny(wallet+id, "/") {
		return "", fmt.Errorf("service: %w: a slash is not allowed", store.ErrBadKey)
	}
	full := kind + "/" + wallet + "/" + id
	if err := store.ValidateKey(full); err != nil {
		return "", fmt.Errorf("service: %w", err)
	}
	return full, nil
}

// put writes one record.
func (s *Service) put(ctx context.Context, kind, wallet string, rec record) error {
	k, err := key(kind, wallet, rec.ID)
	if err != nil {
		return err
	}
	rec.ExpiresAt = s.opts.Now().Add(s.opts.PendingTTL).UTC()
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("service: encode the record: %w", err)
	}
	if err := s.opts.Store.Put(ctx, k, raw); err != nil {
		return fmt.Errorf("service: write the record: %w", err)
	}
	return nil
}

// get reads one record. It removes an expired record.
func (s *Service) get(ctx context.Context, kind, wallet, id string) (record, error) {
	k, err := key(kind, wallet, id)
	if err != nil {
		return record{}, err
	}
	raw, err := s.opts.Store.Get(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		return record{}, ErrNoRecord
	}
	if err != nil {
		return record{}, fmt.Errorf("service: read the record: %w", err)
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return record{}, fmt.Errorf("service: the record does not parse: %w", err)
	}
	if s.opts.Now().After(rec.ExpiresAt) {
		ignored := s.opts.Store.Delete(ctx, k)
		_ = ignored
		return record{}, ErrExpired
	}
	return rec, nil
}

// drop removes one record.
func (s *Service) drop(ctx context.Context, kind, wallet, id string) error {
	k, err := key(kind, wallet, id)
	if err != nil {
		return err
	}
	if err := s.opts.Store.Delete(ctx, k); err != nil {
		return fmt.Errorf("service: remove the record: %w", err)
	}
	return nil
}

// list returns every record of one kind of one wallet, oldest key first.
func (s *Service) list(ctx context.Context, kind, wallet string) ([]record, error) {
	keys, err := s.opts.Store.List(ctx, kind+"/"+wallet+"/")
	if err != nil {
		return nil, fmt.Errorf("service: list the records: %w", err)
	}
	out := make([]record, 0, len(keys))
	for _, k := range keys {
		raw, err := s.opts.Store.Get(ctx, k)
		if err != nil {
			continue
		}
		var rec record
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		if s.opts.Now().After(rec.ExpiresAt) {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// newID returns a random record id.
func newID() string {
	b := make([]byte, 12)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// toInt32 converts n to int32. A value out of range clamps to the limit.
func toInt32(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
