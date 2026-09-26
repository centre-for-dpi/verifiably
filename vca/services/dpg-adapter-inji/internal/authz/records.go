// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// The store keys of the records. A key holds the SHA-256 of a secret
// value, never the value, so a copy of the store gives no code.
const (
	loginPrefix = "authz/logins/"
	codePrefix  = "authz/codes/"
	jtiPrefix   = "authz/jti/"
	// signInKey holds every sign in source in one document.
	signInKey = "authz/signin-sources"
)

func hashed(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(sum[:])
}

// authRequest is the authorization request of a wallet.
type authRequest struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	Challenge   string `json:"challenge"`
	IssuerState string `json:"issuer_state,omitempty"`
	ConfigID    string `json:"config_id,omitempty"`
}

// login is a sign in at the holder provider, keyed by its state.
type login struct {
	Request   authRequest      `json:"request"`
	Pending   oidcflow.Pending `json:"pending"`
	ExpiresAt time.Time        `json:"expires_at"`
	Used      bool             `json:"used,omitempty"`
}

// code is one authorization code, keyed by its hash.
type code struct {
	ClientID    string    `json:"client_id"`
	RedirectURI string    `json:"redirect_uri"`
	Challenge   string    `json:"challenge"`
	Subject     string    `json:"subject"`
	OfferID     string    `json:"offer_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	Used        bool      `json:"used,omitempty"`
}

// jti is a client assertion that was used, until it expires.
type jti struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// expiring is the part every short lived record shares.
type expiring struct {
	ExpiresAt time.Time `json:"expires_at"`
}

func putJSON(ctx context.Context, kv store.KeyValue, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return kv.Put(ctx, key, raw)
}

// getJSON reads a record. A missing record gives false and no error.
func getJSON(ctx context.Context, kv store.KeyValue, key string, v any) (bool, error) {
	raw, err := kv.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("authz: read %s: %w", key, err)
	}
	return true, nil
}

// consume reads a record and marks it used in one compare and swap, so
// two requests with the same code or state cannot both pass. It returns
// the record as it was before the call. mark sets the used flag and
// reports whether the record was already used.
func consume[T any](ctx context.Context, kv store.KeyValue, key string, rec *T, mark func(*T) bool) (found, wasUsed bool, err error) {
	raw, err := kv.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if uerr := json.Unmarshal(raw, rec); uerr != nil {
		return false, false, fmt.Errorf("authz: read %s: %w", key, uerr)
	}
	updated := *rec
	if mark(&updated) {
		return true, true, nil
	}
	next, err := json.Marshal(updated)
	if err != nil {
		return false, false, err
	}
	if err := kv.CompareAndSwap(ctx, key, raw, next); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Another request took it first.
			return true, true, nil
		}
		return false, false, err
	}
	return true, false, nil
}

// Sweep deletes the logins, codes and assertion ids that have expired.
// It returns the number it deleted.
func (s *Server) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	removed := 0
	for _, prefix := range []string{loginPrefix, codePrefix, jtiPrefix} {
		keys, err := s.kv.List(ctx, strings.TrimSuffix(prefix, "/"))
		if err != nil {
			return removed, err
		}
		for _, k := range keys {
			var rec expiring
			ok, err := getJSON(ctx, s.kv, k, &rec)
			if err != nil || !ok || now.Before(rec.ExpiresAt) {
				continue
			}
			if err := s.kv.Delete(ctx, k); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}
