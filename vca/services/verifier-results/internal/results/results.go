// SPDX-License-Identifier: Apache-2.0

// Package results keeps verification results and raw presentations
// (ADR-025 decisions 1 and 3). One document holds one result. A second
// document holds the raw presentation of that result.
//
// The keys are "result/<id>" and "raw/<id>". The purge deletes the raw
// presentation first, so the service holds personal data for the
// shortest time it can.
package results

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"

	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ResultPrefix of every result key.
const ResultPrefix = "result/"

// RawPrefix of every raw presentation key.
const RawPrefix = "raw/"

// ErrNotFound reports a missing result.
var ErrNotFound = errors.New("results: no such result")

// ErrBadID reports an id that the key rules do not allow.
var ErrBadID = errors.New("results: the id must hold letters, digits, dots, dashes, or underscores")

var idRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Store reads and writes results.
type Store struct {
	kv    store.KeyValue
	newID func() string
}

// New builds a store on a key value backend. A nil newID makes a random
// hexadecimal id.
func New(kv store.KeyValue, newID func() string) *Store {
	if newID == nil {
		newID = randomID
	}
	return &Store{kv: kv, newID: newID}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Put writes a result. An empty id gets a new one.
func (s *Store) Put(ctx context.Context, r *resultsv1.VerificationResult) (*resultsv1.VerificationResult, error) {
	out := proto.Clone(r).(*resultsv1.VerificationResult)
	if out.GetId() == "" {
		out.Id = s.newID()
	}
	if !idRE.MatchString(out.GetId()) {
		return nil, ErrBadID
	}
	raw, err := protojson.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("results: encode: %w", err)
	}
	if err := s.kv.Put(ctx, ResultPrefix+out.GetId(), raw); err != nil {
		return nil, fmt.Errorf("results: write: %w", err)
	}
	return out, nil
}

// PutRaw writes the raw presentation of a result.
func (s *Store) PutRaw(ctx context.Context, id string, payload []byte) error {
	if !idRE.MatchString(id) {
		return ErrBadID
	}
	if err := s.kv.Put(ctx, RawPrefix+id, payload); err != nil {
		return fmt.Errorf("results: write raw: %w", err)
	}
	return nil
}

// GetRaw returns the raw presentation of a result.
func (s *Store) GetRaw(ctx context.Context, id string) ([]byte, error) {
	if !idRE.MatchString(id) {
		return nil, ErrBadID
	}
	raw, err := s.kv.Get(ctx, RawPrefix+id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("results: read raw: %w", err)
	}
	return raw, nil
}

// DeleteRaw removes the raw presentation of a result.
func (s *Store) DeleteRaw(ctx context.Context, id string) error {
	if !idRE.MatchString(id) {
		return ErrBadID
	}
	if err := s.kv.Delete(ctx, RawPrefix+id); err != nil {
		return fmt.Errorf("results: delete raw: %w", err)
	}
	return nil
}

// Get returns one result.
func (s *Store) Get(ctx context.Context, id string) (*resultsv1.VerificationResult, error) {
	if !idRE.MatchString(id) {
		return nil, ErrBadID
	}
	return s.read(ctx, ResultPrefix+id)
}

func (s *Store) read(ctx context.Context, key string) (*resultsv1.VerificationResult, error) {
	raw, err := s.kv.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("results: read: %w", err)
	}
	var out resultsv1.VerificationResult
	if err := protojson.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("results: decode %s: %w", key, err)
	}
	return &out, nil
}

// Delete removes one result. It removes the raw presentation too.
func (s *Store) Delete(ctx context.Context, id string) error {
	if !idRE.MatchString(id) {
		return ErrBadID
	}
	if err := s.DeleteRaw(ctx, id); err != nil {
		return err
	}
	if err := s.kv.Delete(ctx, ResultPrefix+id); err != nil {
		return fmt.Errorf("results: delete: %w", err)
	}
	return nil
}

// All returns every result, newest first (ADR-025 decision 4).
func (s *Store) All(ctx context.Context) ([]*resultsv1.VerificationResult, error) {
	keys, err := s.kv.List(ctx, ResultPrefix)
	if err != nil {
		return nil, fmt.Errorf("results: list: %w", err)
	}
	out := make([]*resultsv1.VerificationResult, 0, len(keys))
	for _, k := range keys {
		r, rerr := s.read(ctx, k)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].GetEvaluatedAt().AsTime().After(out[j].GetEvaluatedAt().AsTime())
	})
	return out, nil
}
