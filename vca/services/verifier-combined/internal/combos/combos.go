// SPDX-License-Identifier: Apache-2.0

// Package combos keeps combined templates (ADR-026 decision 1). One
// document holds one template under the key "combined/<id>".
package combos

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// idSuffixLen is the length of the random suffix in a default id.
const idSuffixLen = 8

// Prefix of every key this package writes.
const Prefix = "combined/"

// ErrNotFound reports a missing template.
var ErrNotFound = errors.New("combos: no such combined template")

// ErrBadID reports an id that the key rules do not allow.
var ErrBadID = errors.New("combos: the id must hold letters, digits, dots, dashes, or underscores")

var idRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Store reads and writes combined templates.
type Store struct {
	kv    store.KeyValue
	newID func(string) string
}

// New builds a store on a key value backend. A nil newID makes a slug
// plus random text.
func New(kv store.KeyValue, newID func(string) string) *Store {
	if newID == nil {
		newID = defaultID
	}
	return &Store{kv: kv, newID: newID}
}

// defaultID makes a readable, unique id from a display name.
func defaultID(displayName string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		default:
			return '-'
		}
	}, displayName)
	slug = strings.Trim(slug, "-")
	if len(slug) > 32 {
		slug = strings.Trim(slug[:32], "-")
	}
	suffix := strings.ToLower(rand.Text()[:idSuffixLen])
	if slug == "" {
		return "combined-" + suffix
	}
	return slug + "-" + suffix
}

// Create stores a template. An empty id gets a new one.
func (s *Store) Create(ctx context.Context, t *combinedv1.CombinedTemplate) (
	*combinedv1.CombinedTemplate, error) {
	out := proto.CloneOf(t)
	if out.GetId() == "" {
		out.Id = s.newID(out.GetDisplayName())
	}
	if !idRE.MatchString(out.GetId()) {
		return nil, ErrBadID
	}
	if _, err := s.Get(ctx, out.GetId()); err == nil {
		return nil, fmt.Errorf("combos: the combined template %s exists", out.GetId())
	}
	raw, err := protojson.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("combos: encode: %w", err)
	}
	if err := s.kv.Put(ctx, Prefix+out.GetId(), raw); err != nil {
		return nil, fmt.Errorf("combos: write: %w", err)
	}
	return out, nil
}

// Get returns one template.
func (s *Store) Get(ctx context.Context, id string) (*combinedv1.CombinedTemplate, error) {
	if !idRE.MatchString(id) {
		return nil, ErrBadID
	}
	return s.read(ctx, Prefix+id)
}

func (s *Store) read(ctx context.Context, key string) (*combinedv1.CombinedTemplate, error) {
	raw, err := s.kv.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("combos: read: %w", err)
	}
	var out combinedv1.CombinedTemplate
	if err := protojson.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("combos: decode %s: %w", key, err)
	}
	return &out, nil
}

// List returns every template, sorted by id. An empty tenant returns
// every template.
func (s *Store) List(ctx context.Context, tenant string) ([]*combinedv1.CombinedTemplate, error) {
	keys, err := s.kv.List(ctx, Prefix)
	if err != nil {
		return nil, fmt.Errorf("combos: list: %w", err)
	}
	out := make([]*combinedv1.CombinedTemplate, 0, len(keys))
	for _, k := range keys {
		t, rerr := s.read(ctx, k)
		if rerr != nil {
			return nil, rerr
		}
		if tenant != "" && t.GetTenantId() != tenant {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// Delete removes one template.
func (s *Store) Delete(ctx context.Context, id string) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	if err := s.kv.Delete(ctx, Prefix+id); err != nil {
		return fmt.Errorf("combos: delete: %w", err)
	}
	return nil
}
