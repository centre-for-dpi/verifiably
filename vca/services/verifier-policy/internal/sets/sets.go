// SPDX-License-Identifier: Apache-2.0

// Package sets keeps named, versioned policy sets (ADR-024 decision 6).
// One document holds one version. A version never changes after the
// store writes it, so a stored result can name the rules that ran.
//
// The keys are "policyset/<id>/<version>". The version is padded, so the
// sorted key list is also the version order.
package sets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Prefix of every key this package writes.
const Prefix = "policyset/"

// ErrNotFound reports a missing set or version.
var ErrNotFound = errors.New("sets: no such policy set version")

// ErrBadID reports an id that the key rules do not allow.
var ErrBadID = errors.New("sets: the id must hold letters, digits, dots, dashes, or underscores")

// ErrExists reports that a set with the id exists.
var ErrExists = errors.New("sets: the policy set exists")

var idRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Store reads and writes policy sets.
type Store struct {
	kv    store.KeyValue
	newID func(string) string
}

// New builds a store on a key value backend. newID makes an id from a
// display name. A nil newID uses a slug plus random hex.
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
	b := make([]byte, 4)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	if slug == "" {
		return "set-" + hex.EncodeToString(b)
	}
	return slug + "-" + hex.EncodeToString(b)
}

// key returns the document key of one version.
func key(id string, version int32) string {
	return fmt.Sprintf("%s%s/%06d", Prefix, id, version)
}

// Create stores a set as version 1.
func (s *Store) Create(ctx context.Context, set *policyv1.PolicySet) (*policyv1.PolicySet, error) {
	out := proto.CloneOf(set)
	if out.GetId() == "" {
		out.Id = s.newID(out.GetDisplayName())
	}
	if !idRE.MatchString(out.GetId()) {
		return nil, ErrBadID
	}
	if _, err := s.Get(ctx, out.GetId(), 0); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, out.GetId())
	}
	out.Version = 1
	return out, s.put(ctx, out)
}

// Update stores the next version of a set.
func (s *Store) Update(ctx context.Context, set *policyv1.PolicySet) (*policyv1.PolicySet, error) {
	latest, err := s.Get(ctx, set.GetId(), 0)
	if err != nil {
		return nil, err
	}
	out := proto.CloneOf(set)
	out.Version = latest.GetVersion() + 1
	return out, s.put(ctx, out)
}

func (s *Store) put(ctx context.Context, set *policyv1.PolicySet) error {
	raw, err := protojson.Marshal(set)
	if err != nil {
		return fmt.Errorf("sets: encode: %w", err)
	}
	return s.kv.Put(ctx, key(set.GetId(), set.GetVersion()), raw)
}

// Get returns one version. Version zero returns the latest version.
func (s *Store) Get(ctx context.Context, id string, version int32) (*policyv1.PolicySet, error) {
	if !idRE.MatchString(id) {
		return nil, ErrBadID
	}
	if version > 0 {
		return s.read(ctx, key(id, version))
	}
	keys, err := s.kv.List(ctx, Prefix+id+"/")
	if err != nil {
		return nil, fmt.Errorf("sets: list: %w", err)
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return s.read(ctx, keys[len(keys)-1])
}

func (s *Store) read(ctx context.Context, k string) (*policyv1.PolicySet, error) {
	raw, err := s.kv.Get(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sets: read: %w", err)
	}
	var set policyv1.PolicySet
	if err := protojson.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("sets: decode %s: %w", k, err)
	}
	return &set, nil
}

// List returns the latest version of every set, sorted by id. An empty
// tenant returns every set.
func (s *Store) List(ctx context.Context, tenant string) ([]*policyv1.PolicySet, error) {
	keys, err := s.kv.List(ctx, Prefix)
	if err != nil {
		return nil, fmt.Errorf("sets: list: %w", err)
	}
	latest := map[string]string{}
	var ids []string
	for _, k := range keys {
		id := setID(k)
		if id == "" {
			continue
		}
		if _, seen := latest[id]; !seen {
			ids = append(ids, id)
		}
		latest[id] = k
	}
	out := make([]*policyv1.PolicySet, 0, len(ids))
	for _, id := range ids {
		set, rerr := s.read(ctx, latest[id])
		if rerr != nil {
			return nil, rerr
		}
		if tenant != "" && set.GetTenantId() != tenant {
			continue
		}
		out = append(out, set)
	}
	return out, nil
}

// Delete removes every version of a set.
func (s *Store) Delete(ctx context.Context, id string) error {
	if !idRE.MatchString(id) {
		return ErrBadID
	}
	keys, err := s.kv.List(ctx, Prefix+id+"/")
	if err != nil {
		return fmt.Errorf("sets: list: %w", err)
	}
	if len(keys) == 0 {
		return ErrNotFound
	}
	for _, k := range keys {
		if derr := s.kv.Delete(ctx, k); derr != nil {
			return fmt.Errorf("sets: delete: %w", derr)
		}
	}
	return nil
}

// setID returns the set id of a key.
func setID(k string) string {
	rest := strings.TrimPrefix(k, Prefix)
	i := strings.Index(rest, "/")
	if i <= 0 {
		return ""
	}
	return rest[:i]
}
