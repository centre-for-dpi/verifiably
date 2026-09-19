// SPDX-License-Identifier: Apache-2.0

// Package store keeps the crawled catalogue and the presentation
// templates in the shared key value store (ADR-022 decisions 1 and 4).
//
// An issuer document lives at "issuers/<key>", where the key is the hex
// SHA-256 of the issuer URL. A template version lives at
// "templates/<id>/v<version>". The store never changes a stored version,
// so an old version stays readable.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
)

// ErrNotFound reports that the store holds no such record.
var ErrNotFound = errors.New("store: not found")

// Prefixes of the two record kinds.
const (
	IssuerPrefix   = "issuers/"
	TemplatePrefix = "templates/"
)

// Store reads and writes the records of the service.
type Store struct {
	kv store.KeyValue
}

// New wraps a key value backend.
func New(kv store.KeyValue) (*Store, error) {
	if kv == nil {
		return nil, errors.New("store: a key value backend is required")
	}
	return &Store{kv: kv}, nil
}

// IssuerKey returns the store key of one issuer URL.
func IssuerKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return IssuerPrefix + hex.EncodeToString(sum[:16])
}

// PutIssuer writes one issuer record.
func (s *Store) PutIssuer(ctx context.Context, issuer catalog.Issuer) error {
	// The record holds strings, numbers, and times, so it always writes.
	data, ignored2 := json.Marshal(issuer)
	_ = ignored2
	return s.kv.Put(ctx, IssuerKey(issuer.CredentialIssuer), data)
}

// GetIssuer reads one issuer record by URL.
func (s *Store) GetIssuer(ctx context.Context, url string) (catalog.Issuer, error) {
	data, err := s.kv.Get(ctx, IssuerKey(url))
	if errors.Is(err, store.ErrNotFound) {
		return catalog.Issuer{}, fmt.Errorf("%w: the catalogue has no issuer %q", ErrNotFound, url)
	}
	if err != nil {
		return catalog.Issuer{}, err
	}
	var issuer catalog.Issuer
	if err := json.Unmarshal(data, &issuer); err != nil {
		return catalog.Issuer{}, fmt.Errorf("store: read the issuer: %w", err)
	}
	return issuer, nil
}

// ListIssuers returns every issuer record, ordered by issuer URL.
func (s *Store) ListIssuers(ctx context.Context) ([]catalog.Issuer, error) {
	keys, err := s.kv.List(ctx, IssuerPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]catalog.Issuer, 0, len(keys))
	for _, key := range keys {
		data, err := s.kv.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var issuer catalog.Issuer
		if err := json.Unmarshal(data, &issuer); err != nil {
			return nil, fmt.Errorf("store: read the issuer %q: %w", key, err)
		}
		out = append(out, issuer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CredentialIssuer < out[j].CredentialIssuer })
	return out, nil
}

// DeleteIssuer removes one issuer record.
func (s *Store) DeleteIssuer(ctx context.Context, url string) error {
	return s.kv.Delete(ctx, IssuerKey(url))
}

// TemplateKey returns the store key of one template version.
func TemplateKey(id string, version int32) string {
	return TemplatePrefix + id + "/v" + strconv.Itoa(int(version))
}

// PutTemplate writes one template version. It refuses to replace a
// stored version.
func (s *Store) PutTemplate(ctx context.Context, t template.Template) error {
	// The record holds strings, numbers, and times, so it always writes.
	data, ignored := json.Marshal(t)
	_ = ignored
	key := TemplateKey(t.ID, t.Version)
	if err := s.kv.CompareAndSwap(ctx, key, nil, data); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("store: version %d of template %q exists", t.Version, t.ID)
		}
		return err
	}
	return nil
}

// GetTemplate reads one template version. Version zero reads the latest
// version.
func (s *Store) GetTemplate(ctx context.Context, id string, version int32) (template.Template, error) {
	if version <= 0 {
		latest, err := s.LatestVersion(ctx, id)
		if err != nil {
			return template.Template{}, err
		}
		version = latest
	}
	data, err := s.kv.Get(ctx, TemplateKey(id, version))
	if errors.Is(err, store.ErrNotFound) {
		return template.Template{}, fmt.Errorf("%w: template %q has no version %d", ErrNotFound, id, version)
	}
	if err != nil {
		return template.Template{}, err
	}
	var t template.Template
	if err := json.Unmarshal(data, &t); err != nil {
		return template.Template{}, fmt.Errorf("store: read the template: %w", err)
	}
	return t, nil
}

// Versions returns the version numbers of one template, in order.
func (s *Store) Versions(ctx context.Context, id string) ([]int32, error) {
	keys, err := s.kv.List(ctx, TemplatePrefix+id+"/v")
	if err != nil {
		return nil, err
	}
	out := make([]int32, 0, len(keys))
	for _, key := range keys {
		n, err := strconv.ParseInt(strings.TrimPrefix(key, TemplatePrefix+id+"/v"), 10, 32)
		if err != nil {
			continue
		}
		out = append(out, int32(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// LatestVersion returns the highest version number of one template.
func (s *Store) LatestVersion(ctx context.Context, id string) (int32, error) {
	versions, err := s.Versions(ctx, id)
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, fmt.Errorf("%w: no template %q", ErrNotFound, id)
	}
	return versions[len(versions)-1], nil
}

// ListTemplates returns the latest version of every template, ordered by
// template id.
func (s *Store) ListTemplates(ctx context.Context) ([]template.Template, error) {
	keys, err := s.kv.List(ctx, TemplatePrefix)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, key := range keys {
		rest := strings.TrimPrefix(key, TemplatePrefix)
		cut := strings.LastIndex(rest, "/v")
		if cut <= 0 {
			continue
		}
		ids[rest[:cut]] = true
	}
	names := make([]string, 0, len(ids))
	for id := range ids {
		names = append(names, id)
	}
	sort.Strings(names)
	out := make([]template.Template, 0, len(names))
	for _, id := range names {
		t, err := s.GetTemplate(ctx, id, 0)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// DeleteTemplate removes every version of one template. It returns the
// number of versions it removed.
func (s *Store) DeleteTemplate(ctx context.Context, id string) (int, error) {
	versions, err := s.Versions(ctx, id)
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, fmt.Errorf("%w: no template %q", ErrNotFound, id)
	}
	for _, v := range versions {
		if err := s.kv.Delete(ctx, TemplateKey(id, v)); err != nil {
			return 0, err
		}
	}
	return len(versions), nil
}
