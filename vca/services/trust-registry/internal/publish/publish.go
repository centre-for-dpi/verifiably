// SPDX-License-Identifier: Apache-2.0

// Package publish defines the TrustListPublisher interface (ADR-011
// decision 1) and the snapshot of published files that the HTTP layer
// serves. A publisher turns the canonical entries into the files of one
// method. It also checks a published set of files, so that the lookup
// cache can trust what it reads.
package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
)

// Method names of the two publication formats.
const (
	MethodEtsi = "etsi"
	MethodDedi = "dedi"
)

// File is one published document.
type File struct {
	ContentType string
	Body        []byte
}

// ETag returns the strong entity tag of the file body.
func (f File) ETag() string {
	sum := sha256.Sum256(f.Body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// Issuer identifies the operator of the registry in the lists.
type Issuer struct {
	// ID is the DID or URL of the registry operator.
	ID string
	// Name is the display name of the operator.
	Name string
	// Territory is the ISO 3166-1 code of the scheme, for example KE.
	Territory string
}

// Input is what a publisher needs to build the files of one method.
type Input struct {
	Entries []entry.Entry
	// Sequence is the store revision. It rises with every change.
	Sequence uint64
	Now      time.Time
	// TTL is the validity of the published list.
	TTL time.Duration
	// BaseURL is the public root of the service without a trailing slash.
	BaseURL string
	Issuer  Issuer
	Signer  keys.Key
}

// Publication is the result of one publisher.
type Publication struct {
	Method string
	// URL is the public URL of the list or manifest.
	URL string
	// Files maps a URL path, for example /trust-list/etsi.json, to a file.
	Files       map[string]File
	EntryCount  int
	PublishedAt time.Time
	KeyID       string
	Sequence    uint64
}

// Verified is a signature checked copy of a published list.
type Verified struct {
	Entries   []entry.Entry
	Sequence  uint64
	KeyID     string
	ListURL   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Publisher is one publication method (ADR-011 decisions 2 and 3).
type Publisher interface {
	// Method returns etsi or dedi.
	Method() string
	// Publish builds and signs the files of the method.
	Publish(in Input) (Publication, error)
	// Verify checks the signatures of published files with the JWKS and
	// returns the entries. It fails when a signature does not match or
	// the list expired at now.
	Verify(files map[string]File, set jose.JWKS, now time.Time) (Verified, error)
}

// Snapshot is an immutable set of published files across methods.
type Snapshot struct {
	files map[string]File
	pubs  map[string]Publication
}

// NewSnapshot merges publications into one snapshot.
// It fails when two publications write the same path.
func NewSnapshot(pubs ...Publication) (*Snapshot, error) {
	s := &Snapshot{files: map[string]File{}, pubs: map[string]Publication{}}
	for _, p := range pubs {
		for path, f := range p.Files {
			if _, dup := s.files[path]; dup {
				return nil, fmt.Errorf("publish: path %s published twice", path)
			}
			s.files[path] = f
		}
		s.pubs[p.Method] = p
	}
	return s, nil
}

// File returns the file at path.
func (s *Snapshot) File(path string) (File, bool) {
	if s == nil {
		return File{}, false
	}
	f, ok := s.files[path]
	return f, ok
}

// Publication returns the publication of method.
func (s *Snapshot) Publication(method string) (Publication, bool) {
	if s == nil {
		return Publication{}, false
	}
	p, ok := s.pubs[method]
	return p, ok
}

// Methods returns the published methods in order.
func (s *Snapshot) Methods() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.pubs))
	for m := range s.pubs {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// Paths returns every published path in order.
func (s *Snapshot) Paths() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.files))
	for p := range s.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// JoinURL appends path to base with exactly one slash between them.
func JoinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}
