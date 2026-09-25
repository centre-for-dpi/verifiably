// SPDX-License-Identifier: Apache-2.0

// Package federation reads the trust lists of external registries
// (ADR-011 decision 7, owner spec AD2). An admin adds a registry with its
// list URL, its format, and a trust anchor. The package fetches the list
// through core/fetchguard, checks its signature against the anchor, and
// keeps the last good copy with the time of the check. A lookup consults
// the copies after the local lists and names the registry that answered.
//
// The entries of an external registry are read only: the service refuses
// a local edit of an entity that a registry names. A failed read keeps
// the last good copy and records the reason, so verification keeps
// working offline until the copy expires.
package federation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/dedi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/xmldsig"
)

// Method names the format of an external list.
type Method string

// Methods.
const (
	// MethodEtsiLoteJSON is an ETSI TS 119 602 list signed as a compact JWS.
	MethodEtsiLoteJSON Method = "etsi-lote-json"
	// MethodEtsiTslXML is an ETSI TS 119 612 XML list with an XML signature.
	MethodEtsiTslXML Method = "etsi-tsl-xml"
	// MethodDedi is a signed DeDi manifest with its directory files.
	MethodDedi Method = "dedi"
)

// Refresh bounds.
const (
	DefaultRefresh = 24 * time.Hour
	MinRefresh     = 5 * time.Minute
)

// SourcePrefix starts the source of an external entry: registry:<id>.
const SourcePrefix = "registry:"

// Errors.
var (
	ErrInvalid  = errors.New("federation: the registry is not valid")
	ErrNotFound = errors.New("federation: no registry has this id")
	ErrReadOnly = errors.New("federation: an external registry owns this entity")
)

// Registry is one external registry with the state of its last read.
type Registry struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Method  Method        `json:"method"`
	URL     string        `json:"url"`
	JWKSURL string        `json:"jwks_url,omitempty"`
	X509PEM string        `json:"x509_pem,omitempty"`
	Refresh time.Duration `json:"refresh"`
	// LastSync is the time of the last good read.
	LastSync time.Time `json:"last_sync,omitzero"`
	// LastRead is the time of the last read, good or failed.
	LastRead time.Time `json:"last_read,omitzero"`
	// LastError is the reason of the last failed read, or empty.
	LastError  string `json:"last_error,omitempty"`
	EntryCount int    `json:"entry_count"`
	// SignedBy is the key id or the certificate subject of the copy.
	SignedBy string `json:"signed_by,omitempty"`
}

// Snapshot is the last good copy of one registry.
type Snapshot struct {
	Entries   []entry.Entry `json:"entries"`
	ListURL   string        `json:"list_url"`
	SignedBy  string        `json:"signed_by"`
	CheckedAt time.Time     `json:"checked_at"`
	// ExpiresAt is the end of validity the list states. Zero means none.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Result is the answer of Lookup with its provenance.
type Result struct {
	entry.Result
	Registry  Registry
	Method    Method
	ListURL   string
	SignedBy  string
	CheckedAt time.Time
}

// Options configure a federation.
type Options struct {
	// Backend keeps the registries and their copies.
	Backend sharedstore.Document
	// Fetcher reads every list, JWKS and manifest.
	Fetcher *fetchguard.Fetcher
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// document is the saved state.
type document struct {
	Registries map[string]Registry `json:"registries"`
	Snapshots  map[string]Snapshot `json:"snapshots"`
}

// Federation holds the external registries.
type Federation struct {
	opts Options
	mu   sync.RWMutex
	doc  document
	// syncing serializes the reads of one registry.
	syncing sync.Mutex
}

// New loads the saved registries.
func New(opts Options) (*Federation, error) {
	if opts.Backend == nil {
		opts.Backend = sharedstore.MemoryDoc()
	}
	if opts.Fetcher == nil {
		opts.Fetcher = fetchguard.New(fetchguard.Options{})
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	doc := document{Registries: map[string]Registry{}, Snapshots: map[string]Snapshot{}}
	data, found, err := opts.Backend.Load()
	if err != nil {
		return nil, err
	}
	if found {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("federation: parse state: %w", err)
		}
		if doc.Registries == nil {
			doc.Registries = map[string]Registry{}
		}
		if doc.Snapshots == nil {
			doc.Snapshots = map[string]Snapshot{}
		}
	}
	return &Federation{opts: opts, doc: doc}, nil
}

// validate checks the fields an admin gives and fills the refresh.
func validate(r Registry) (Registry, error) {
	r.Name = strings.TrimSpace(r.Name)
	r.URL = strings.TrimSpace(r.URL)
	r.JWKSURL = strings.TrimSpace(r.JWKSURL)
	r.X509PEM = strings.TrimSpace(r.X509PEM)
	switch {
	case r.Name == "":
		return r, fmt.Errorf("%w: the name is empty", ErrInvalid)
	case r.URL == "":
		return r, fmt.Errorf("%w: the URL is empty", ErrInvalid)
	case (r.JWKSURL == "") == (r.X509PEM == ""):
		return r, fmt.Errorf("%w: set exactly one anchor, a JWKS URL or an X.509 certificate", ErrInvalid)
	}
	switch r.Method {
	case MethodEtsiLoteJSON, MethodDedi:
	case MethodEtsiTslXML:
		if r.X509PEM == "" {
			return r, fmt.Errorf("%w: an ETSI TS 119 612 list needs an X.509 anchor", ErrInvalid)
		}
	default:
		return r, fmt.Errorf("%w: unknown method %q", ErrInvalid, r.Method)
	}
	if r.JWKSURL != "" {
		if u, err := url.Parse(r.JWKSURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return r, fmt.Errorf("%w: the JWKS URL %q is not an http or https URL", ErrInvalid, r.JWKSURL)
		}
	}
	if r.X509PEM != "" {
		if _, err := parseCertificates(r.X509PEM); err != nil {
			return r, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	if r.Refresh == 0 {
		r.Refresh = DefaultRefresh
	}
	if r.Refresh < MinRefresh {
		return r, fmt.Errorf("%w: the refresh is shorter than %s", ErrInvalid, MinRefresh)
	}
	return r, nil
}

// parseCertificates reads every CERTIFICATE block of a PEM text.
func parseCertificates(text string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the anchor certificate does not parse: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("the anchor holds no PEM certificate")
	}
	return out, nil
}

// newID returns a short random id.
func newID() string {
	var b [8]byte
	// crypto/rand never fails on the supported platforms.
	_, ignored := rand.Read(b[:])
	_ = ignored
	return hex.EncodeToString(b[:])
}

// Add stores a registry and reads its list once. A failed read does not
// fail Add: the registry keeps the reason in LastError.
func (f *Federation) Add(ctx context.Context, r Registry) (Registry, error) {
	r, err := validate(r)
	if err != nil {
		return Registry{}, err
	}
	r.ID = newID()
	r.LastSync, r.LastRead, r.LastError, r.EntryCount, r.SignedBy = time.Time{}, time.Time{}, "", 0, ""
	if err := f.update(func(d *document) { d.Registries[r.ID] = r }); err != nil {
		return Registry{}, err
	}
	return f.Sync(ctx, r.ID)
}

// List returns the registries ordered by name.
func (f *Federation) List() []Registry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Registry, 0, len(f.doc.Registries))
	for _, r := range f.doc.Registries {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one registry.
func (f *Federation) Get(id string) (Registry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r, ok := f.doc.Registries[id]
	return r, ok
}

// Remove drops a registry and its copy. found is false for an unknown id.
func (f *Federation) Remove(id string) (found bool, err error) {
	if _, ok := f.Get(id); !ok {
		return false, nil
	}
	return true, f.update(func(d *document) {
		delete(d.Registries, id)
		delete(d.Snapshots, id)
	})
}

// Sync reads the list of one registry now. The error is for an unknown
// id or a store fault. A failed read sets LastError and keeps the copy.
func (f *Federation) Sync(ctx context.Context, id string) (Registry, error) {
	f.syncing.Lock()
	defer f.syncing.Unlock()
	r, ok := f.Get(id)
	if !ok {
		return Registry{}, ErrNotFound
	}
	now := f.opts.Now()
	snap, err := f.read(ctx, r, now)
	r.LastRead = now
	if err != nil {
		r.LastError = err.Error()
	} else {
		r.LastError, r.LastSync, r.EntryCount, r.SignedBy = "", now, len(snap.Entries), snap.SignedBy
	}
	uerr := f.update(func(d *document) {
		if _, still := d.Registries[id]; !still {
			return
		}
		d.Registries[id] = r
		if err == nil {
			d.Snapshots[id] = snap
		}
	})
	if uerr != nil {
		return Registry{}, uerr
	}
	return r, nil
}

// SyncDue reads every registry whose refresh interval passed since its
// last read. It returns the number of reads.
func (f *Federation) SyncDue(ctx context.Context) int {
	now := f.opts.Now()
	n := 0
	for _, r := range f.List() {
		if !r.LastRead.IsZero() && now.Sub(r.LastRead) < r.Refresh {
			continue
		}
		if _, err := f.Sync(ctx, r.ID); err == nil {
			n++
		}
	}
	return n
}

// Owner returns the registry whose copy names an entity id.
func (f *Federation) Owner(id string) (Registry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for rid, snap := range f.doc.Snapshots {
		for _, e := range snap.Entries {
			if e.ID() == id {
				return f.doc.Registries[rid], true
			}
		}
	}
	return Registry{}, false
}

// CheckWritable fails with ErrReadOnly when an external registry owns id.
func (f *Federation) CheckWritable(id string) error {
	if r, ok := f.Owner(id); ok {
		return fmt.Errorf("%w: %s lists %s", ErrReadOnly, r.Name, id)
	}
	return nil
}

// Lookup answers from the copies that have not expired. A trusted answer
// wins; otherwise the first untrusted answer in name order. ok is false
// when no copy names the entity.
func (f *Federation) Lookup(id string, role entry.Role, credentialType string, at time.Time) (Result, bool) {
	now := f.opts.Now()
	var best Result
	found := false
	for _, r := range f.List() {
		f.mu.RLock()
		snap, ok := f.doc.Snapshots[r.ID]
		f.mu.RUnlock()
		if !ok || (!snap.ExpiresAt.IsZero() && now.After(snap.ExpiresAt)) {
			continue
		}
		res := entry.Evaluate(snap.Entries, id, role, credentialType, at)
		if res.Outcome == entry.Unknown {
			continue
		}
		out := Result{Result: res, Registry: r, Method: r.Method, ListURL: snap.ListURL, SignedBy: snap.SignedBy, CheckedAt: snap.CheckedAt}
		if res.Outcome == entry.Trusted {
			return out, true
		}
		if !found {
			best, found = out, true
		}
	}
	return best, found
}

// Copy is one registry with its last good copy.
type Copy struct {
	Registry Registry
	Snapshot Snapshot
}

// Copies returns every registry with a good copy that has not expired,
// in name order. The signed snapshot of the service carries them.
func (f *Federation) Copies() []Copy {
	now := f.opts.Now()
	var out []Copy
	for _, r := range f.List() {
		f.mu.RLock()
		snap, ok := f.doc.Snapshots[r.ID]
		f.mu.RUnlock()
		if !ok || (!snap.ExpiresAt.IsZero() && now.After(snap.ExpiresAt)) {
			continue
		}
		out = append(out, Copy{Registry: r, Snapshot: snap})
	}
	return out
}

// update applies change to a copy of the state and saves it.
func (f *Federation) update(change func(*document)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	next := document{Registries: map[string]Registry{}, Snapshots: map[string]Snapshot{}}
	for k, v := range f.doc.Registries {
		next.Registries[k] = v
	}
	for k, v := range f.doc.Snapshots {
		next.Snapshots[k] = v
	}
	change(&next)
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("federation: encode state: %w", err)
	}
	if err := f.opts.Backend.Save(data); err != nil {
		return err
	}
	f.doc = next
	return nil
}

// read fetches and checks the list of one registry.
func (f *Federation) read(ctx context.Context, r Registry, now time.Time) (Snapshot, error) {
	var (
		snap Snapshot
		err  error
	)
	switch r.Method {
	case MethodEtsiLoteJSON:
		snap, err = f.readLote(ctx, r, now)
	case MethodDedi:
		snap, err = f.readDedi(ctx, r, now)
	default:
		snap, err = f.readTSL(ctx, r, now)
	}
	if err != nil {
		return Snapshot{}, err
	}
	snap.CheckedAt = now
	for i := range snap.Entries {
		snap.Entries[i].Source = SourcePrefix + r.ID
	}
	return snap, nil
}

// get fetches one document, always from the server.
func (f *Federation) get(ctx context.Context, raw string) ([]byte, error) {
	f.opts.Fetcher.Forget(raw)
	doc, err := f.opts.Fetcher.Get(ctx, raw)
	if err != nil {
		return nil, err
	}
	return doc.Body, nil
}

// jwks fetches the key set of a registry.
func (f *Federation) jwks(ctx context.Context, r Registry) (jose.JWKS, error) {
	body, err := f.get(ctx, r.JWKSURL)
	if err != nil {
		return jose.JWKS{}, err
	}
	set, err := jose.ParseJWKS(body)
	if err != nil {
		return jose.JWKS{}, fmt.Errorf("federation: the JWKS at %s: %w", r.JWKSURL, err)
	}
	return set, nil
}

// anchor returns the first anchor certificate, valid at now.
func anchor(r Registry, now time.Time) (*x509.Certificate, error) {
	certs, err := parseCertificates(r.X509PEM)
	if err != nil {
		return nil, err
	}
	c := certs[0]
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return nil, fmt.Errorf("federation: the anchor certificate %s is not valid now", c.Subject)
	}
	return c, nil
}

// readLote checks an ETSI TS 119 602 list signed as a compact JWS.
func (f *Federation) readLote(ctx context.Context, r Registry, now time.Time) (Snapshot, error) {
	body, err := f.get(ctx, r.URL)
	if err != nil {
		return Snapshot{}, err
	}
	claims, signedBy, err := f.checkLote(ctx, r, strings.TrimSpace(string(body)), now)
	if err != nil {
		return Snapshot{}, err
	}
	entries, err := etsi.ToEntries(claims.Entities)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Entries: entries, ListURL: r.URL, SignedBy: signedBy, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}, nil
}

// checkLote checks the JWS of a list against the anchor of r and names
// the key or the certificate that signed it.
func (f *Federation) checkLote(ctx context.Context, r Registry, token string, now time.Time) (etsi.Claims, string, error) {
	if r.JWKSURL != "" {
		set, err := f.jwks(ctx, r)
		if err != nil {
			return etsi.Claims{}, "", err
		}
		claims, hdr, err := etsi.VerifyJWS(token, set, now)
		return claims, hdr.Kid, err
	}
	cert, err := anchor(r, now)
	if err != nil {
		return etsi.Claims{}, "", err
	}
	claims, _, err := etsi.VerifyJWSKey(token, cert.PublicKey, now)
	return claims, cert.Subject.String(), err
}

// readDedi checks a DeDi manifest and every directory file it lists. The
// directory files must sit on the host of the manifest.
func (f *Federation) readDedi(ctx context.Context, r Registry, now time.Time) (Snapshot, error) {
	manifestURL := r.URL
	if !strings.HasSuffix(manifestURL, ".json") {
		manifestURL = publish.JoinURL(manifestURL, dedi.IndexPath)
	}
	base, err := url.Parse(manifestURL)
	if err != nil {
		return Snapshot{}, fmt.Errorf("federation: the manifest URL: %w", err)
	}
	body, err := f.get(ctx, manifestURL)
	if err != nil {
		return Snapshot{}, err
	}
	// The clear copy names the files to fetch. The check below reads the
	// signed copy, so a changed clear copy cannot add an entry.
	var env struct {
		Document dedi.Index     `json:"document"`
		Proof    dedi.Signature `json:"proof"`
	}
	if err = json.Unmarshal(body, &env); err != nil {
		return Snapshot{}, fmt.Errorf("federation: the manifest does not parse: %w", err)
	}
	files := map[string]publish.File{dedi.IndexPath: {Body: body}}
	for _, d := range env.Document.Directories {
		dir, derr := f.directory(ctx, base, d)
		if derr != nil {
			return Snapshot{}, derr
		}
		files[dedi.DirectoryPath(d.Name)] = publish.File{Body: dir}
	}
	set, signedBy, err := f.dediKeys(ctx, r, env.Proof.KeyID, now)
	if err != nil {
		return Snapshot{}, err
	}
	v, err := dedi.Publisher{}.Verify(files, set, now)
	if err != nil {
		return Snapshot{}, err
	}
	if signedBy == "" {
		signedBy = v.KeyID
	}
	return Snapshot{Entries: v.Entries, ListURL: manifestURL, SignedBy: signedBy, ExpiresAt: v.ExpiresAt}, nil
}

// directory fetches one directory file of a manifest. The file must sit
// on the host of the manifest.
func (f *Federation) directory(ctx context.Context, base *url.URL, d dedi.Directory) ([]byte, error) {
	target := d.URL
	if target == "" {
		target = dedi.DirectoryPath(d.Name)
	}
	u, err := base.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("federation: the URL of the directory %s: %w", d.Name, err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return nil, fmt.Errorf("federation: the directory %s sits on the host %s, not on the manifest host %s", d.Name, u.Host, base.Host)
	}
	return f.get(ctx, u.String())
}

// dediKeys returns the key set that checks the DeDi files of r. An X.509
// anchor gives a set with its one key under the kid of the files.
func (f *Federation) dediKeys(ctx context.Context, r Registry, kid string, now time.Time) (jose.JWKS, string, error) {
	if r.JWKSURL != "" {
		set, err := f.jwks(ctx, r)
		return set, "", err
	}
	cert, err := anchor(r, now)
	if err != nil {
		return jose.JWKS{}, "", err
	}
	jwk, err := jose.PublicJWK(cert.PublicKey, kid)
	if err != nil {
		return jose.JWKS{}, "", fmt.Errorf("federation: the anchor key: %w", err)
	}
	return jose.JWKS{Keys: []jose.JWK{jwk}}, cert.Subject.String(), nil
}

// readTSL checks an ETSI TS 119 612 XML list against the X.509 anchors
// and imports its services as issuer entries.
func (f *Federation) readTSL(ctx context.Context, r Registry, now time.Time) (Snapshot, error) {
	body, err := f.get(ctx, r.URL)
	if err != nil {
		return Snapshot{}, err
	}
	anchors, err := parseCertificates(r.X509PEM)
	if err != nil {
		return Snapshot{}, err
	}
	signer, err := xmldsig.Verify(body, anchors, now)
	if err != nil {
		return Snapshot{}, err
	}
	tl, err := etsi.ParseTrustedList(body)
	if err != nil {
		return Snapshot{}, err
	}
	var expires time.Time
	if next := strings.TrimSpace(tl.SchemeInformation.NextUpdate); next != "" {
		t, err := time.Parse(time.RFC3339, next)
		if err != nil {
			return Snapshot{}, fmt.Errorf("federation: the next update %q is not a time", next)
		}
		if now.After(t) {
			return Snapshot{}, fmt.Errorf("federation: the list expired at %s", next)
		}
		expires = t
	}
	entries, _ := etsi.Import(tl, now)
	return Snapshot{Entries: entries, ListURL: r.URL, SignedBy: signer.Subject.String(), ExpiresAt: expires}, nil
}
