// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/trustsnap"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/ports"
)

// Sync reads every source of kind now, or of every kind when kind is
// empty. It returns the number of sources whose read failed or whose
// copy was refused. The error is for a store fault.
func (c *Cache) Sync(ctx context.Context, kind Kind) (int, error) {
	kinds := Kinds()
	if kind != "" {
		kinds = []Kind{kind}
	}
	failed := 0
	for _, k := range kinds {
		n, err := c.syncKind(ctx, k)
		failed += n
		if err != nil {
			return failed, err
		}
	}
	return failed, nil
}

// syncKind reads one kind and records the run for the schedule.
func (c *Cache) syncKind(ctx context.Context, k Kind) (int, error) {
	c.syncing.Lock()
	defer c.syncing.Unlock()
	var (
		failed int
		err    error
	)
	switch k {
	case KindTrust:
		failed, err = c.syncTrust(ctx)
	case KindKeys:
		failed, err = c.syncKeys(ctx)
	case KindStatus:
		failed, err = c.syncStatus(ctx)
	default:
		return 0, fmt.Errorf("cache: the kind %q is not known", k)
	}
	c.mu.Lock()
	c.runs[k] = c.now()
	c.mu.Unlock()
	return failed, err
}

// read reads one source with check and stores the outcome. A failed
// read or a refused copy keeps the last good copy and sets LastError.
// It returns 1 for a failure.
func (c *Cache) read(ctx context.Context, base Source, check func(context.Context) (Source, error)) (int, error) {
	s, ok := c.load(ctx, base.Kind, base.Key)
	if !ok {
		s = base
	}
	if base.RegistryID != "" || base.RegistryName != "" {
		s.RegistryID, s.RegistryName = base.RegistryID, base.RegistryName
	}
	if base.Issuer != "" {
		s.Issuer = base.Issuer
	}
	s.ReadAt = c.now()
	got, err := check(ctx)
	failed := 0
	if err != nil {
		s.LastError = err.Error()
		failed = 1
		c.opts.Log.Warn("cache: a read failed, the last good copy stays", "kind", s.Kind, "source", s.Key, "error", err)
	} else {
		s.Body, s.SignedBy, s.Items, s.LastError, s.SyncedAt = got.Body, got.SignedBy, got.Items, "", s.ReadAt
		if got.Issuer != "" {
			s.Issuer = got.Issuer
		}
	}
	return failed, c.save(ctx, s)
}

// syncTrust reads the signed snapshot and checks it with the key set of
// the trust registry.
func (c *Cache) syncTrust(ctx context.Context) (int, error) {
	if c.opts.Snapshot == nil {
		return 0, nil
	}
	return c.read(ctx, Source{Kind: KindTrust, Key: c.opts.TrustURL}, func(ctx context.Context) (Source, error) {
		set, err := c.registryKeys(ctx)
		if err != nil {
			return Source{}, err
		}
		token, err := c.opts.Snapshot(ctx)
		if err != nil {
			return Source{}, fmt.Errorf("cache: the trust registry did not answer: %w", err)
		}
		claims, kid, err := trustsnap.Verify(token, set, c.now())
		if err != nil {
			return Source{}, err
		}
		return Source{Body: []byte(token), SignedBy: kid, Items: claims.Count()}, nil
	})
}

// registryKeys returns the key set of the trust registry: a fresh read,
// or the stored copy when the registry does not answer.
func (c *Cache) registryKeys(ctx context.Context) (jose.JWKS, error) {
	raw, err := c.opts.Fetch(ctx, c.jwksURL())
	if err != nil {
		stored, ok := c.load(ctx, KindKeys, c.jwksURL())
		if !ok || !stored.Good() {
			return jose.JWKS{}, fmt.Errorf("cache: the key set of the trust registry: %w", err)
		}
		raw = stored.Body
	}
	return jose.ParseJWKS(raw)
}

// claims returns the stored trust snapshot, or false.
func (c *Cache) claims(ctx context.Context) (trustsnap.Claims, bool) {
	s, ok := c.load(ctx, KindTrust, c.opts.TrustURL)
	if !ok || !s.Good() {
		return trustsnap.Claims{}, false
	}
	claims, err := decodeClaims(s.Body)
	return claims, err == nil
}

// decodeClaims reads the payload of a snapshot that a sync checked.
func decodeClaims(token []byte) (trustsnap.Claims, error) {
	payload, err := jose.PeekPayload(string(token))
	if err != nil {
		return trustsnap.Claims{}, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return trustsnap.Claims{}, err
	}
	var out trustsnap.Claims
	err = json.Unmarshal(raw, &out)
	return out, err
}

// trustIssuers counts the issuers of the stored snapshot.
func (c *Cache) trustIssuers(ctx context.Context) int {
	claims, ok := c.claims(ctx)
	if !ok {
		return 0
	}
	return len(claims.Issuers())
}

// networkIssuer reports whether the keys of an issuer need the network:
// a did:web or an https issuer. did:key and did:jwk carry their key.
func networkIssuer(id string) bool {
	return strings.HasPrefix(id, "did:web:") || strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://")
}

// syncKeys reads the key set of the trust registry, the keys of every
// listed or remembered issuer, and the anchor chains of the external
// registries.
func (c *Cache) syncKeys(ctx context.Context) (int, error) {
	failed := 0
	add := func(n int, err error) error {
		failed += n
		return err
	}
	if c.opts.Snapshot != nil {
		if err := add(c.read(ctx, Source{Kind: KindKeys, Key: c.jwksURL()}, func(ctx context.Context) (Source, error) {
			raw, err := c.opts.Fetch(ctx, c.jwksURL())
			if err != nil {
				return Source{}, err
			}
			set, err := jose.ParseJWKS(raw)
			if err != nil || len(set.Keys) == 0 {
				return Source{}, errors.New("cache: the key set of the trust registry holds no key")
			}
			return Source{Body: raw, Items: len(set.Keys)}, nil
		})); err != nil {
			return failed, err
		}
	}
	targets, err := c.keyTargets(ctx)
	if err != nil {
		return failed, err
	}
	for _, t := range targets {
		if err := add(c.read(ctx, t, func(ctx context.Context) (Source, error) {
			return c.issuerKeys(ctx, t.Key)
		})); err != nil {
			return failed, err
		}
	}
	claims, _ := c.claims(ctx)
	for _, ch := range claims.Chains() {
		base := Source{Kind: KindKeys, Key: "x509:" + ch.RegistryID, RegistryID: ch.RegistryID, RegistryName: ch.RegistryName}
		if err := add(c.read(ctx, base, func(context.Context) (Source, error) {
			return checkChain(ch.PEM, c.now())
		})); err != nil {
			return failed, err
		}
	}
	return failed, nil
}

// keyTargets returns the issuers whose keys a sync reads: the issuers
// of the snapshot, then the remembered ones.
func (c *Cache) keyTargets(ctx context.Context) ([]Source, error) {
	seen := map[string]bool{c.jwksURL(): true}
	var out []Source
	claims, _ := c.claims(ctx)
	for _, is := range claims.Issuers() {
		if networkIssuer(is.ID) && !seen[is.ID] {
			seen[is.ID] = true
			out = append(out, Source{Kind: KindKeys, Key: is.ID, Issuer: is.ID, RegistryID: is.RegistryID, RegistryName: is.RegistryName})
		}
	}
	stored, err := c.sources(ctx, KindKeys)
	if err != nil {
		return nil, err
	}
	for _, s := range stored {
		if s.Issuer != "" && !seen[s.Key] {
			seen[s.Key] = true
			out = append(out, Source{Kind: KindKeys, Key: s.Key, Issuer: s.Issuer})
		}
	}
	return out, nil
}

// issuerKeys reads the keys of one issuer. A DID document must name the
// DID it was read for.
func (c *Cache) issuerKeys(ctx context.Context, issuer string) (Source, error) {
	if strings.HasPrefix(issuer, "did:web:") {
		u, err := did.WebURL(issuer)
		if err != nil {
			return Source{}, err
		}
		raw, err := c.opts.Fetch(ctx, u)
		if err != nil {
			return Source{}, err
		}
		doc, err := did.ParseDocument(raw)
		if err != nil {
			return Source{}, err
		}
		if doc.ID != issuer {
			return Source{}, fmt.Errorf("cache: the document at %s names %q, not %s", u, doc.ID, issuer)
		}
		set, err := ports.KeysOf(doc)
		if err != nil {
			return Source{}, err
		}
		return keySource(set, issuer)
	}
	raw, err := c.opts.Fetch(ctx, strings.TrimRight(issuer, "/")+ports.JWKSPath)
	if err != nil {
		return Source{}, err
	}
	set, err := jose.ParseJWKS(raw)
	if err != nil || len(set.Keys) == 0 {
		return Source{}, fmt.Errorf("cache: %s publishes no usable key", issuer)
	}
	return keySource(set, issuer)
}

// keySource stores a key set as JSON.
func keySource(set jose.JWKS, issuer string) (Source, error) {
	raw, err := json.Marshal(set)
	if err != nil {
		return Source{}, fmt.Errorf("cache: encode the keys of %s: %w", issuer, err)
	}
	return Source{Body: raw, SignedBy: issuer, Items: len(set.Keys), Issuer: issuer}, nil
}

// checkChain checks PEM anchor certificates: each one is valid at now
// and signed by the next one. The last one is the anchor.
func checkChain(text string, now time.Time) (Source, error) {
	var certs []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Source{}, fmt.Errorf("cache: an anchor certificate does not parse: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return Source{}, errors.New("cache: the anchor holds no certificate")
	}
	for i, cert := range certs {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return Source{}, fmt.Errorf("cache: the certificate %s is not valid now", cert.Subject)
		}
		if i+1 < len(certs) {
			if err := cert.CheckSignatureFrom(certs[i+1]); err != nil {
				return Source{}, fmt.Errorf("cache: %s does not sign %s", certs[i+1].Subject, cert.Subject)
			}
		}
	}
	last := certs[len(certs)-1]
	return Source{Body: []byte(text), SignedBy: last.Subject.String(), Items: len(certs)}, nil
}

// syncStatus reads the status lists of the listed issuers and the
// remembered lists. A signed list must verify with the issuer keys.
func (c *Cache) syncStatus(ctx context.Context) (int, error) {
	seen := map[string]bool{}
	var targets []Source
	claims, _ := c.claims(ctx)
	for _, is := range claims.Issuers() {
		for _, u := range is.StatusLists {
			if !seen[u] {
				seen[u] = true
				targets = append(targets, Source{Kind: KindStatus, Key: u, Issuer: is.ID, RegistryID: is.RegistryID, RegistryName: is.RegistryName})
			}
		}
	}
	stored, err := c.sources(ctx, KindStatus)
	if err != nil {
		return 0, err
	}
	for _, s := range stored {
		if !seen[s.Key] {
			seen[s.Key] = true
			targets = append(targets, Source{Kind: KindStatus, Key: s.Key})
		}
	}
	failed := 0
	for _, t := range targets {
		n, err := c.read(ctx, t, func(ctx context.Context) (Source, error) {
			return c.statusList(ctx, t.Key)
		})
		failed += n
		if err != nil {
			return failed, err
		}
	}
	return failed, nil
}

// statusList reads one status list and checks its signature.
func (c *Cache) statusList(ctx context.Context, url string) (Source, error) {
	raw, err := c.opts.Fetch(ctx, url)
	if err != nil {
		return Source{}, err
	}
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "{") {
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			return Source{}, errors.New("cache: the status list document does not parse")
		}
		return Source{Body: raw, SignedBy: NotChecked, Items: 1, Issuer: issuerOf(doc)}, nil
	}
	hdr, err := jose.PeekHeader(text)
	if err != nil {
		return Source{}, errors.New("cache: the status list token does not parse")
	}
	payload, err := jose.PeekPayload(text)
	if err != nil {
		return Source{}, errors.New("cache: the status list token does not parse")
	}
	issuer := issuerOf(payload)
	if issuer == "" {
		return Source{}, errors.New("cache: the status list names no issuer")
	}
	if err := c.verifyStatus(ctx, text, issuer); err != nil {
		return Source{}, err
	}
	return Source{Body: raw, SignedBy: hdr.Kid, Items: 1, Issuer: issuer}, nil
}

// verifyStatus checks a status list token with the stored keys of its
// issuer, and then with a fresh read of the keys, so a rotated key
// passes.
func (c *Cache) verifyStatus(ctx context.Context, token, issuer string) error {
	if s, ok := c.load(ctx, KindKeys, issuer); ok && s.Good() {
		var set jose.JWKS
		if json.Unmarshal(s.Body, &set) == nil {
			if _, _, err := jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms); err == nil {
				return nil
			}
		}
	}
	fresh, err := c.issuerKeys(ctx, issuer)
	if err != nil {
		return fmt.Errorf("cache: the keys of %s: %w", issuer, err)
	}
	var set jose.JWKS
	if err := json.Unmarshal(fresh.Body, &set); err != nil {
		return fmt.Errorf("cache: the keys of %s: %w", issuer, err)
	}
	if _, _, err := jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms); err != nil {
		return errors.New("cache: the status list signature is not valid")
	}
	return nil
}

// issuerOf returns the issuer of a status list: iss, or the issuer of
// a credential as a string or an object with an id.
func issuerOf(doc map[string]any) string {
	if iss, ok := doc["iss"].(string); ok && iss != "" {
		return iss
	}
	switch v := doc["issuer"].(type) {
	case string:
		return v
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			return id
		}
	}
	return ""
}
