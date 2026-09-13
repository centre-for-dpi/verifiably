// SPDX-License-Identifier: Apache-2.0

// Package did resolves did:web, did:key and did:jwk identifiers to DID
// documents (W3C DID Core 1.0, https://www.w3.org/TR/did-core/).
//
// Method specifications:
//   - did:web: https://w3c-ccg.github.io/did-method-web/
//   - did:key: https://w3c-ccg.github.io/did-key-spec/
//   - did:jwk: https://github.com/quartzjer/did-jwk/blob/main/spec.md
//
// Network access is injected as a Fetcher. Caching is injected as a Cache.
// The package holds no state of its own.
package did

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Fetcher performs an HTTP GET and returns the body.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Cache stores resolved documents. Implementations own the expiry policy.
type Cache interface {
	Get(did string) (Document, bool)
	Put(did string, doc Document)
}

// Document is the subset of a DID document needed for key resolution.
type Document struct {
	ID                 string               `json:"id"`
	Controller         []string             `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
}

// VerificationMethod is one key entry in a DID document.
type VerificationMethod struct {
	ID                 string         `json:"id"`
	Type               string         `json:"type"`
	Controller         string         `json:"controller,omitempty"`
	PublicKeyJWK       map[string]any `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string         `json:"publicKeyMultibase,omitempty"`
}

// ErrUnsupportedMethod reports a DID method this package does not resolve.
var ErrUnsupportedMethod = errors.New("did: unsupported method")

// Resolver resolves DIDs with an injected fetcher and cache.
type Resolver struct {
	fetch Fetcher
	cache Cache
}

// NewResolver builds a Resolver. fetch may be nil when did:web is not needed.
// cache may be nil to disable caching.
func NewResolver(fetch Fetcher, cache Cache) Resolver {
	return Resolver{fetch: fetch, cache: cache}
}

// Method returns the method name of a DID, for example "web".
func Method(did string) (string, error) {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) != 3 || parts[0] != "did" || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("did: %q is not a DID", did)
	}
	return parts[1], nil
}

// Resolve returns the DID document for did.
func (r Resolver) Resolve(ctx context.Context, did string) (Document, error) {
	method, err := Method(did)
	if err != nil {
		return Document{}, err
	}
	switch method {
	case "key":
		return KeyDocument(did)
	case "jwk":
		return JWKDocument(did)
	case "web":
		return r.resolveWeb(ctx, did)
	}
	return Document{}, fmt.Errorf("%w: %s", ErrUnsupportedMethod, method)
}

func (r Resolver) resolveWeb(ctx context.Context, did string) (Document, error) {
	if r.cache != nil {
		if doc, ok := r.cache.Get(did); ok {
			return doc, nil
		}
	}
	if r.fetch == nil {
		return Document{}, errors.New("did: no fetcher configured for did:web")
	}
	u, err := WebURL(did)
	if err != nil {
		return Document{}, err
	}
	raw, err := r.fetch(ctx, u)
	if err != nil {
		return Document{}, fmt.Errorf("did: fetch %s: %w", u, err)
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return Document{}, fmt.Errorf("did: %s: %w", u, err)
	}
	if r.cache != nil {
		r.cache.Put(did, doc)
	}
	return doc, nil
}

// WebURL converts a did:web identifier to its document URL
// (did:web method specification section 3.2).
//
//	did:web:example.com            -> https://example.com/.well-known/did.json
//	did:web:example.com:path:to    -> https://example.com/path/to/did.json
//	did:web:example.com%3A8443     -> https://example.com:8443/.well-known/did.json
func WebURL(did string) (string, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", fmt.Errorf("did: %q is not a did:web", did)
	}
	rest := strings.TrimPrefix(did, "did:web:")
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		rest = rest[:i]
	}
	parts := strings.Split(rest, ":")
	host, err := url.PathUnescape(parts[0])
	if err != nil || host == "" {
		return "", fmt.Errorf("did: %q has an invalid host", did)
	}
	if len(parts) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	for _, p := range parts[1:] {
		if p == "" {
			return "", fmt.Errorf("did: %q has an empty path segment", did)
		}
	}
	return "https://" + host + "/" + strings.Join(parts[1:], "/") + "/did.json", nil
}

// ParseDocument decodes a DID document. The id field is required.
func ParseDocument(raw []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("did: parse document: %w", err)
	}
	if doc.ID == "" {
		return Document{}, errors.New("did: document has no id")
	}
	return doc, nil
}

// Key returns the verification method named by id. id may be a full
// method id or a bare fragment such as "#key-1" or "key-1".
// An empty id returns the first method.
func (d Document) Key(id string) (VerificationMethod, bool) {
	if id == "" && len(d.VerificationMethod) > 0 {
		return d.VerificationMethod[0], true
	}
	frag := strings.TrimPrefix(id, "#")
	for _, vm := range d.VerificationMethod {
		if vm.ID == id || strings.TrimPrefix(vm.ID, d.ID+"#") == frag || strings.TrimPrefix(vm.ID, "#") == frag {
			return vm, true
		}
	}
	return VerificationMethod{}, false
}

// PublicKey extracts the public key of a verification method from its
// publicKeyJwk or publicKeyMultibase member.
func PublicKey(vm VerificationMethod) (crypto.PublicKey, error) {
	if vm.PublicKeyJWK != nil {
		k, err := jose.JWKFromMap(vm.PublicKeyJWK)
		if err != nil {
			return nil, err
		}
		return k.Key, nil
	}
	if vm.PublicKeyMultibase != "" {
		return decodeMultikey(vm.PublicKeyMultibase)
	}
	return nil, fmt.Errorf("did: verification method %q carries no public key", vm.ID)
}

// Multicodec prefixes as unsigned varints (https://github.com/multiformats/multicodec).
var (
	codecEd25519 = []byte{0xed, 0x01}
	codecP256    = []byte{0x80, 0x24}
)

// KeyDocument builds the DID document of a did:key (Ed25519 or P-256).
func KeyDocument(did string) (Document, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return Document{}, fmt.Errorf("did: %q is not a did:key", did)
	}
	mb := strings.TrimPrefix(did, "did:key:")
	if i := strings.IndexAny(mb, "#?"); i >= 0 {
		mb = mb[:i]
	}
	pub, err := decodeMultikey(mb)
	if err != nil {
		return Document{}, err
	}
	// decodeMultikey returns Ed25519 or P-256 keys only. Both convert.
	jwk, _ := jose.PublicJWK(pub, "")
	m, _ := jose.JWKToMap(jwk)
	id := "did:key:" + mb
	vmID := id + "#" + mb
	return Document{
		ID: id,
		VerificationMethod: []VerificationMethod{{
			ID: vmID, Type: "JsonWebKey2020", Controller: id, PublicKeyJWK: m,
		}},
		AssertionMethod: []string{vmID},
		Authentication:  []string{vmID},
	}, nil
}

// FromPublicKey returns the did:key of an Ed25519 or P-256 public key.
func FromPublicKey(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return "did:key:z" + base58Encode(append(append([]byte{}, codecEd25519...), k...)), nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("did: unsupported curve %s", k.Curve.Params().Name)
		}
		pt := elliptic.MarshalCompressed(k.Curve, k.X, k.Y)
		return "did:key:z" + base58Encode(append(append([]byte{}, codecP256...), pt...)), nil
	}
	return "", fmt.Errorf("did: unsupported key type %T", pub)
}

func decodeMultikey(mb string) (crypto.PublicKey, error) {
	if !strings.HasPrefix(mb, "z") {
		return nil, fmt.Errorf("did: multibase %q is not base58btc", mb)
	}
	raw, err := base58Decode(mb[1:])
	if err != nil {
		return nil, err
	}
	switch {
	case len(raw) == 2+ed25519.PublicKeySize && raw[0] == codecEd25519[0] && raw[1] == codecEd25519[1]:
		return ed25519.PublicKey(raw[2:]), nil
	case len(raw) == 2+33 && raw[0] == codecP256[0] && raw[1] == codecP256[1]:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw[2:])
		if x == nil {
			return nil, errors.New("did: invalid P-256 point")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}
	return nil, errors.New("did: unsupported multicodec key")
}

// JWKDocument builds the DID document of a did:jwk.
func JWKDocument(did string) (Document, error) {
	if !strings.HasPrefix(did, "did:jwk:") {
		return Document{}, fmt.Errorf("did: %q is not a did:jwk", did)
	}
	enc := strings.TrimPrefix(did, "did:jwk:")
	if i := strings.IndexAny(enc, "#?"); i >= 0 {
		enc = enc[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		// Some producers pad the value. Accept that too.
		if raw, err = base64.URLEncoding.DecodeString(enc); err != nil {
			return Document{}, fmt.Errorf("did: did:jwk base64url: %w", err)
		}
	}
	jwk, err := jose.ParseJWK(raw)
	if err != nil {
		return Document{}, err
	}
	if !jwk.IsPublic() {
		return Document{}, errors.New("did: did:jwk must carry a public key")
	}
	m, _ := jose.JWKToMap(jwk)
	id := "did:jwk:" + enc
	return Document{
		ID: id,
		VerificationMethod: []VerificationMethod{{
			ID: id + "#0", Type: "JsonWebKey2020", Controller: id, PublicKeyJWK: m,
		}},
		AssertionMethod: []string{id + "#0"},
		Authentication:  []string{id + "#0"},
	}, nil
}

// FromJWK returns the did:jwk of a public JWK object.
// The JSON keys are sorted, which is the order encoding/json uses for maps.
func FromJWK(pub map[string]any) (string, error) {
	if _, ok := pub["d"]; ok {
		return "", errors.New("did: did:jwk must not carry a private key")
	}
	if _, err := jose.JWKFromMap(pub); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(pub)
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// base58 (Bitcoin alphabet), used by multibase "z" (base58btc).
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	digits := []byte{0}
	for _, c := range b[zeros:] {
		carry := int(c)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	out := make([]byte, 0, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out = append(out, b58Alphabet[0])
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, b58Alphabet[digits[i]])
	}
	// A zero-only input has digits [0], which renders as one extra '1'.
	if len(b) == zeros {
		out = out[:zeros]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == b58Alphabet[0] {
		zeros++
	}
	bytesOut := []byte{0}
	for _, c := range []byte(s[zeros:]) {
		idx := strings.IndexByte(b58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("did: invalid base58 character %q", c)
		}
		carry := idx
		for i := range bytesOut {
			carry += int(bytesOut[i]) * 58
			bytesOut[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			bytesOut = append(bytesOut, byte(carry&0xff))
			carry >>= 8
		}
	}
	out := make([]byte, 0, zeros+len(bytesOut))
	for i := 0; i < zeros; i++ {
		out = append(out, 0)
	}
	for i := len(bytesOut) - 1; i >= 0; i-- {
		out = append(out, bytesOut[i])
	}
	if len(s) == zeros {
		out = out[:zeros]
	}
	return out, nil
}
