// SPDX-License-Identifier: Apache-2.0

// Package sdjwt parses and verifies Selective Disclosure JWTs
// (RFC 9901, https://www.rfc-editor.org/rfc/rfc9901).
//
// It resolves disclosures against the _sd digests of the issuer payload
// and verifies the Key Binding JWT: issuer signature, disclosure digests,
// cnf key, typ, aud, nonce, iat and sd_hash. The legacy code decoded
// disclosures without a digest match and never verified the KB-JWT.
//
// The package is pure. Key lookup is injected as a KeyResolver.
package sdjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// TypeKB is the typ header of a Key Binding JWT (RFC 9901 section 4.3).
const TypeKB = "kb+jwt"

// DefaultAlg is the digest algorithm used when _sd_alg is absent.
const DefaultAlg = "sha-256"

// Errors returned by Verify.
var (
	ErrNoKeyBinding      = errors.New("sdjwt: key binding JWT missing")
	ErrKeyBindingInvalid = errors.New("sdjwt: key binding JWT invalid")
	ErrExpired           = errors.New("sdjwt: issuer JWT expired")
	ErrNotYetValid       = errors.New("sdjwt: issuer JWT not yet valid")
)

// Disclosure is one decoded disclosure.
type Disclosure struct {
	Encoded string // base64url form as it appears in the token
	Salt    string
	Name    string // empty for an array element disclosure
	Value   any
}

// Presentation is a parsed SD-JWT or SD-JWT+KB.
type Presentation struct {
	IssuerJWT     string
	Disclosures   []Disclosure
	KeyBindingJWT string // empty when absent
}

// Parse splits a compact SD-JWT. The token must end with "~" or carry a
// Key Binding JWT after the last "~".
func Parse(tok string) (Presentation, error) {
	tok = strings.TrimSpace(tok)
	parts := strings.Split(tok, "~")
	if len(parts) < 2 {
		return Presentation{}, errors.New("sdjwt: token has no ~ separator")
	}
	if strings.Count(parts[0], ".") != 2 {
		return Presentation{}, errors.New("sdjwt: issuer JWT is not a compact JWS")
	}
	p := Presentation{IssuerJWT: parts[0]}
	last := parts[len(parts)-1]
	if last != "" {
		if strings.Count(last, ".") != 2 {
			return Presentation{}, errors.New("sdjwt: trailing segment is neither empty nor a key binding JWT")
		}
		p.KeyBindingJWT = last
	}
	for _, seg := range parts[1 : len(parts)-1] {
		d, err := ParseDisclosure(seg)
		if err != nil {
			return Presentation{}, err
		}
		p.Disclosures = append(p.Disclosures, d)
	}
	return p, nil
}

// ParseDisclosure decodes one base64url disclosure (section 4.2).
func ParseDisclosure(seg string) (Disclosure, error) {
	if seg == "" {
		return Disclosure{}, errors.New("sdjwt: empty disclosure")
	}
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure base64url: %w", err)
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure JSON: %w", err)
	}
	if len(arr) != 2 && len(arr) != 3 {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure has %d elements, want 2 or 3", len(arr))
	}
	salt, _ := arr[0].(string)
	if salt == "" {
		return Disclosure{}, errors.New("sdjwt: disclosure salt must be a non-empty string")
	}
	if len(arr) == 3 {
		name, _ := arr[1].(string)
		if name == "" || name == "_sd" || name == "..." {
			return Disclosure{}, fmt.Errorf("sdjwt: disclosure name %q is not allowed", name)
		}
		return Disclosure{Encoded: seg, Salt: salt, Name: name, Value: arr[2]}, nil
	}
	return Disclosure{Encoded: seg, Salt: salt, Value: arr[1]}, nil
}

// NewDisclosure builds a disclosure with a random 128 bit salt.
// name is empty for an array element.
func NewDisclosure(name string, value any) (Disclosure, error) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	s := base64.RawURLEncoding.EncodeToString(salt)
	arr := []any{s, name, value}
	if name == "" {
		arr = []any{s, value}
	}
	raw, err := json.Marshal(arr)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwt: disclosure value: %w", err)
	}
	return Disclosure{Encoded: base64.RawURLEncoding.EncodeToString(raw), Salt: s, Name: name, Value: value}, nil
}

func hasher(alg string) (func() hash.Hash, error) {
	switch alg {
	case DefaultAlg:
		return sha256.New, nil
	case "sha-384":
		return sha512.New384, nil
	case "sha-512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("sdjwt: unsupported _sd_alg %q", alg)
}

// Digest hashes an encoded disclosure (section 4.2.3).
func Digest(alg string, encoded string) (string, error) {
	h, err := hasher(alg)
	if err != nil {
		return "", err
	}
	sum := h()
	sum.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil)), nil
}

// Conceal moves the named top-level claims of payload into disclosures.
// It returns the new payload with _sd digests and _sd_alg set.
func Conceal(payload map[string]any, names []string) (map[string]any, []Disclosure, error) {
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		out[k] = v
	}
	var digests []any
	var discs []Disclosure
	for _, n := range names {
		v, ok := payload[n]
		if !ok {
			return nil, nil, fmt.Errorf("sdjwt: claim %q not in payload", n)
		}
		d, err := NewDisclosure(n, v)
		if err != nil {
			return nil, nil, err
		}
		dg, _ := Digest(DefaultAlg, d.Encoded)
		digests = append(digests, dg)
		discs = append(discs, d)
		delete(out, n)
	}
	out["_sd"] = digests
	out["_sd_alg"] = DefaultAlg
	return out, discs, nil
}

// Serialize joins a presentation back into its compact form.
func Serialize(p Presentation) string {
	var b strings.Builder
	b.WriteString(p.IssuerJWT)
	b.WriteString("~")
	for _, d := range p.Disclosures {
		b.WriteString(d.Encoded)
		b.WriteString("~")
	}
	b.WriteString(p.KeyBindingJWT)
	return b.String()
}

// Resolve replaces the _sd digests in payload with the disclosed claims
// (section 7.1). Every disclosure must match one digest. It returns a new
// map and leaves payload unchanged.
func Resolve(payload map[string]any, discs []Disclosure) (map[string]any, error) {
	alg := DefaultAlg
	if a, ok := payload["_sd_alg"].(string); ok {
		alg = a
	}
	if _, err := hasher(alg); err != nil {
		return nil, err
	}
	byDigest := make(map[string]*Disclosure, len(discs))
	used := make(map[string]bool, len(discs))
	for i := range discs {
		dg, _ := Digest(alg, discs[i].Encoded)
		if _, dup := byDigest[dg]; dup {
			return nil, errors.New("sdjwt: duplicate disclosure")
		}
		byDigest[dg] = &discs[i]
	}
	r := resolver{byDigest: byDigest, used: used}
	out, err := r.object(payload)
	if err != nil {
		return nil, err
	}
	delete(out, "_sd_alg")
	if len(used) != len(byDigest) {
		return nil, errors.New("sdjwt: a disclosure matches no digest")
	}
	return out, nil
}

type resolver struct {
	byDigest map[string]*Disclosure
	used     map[string]bool
}

func (r resolver) object(m map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == "_sd" {
			continue
		}
		rv, err := r.value(v)
		if err != nil {
			return nil, err
		}
		out[k] = rv
	}
	sd, ok := m["_sd"]
	if !ok {
		return out, nil
	}
	list, ok := sd.([]any)
	if !ok {
		return nil, errors.New("sdjwt: _sd is not an array")
	}
	for _, e := range list {
		dg, ok := e.(string)
		if !ok {
			return nil, errors.New("sdjwt: _sd digest is not a string")
		}
		d, err := r.take(dg)
		if err != nil {
			return nil, err
		}
		if d == nil {
			continue
		}
		if d.Name == "" {
			return nil, errors.New("sdjwt: array disclosure used as object claim")
		}
		if _, exists := out[d.Name]; exists {
			return nil, fmt.Errorf("sdjwt: claim %q disclosed twice", d.Name)
		}
		rv, err := r.value(d.Value)
		if err != nil {
			return nil, err
		}
		out[d.Name] = rv
	}
	return out, nil
}

// take returns the disclosure for digest, or nil when it was not disclosed.
// A digest that appears twice in the payload is an error (section 7.1).
func (r resolver) take(digest string) (*Disclosure, error) {
	d, ok := r.byDigest[digest]
	if !ok {
		return nil, nil
	}
	if r.used[digest] {
		return nil, errors.New("sdjwt: digest referenced twice")
	}
	r.used[digest] = true
	return d, nil
}

func (r resolver) array(list []any) ([]any, error) {
	out := make([]any, 0, len(list))
	for _, e := range list {
		if m, ok := e.(map[string]any); ok && len(m) == 1 {
			if dg, ok := m["..."].(string); ok {
				d, err := r.take(dg)
				if err != nil {
					return nil, err
				}
				if d == nil {
					continue
				}
				if d.Name != "" {
					return nil, errors.New("sdjwt: object disclosure used as array element")
				}
				rv, err := r.value(d.Value)
				if err != nil {
					return nil, err
				}
				out = append(out, rv)
				continue
			}
		}
		rv, err := r.value(e)
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, nil
}

func (r resolver) value(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		return r.object(t)
	case []any:
		return r.array(t)
	}
	return v, nil
}

// KeyResolver returns the issuer public key for an issuer JWT. hdr and
// payload are unverified at this point. Callers use iss, kid and x5c.
type KeyResolver func(hdr jose.Header, payload map[string]any) (crypto.PublicKey, error)

// VerifyOptions configure Verify.
type VerifyOptions struct {
	IssuerKey         KeyResolver      // required
	Algs              []jose.Algorithm // default jose.SigningAlgorithms
	Now               time.Time        // zero: time.Now()
	Leeway            time.Duration    // clock skew tolerance, default 60s
	RequireKeyBinding bool
	Audience          string        // expected KB-JWT aud
	Nonce             string        // expected KB-JWT nonce
	MaxKeyBindingAge  time.Duration // zero: KB-JWT iat age is not bounded
}

// Result is a verified SD-JWT.
type Result struct {
	Header    jose.Header
	Claims    map[string]any // issuer claims with disclosures resolved
	HolderKey *jose.JWK      // cnf.jwk when present
	KeyBound  bool           // a KB-JWT was present and verified
	KBClaims  map[string]any
}

func (o VerifyOptions) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

func (o VerifyOptions) leeway() time.Duration {
	if o.Leeway == 0 {
		return 60 * time.Second
	}
	return o.Leeway
}

func (o VerifyOptions) algs() []jose.Algorithm {
	if len(o.Algs) == 0 {
		return jose.SigningAlgorithms
	}
	return o.Algs
}

// Verify parses and verifies an SD-JWT or SD-JWT+KB (section 7).
func Verify(tok string, opts VerifyOptions) (Result, error) {
	if opts.IssuerKey == nil {
		return Result{}, errors.New("sdjwt: IssuerKey resolver is required")
	}
	p, err := Parse(tok)
	if err != nil {
		return Result{}, err
	}
	hdr, err := jose.PeekHeader(p.IssuerJWT)
	if err != nil {
		return Result{}, err
	}
	unverified, err := jose.PeekPayload(p.IssuerJWT)
	if err != nil {
		return Result{}, err
	}
	key, err := opts.IssuerKey(hdr, unverified)
	if err != nil {
		return Result{}, fmt.Errorf("sdjwt: issuer key: %w", err)
	}
	raw, _, err := jose.Verify(p.IssuerJWT, key, opts.algs())
	if err != nil {
		return Result{}, err
	}
	// raw is the same payload PeekPayload parsed above, so it is an object.
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	if err := checkIssuerTimes(payload, opts); err != nil {
		return Result{}, err
	}
	claims, err := Resolve(payload, p.Disclosures)
	if err != nil {
		return Result{}, err
	}
	res := Result{Header: hdr, Claims: claims}
	if cnf, ok := payload["cnf"].(map[string]any); ok {
		if jwkMap, ok := cnf["jwk"].(map[string]any); ok {
			k, err := jose.JWKFromMap(jwkMap)
			if err != nil {
				return Result{}, fmt.Errorf("sdjwt: cnf.jwk: %w", err)
			}
			res.HolderKey = &k
		}
	}
	if p.KeyBindingJWT == "" {
		if opts.RequireKeyBinding {
			return Result{}, ErrNoKeyBinding
		}
		return res, nil
	}
	kb, err := verifyKeyBinding(p, payload, res.HolderKey, opts)
	if err != nil {
		return Result{}, err
	}
	res.KeyBound = true
	res.KBClaims = kb
	return res, nil
}

func checkIssuerTimes(payload map[string]any, opts VerifyOptions) error {
	now := opts.now()
	if exp, ok := payload["exp"].(float64); ok && now.After(time.Unix(int64(exp), 0).Add(opts.leeway())) {
		return ErrExpired
	}
	if nbf, ok := payload["nbf"].(float64); ok && now.Add(opts.leeway()).Before(time.Unix(int64(nbf), 0)) {
		return ErrNotYetValid
	}
	return nil
}

func verifyKeyBinding(p Presentation, payload map[string]any, holder *jose.JWK, opts VerifyOptions) (map[string]any, error) {
	if holder == nil {
		return nil, fmt.Errorf("%w: issuer JWT has no cnf.jwk", ErrKeyBindingInvalid)
	}
	raw, hdr, err := jose.Verify(p.KeyBindingJWT, holder.Key, opts.algs())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyBindingInvalid, err)
	}
	if hdr.Typ != TypeKB {
		return nil, fmt.Errorf("%w: typ %q is not %s", ErrKeyBindingInvalid, hdr.Typ, TypeKB)
	}
	var kb map[string]any
	if err := json.Unmarshal(raw, &kb); err != nil {
		return nil, fmt.Errorf("%w: payload: %w", ErrKeyBindingInvalid, err)
	}
	if aud, _ := kb["aud"].(string); aud != opts.Audience {
		return nil, fmt.Errorf("%w: aud %q does not match %q", ErrKeyBindingInvalid, aud, opts.Audience)
	}
	if nonce, _ := kb["nonce"].(string); nonce != opts.Nonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrKeyBindingInvalid)
	}
	iat, ok := kb["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("%w: iat missing", ErrKeyBindingInvalid)
	}
	issued := time.Unix(int64(iat), 0)
	now := opts.now()
	if issued.After(now.Add(opts.leeway())) {
		return nil, fmt.Errorf("%w: iat is in the future", ErrKeyBindingInvalid)
	}
	if opts.MaxKeyBindingAge > 0 && now.Sub(issued) > opts.MaxKeyBindingAge+opts.leeway() {
		return nil, fmt.Errorf("%w: iat is too old", ErrKeyBindingInvalid)
	}
	alg := DefaultAlg
	if a, ok := payload["_sd_alg"].(string); ok {
		alg = a
	}
	want, _ := Digest(alg, Serialize(Presentation{IssuerJWT: p.IssuerJWT, Disclosures: p.Disclosures}))
	if got, _ := kb["sd_hash"].(string); got != want {
		return nil, fmt.Errorf("%w: sd_hash mismatch", ErrKeyBindingInvalid)
	}
	return kb, nil
}

// KeyBinding signs a Key Binding JWT for the presentation with the holder key.
func KeyBinding(p Presentation, holderKey crypto.PrivateKey, alg, aud, nonce string, iat time.Time) (string, error) {
	sdHash, err := Digest(alg, Serialize(Presentation{IssuerJWT: p.IssuerJWT, Disclosures: p.Disclosures}))
	if err != nil {
		return "", err
	}
	return jose.Sign(holderKey, "", TypeKB, map[string]any{
		"iat":     iat.Unix(),
		"aud":     aud,
		"nonce":   nonce,
		"sd_hash": sdHash,
	})
}
