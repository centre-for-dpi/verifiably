package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/verifiably/verifiably-go/internal/jose"
)

// Self-managed status-list signing keys.
//
// Each issuer DPG signs its own status lists with its own key, so a
// deployment that registers no walt.id issuer (an Inji-only stack, say)
// can still publish a signed, verifiable list. Before this, the only
// SigningKey the process could build came from walt.id's onboarded JWK
// via ParseWaltidIssuerKey, so those deployments 503'd every fetch.
//
// The key is P-256 and the issuer is a did:jwk, and neither is a free
// choice — the verifier (internal/statuslistcache) resolves the signing
// key from the token's own `iss`: did:jwk is decoded inline, anything
// else needs the DID resolver, which only implements did:web. Its
// verifyES256JWT then rejects any key that isn't EC/P-256. So did:key +
// Ed25519 (what LDSigner uses for the JSON-LD list) would produce a list
// nothing could verify. did:jwk carries the public key inline, which
// keeps this offline: no hosting, no resolution, no deploy-time step.

// persistedP256 is the on-disk form: a bare private JWK. JWK rather than
// PKCS8 because did:jwk derivation needs x/y anyway, so storing the same
// vocabulary avoids a second encoding in this package.
type persistedP256 struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// publicJWK is the did:jwk payload — public members only, no `d`. Field
// order is the marshalled order, and it matches the alphabetical order
// encoding/json gives a map, which is what other did:jwk producers emit.
type publicJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// NewSelfSignedKey returns the status-list signing key for id (a DPG
// slug), loading it from stateDir or creating and persisting one on first
// use. Stable across restarts: the same stateDir yields the same key and
// therefore the same did:jwk issuer.
//
// Losing stateDir is survivable — a regenerated key still verifies,
// because the verifier trusts the token's own `iss` — but the list's
// revocation bits are lost with it.
func NewSelfSignedKey(stateDir, id string) (*SigningKey, error) {
	if id == "" {
		return nil, fmt.Errorf("statuslist: self-signed key needs a non-empty id")
	}
	path := filepath.Join(stateDir, "status-list-"+id+"-key.json")
	priv, err := loadOrCreateP256(path)
	if err != nil {
		return nil, fmt.Errorf("statuslist: self-signed key %q: %w", id, err)
	}
	did, err := didJWKFromP256(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("statuslist: self-signed key %q: %w", id, err)
	}
	// kid stays empty: the verifier keys off `iss` alone and SignJWT omits
	// an empty kid from the header.
	return &SigningKey{priv: priv, iss: did}, nil
}

func loadOrCreateP256(path string) (*ecdsa.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if priv, err := parseP256JWK(raw); err == nil {
			return priv, nil
		}
		// Unreadable/corrupt key: fall through and mint a fresh one rather
		// than hard-failing the whole status-list feature. The old list's
		// bits stay valid; only the issuer DID changes.
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(persistedP256{
		Kty: "EC",
		Crv: "P-256",
		X:   b64Coord(priv.X),
		Y:   b64Coord(priv.Y),
		D:   b64Coord(priv.D),
	})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err == nil {
		// 0600 — this is private key material.
		_ = os.WriteFile(path, blob, 0o600)
	}
	return priv, nil
}

func parseP256JWK(raw []byte) (*ecdsa.PrivateKey, error) {
	var pk persistedP256
	if err := json.Unmarshal(raw, &pk); err != nil {
		return nil, err
	}
	if pk.Kty != "EC" || pk.Crv != "P-256" || pk.D == "" {
		return nil, fmt.Errorf("statuslist: not a P-256 private JWK")
	}
	x, err := jose.DecodeBase64URLBigInt(pk.X)
	if err != nil {
		return nil, err
	}
	y, err := jose.DecodeBase64URLBigInt(pk.Y)
	if err != nil {
		return nil, err
	}
	d, err := jose.DecodeBase64URLBigInt(pk.D)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}, nil
}

// didJWKFromP256 builds did:jwk:<base64url(public JWK JSON)> per the
// did:jwk method. Must stay decodable by statuslistcache.decodeDIDJWK —
// that round-trip is the contract the whole scheme rests on.
func didJWKFromP256(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return "", fmt.Errorf("statuslist: incomplete public key")
	}
	blob, err := json.Marshal(publicJWK{
		Crv: "P-256",
		Kty: "EC",
		X:   b64Coord(pub.X),
		Y:   b64Coord(pub.Y),
	})
	if err != nil {
		return "", err
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(blob), nil
}

// b64Coord encodes a P-256 coordinate/scalar as unpadded base64url over
// exactly 32 bytes. big.Int.Bytes() drops leading zeros, which would make
// a short field — JWK requires the fixed curve length (RFC 7518 §6.2.1.2).
func b64Coord(n *big.Int) string {
	b := n.Bytes()
	out := make([]byte, 32)
	if len(b) >= 32 {
		copy(out, b[len(b)-32:])
	} else {
		copy(out[32-len(b):], b)
	}
	return base64.RawURLEncoding.EncodeToString(out)
}
