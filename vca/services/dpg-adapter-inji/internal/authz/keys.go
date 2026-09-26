// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// keyStoreKey is the store key of the sealed token key.
const keyStoreKey = "authz/key"

// keyInfo binds the sealing key to this use (RFC 5869 section 3.2).
const keyInfo = "vca inji holder authorization server token key"

// tokenKeyBits is the size of the token key. Certify 0.14.0 checks an
// access token with RS256, ES256 or PS256. RS256 is what the release
// profiles name, so the server signs with it (ADR-048 decision 2).
const tokenKeyBits = 2048

// tokenKey is the key that signs access tokens. It signs nothing else
// (ADR-052 decision 6).
type tokenKey struct {
	private *rsa.PrivateKey
	public  jose.JWK
}

// sealedKey is the stored form: the PKCS #8 key under AES-256-GCM.
type sealedKey struct {
	Kid        string `json:"kid"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// sealer returns the AEAD of the pair session key.
func sealer(secret []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, secret, nil, keyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("authz: derive the sealing key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("authz: derive the sealing key: %w", err)
	}
	return cipher.NewGCM(block)
}

// loadKey opens the stored token key, or makes one and stores it sealed.
// Two starts at once agree on one key: the second write fails its
// compare and swap and reads the key of the first.
func loadKey(ctx context.Context, kv store.KeyValue, secret []byte) (tokenKey, error) {
	aead, err := sealer(secret)
	if err != nil {
		return tokenKey{}, err
	}
	for range 2 {
		raw, gerr := kv.Get(ctx, keyStoreKey)
		if gerr == nil {
			return openKey(aead, raw)
		}
		if !errors.Is(gerr, store.ErrNotFound) {
			return tokenKey{}, fmt.Errorf("authz: read the token key: %w", gerr)
		}
		made, sealed, merr := makeKey(aead)
		if merr != nil {
			return tokenKey{}, merr
		}
		cerr := kv.CompareAndSwap(ctx, keyStoreKey, nil, sealed)
		if cerr == nil {
			return made, nil
		}
		if !errors.Is(cerr, store.ErrConflict) {
			return tokenKey{}, fmt.Errorf("authz: store the token key: %w", cerr)
		}
	}
	return tokenKey{}, errors.New("authz: the token key changed twice during the start")
}

// makeKey makes a new token key and its sealed form.
func makeKey(aead cipher.AEAD) (tokenKey, []byte, error) {
	private, err := rsa.GenerateKey(rand.Reader, tokenKeyBits)
	if err != nil {
		return tokenKey{}, nil, fmt.Errorf("authz: make the token key: %w", err)
	}
	k, err := withPublic(private)
	if err != nil {
		return tokenKey{}, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return tokenKey{}, nil, fmt.Errorf("authz: encode the token key: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, rerr := rand.Read(nonce); rerr != nil {
		return tokenKey{}, nil, fmt.Errorf("authz: seal the token key: %w", rerr)
	}
	sealed, err := json.Marshal(sealedKey{
		Kid: k.public.KeyID, Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, der, []byte(keyStoreKey+"|"+k.public.KeyID)),
	})
	if err != nil {
		return tokenKey{}, nil, fmt.Errorf("authz: seal the token key: %w", err)
	}
	return k, sealed, nil
}

// openKey reads a sealed token key.
func openKey(aead cipher.AEAD, raw []byte) (tokenKey, error) {
	var sealed sealedKey
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return tokenKey{}, fmt.Errorf("authz: open the token key: %w", err)
	}
	if len(sealed.Nonce) != aead.NonceSize() {
		return tokenKey{}, errors.New("authz: open the token key: the nonce has the wrong size")
	}
	der, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, []byte(keyStoreKey+"|"+sealed.Kid))
	if err != nil {
		return tokenKey{}, errors.New("authz: open the token key: the pair session key does not match the one that sealed it")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return tokenKey{}, fmt.Errorf("authz: open the token key: %w", err)
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return tokenKey{}, fmt.Errorf("authz: open the token key: a %T is not an RSA key", parsed)
	}
	return withPublic(private)
}

// withPublic adds the public JWK with the thumbprint as its kid.
func withPublic(private *rsa.PrivateKey) (tokenKey, error) {
	pub, err := jose.PublicJWK(private, "")
	if err != nil {
		return tokenKey{}, fmt.Errorf("authz: the public token key: %w", err)
	}
	kid, err := jose.Thumbprint(pub)
	if err != nil {
		return tokenKey{}, fmt.Errorf("authz: the public token key: %w", err)
	}
	pub.KeyID = kid
	pub.Algorithm = string(jose.RS256)
	return tokenKey{private: private, public: pub}, nil
}
