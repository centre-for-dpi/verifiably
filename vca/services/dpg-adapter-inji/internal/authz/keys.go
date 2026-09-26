// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// keyStoreKey is the store key of the one sealed token key of an
// earlier release. The first start of the ring moves it into the ring.
const keyStoreKey = "authz/key"

// ringStoreKey is the store key of the key ring (ADR-056 decision 6).
const ringStoreKey = "authz/keys"

// keyInfo binds the sealing key to this use (RFC 5869 section 3.2).
const keyInfo = "vca inji holder authorization server token key"

// rotationLabel is the message of the rotation token.
const rotationLabel = "vca inji authz key rotation"

// tokenKeyBits is the size of the token key. Certify 0.14.0 checks an
// access token with RS256, ES256 or PS256. RS256 is what the release
// profiles name, so the server signs with it (ADR-048 decision 2).
const tokenKeyBits = 2048

// The times of a rotation (ADR-056 decision 6).
const (
	// PublishLead is how long a new key sits in the key set before it
	// signs. Certify keeps the key set five minutes
	// (mosip.certify.jwks-cache-expire-seconds), so every Certify knows
	// the key before a token names it.
	PublishLead = 6 * time.Minute
	// retireLag is how long an old key stays in the key set after the
	// next key signs: the life of its last token and a minute.
	retireLag = TokenTTL + time.Minute
)

// RotatePath is the path of the rotation on the adapter. The proxy of
// the pair does not publish it.
const RotatePath = "/internal/authz/rotate-key"

// tokenKey is the key that signs access tokens. It signs nothing else
// (ADR-052 decision 6).
type tokenKey struct {
	private *rsa.PrivateKey
	public  jose.JWK
}

// ringKey is one key of the ring with its times.
type ringKey struct {
	tokenKey
	// activeFrom is when the key starts to sign.
	activeFrom time.Time
	// retireAt is when the key leaves the key set. Zero means never.
	retireAt time.Time
}

// keyRing holds the token keys in the order they were made.
type keyRing struct {
	keys []ringKey
}

// signer returns the newest key that signs at now.
func (r keyRing) signer(now time.Time) tokenKey {
	for i := len(r.keys) - 1; i >= 0; i-- {
		if !r.keys[i].activeFrom.After(now) {
			return r.keys[i].tokenKey
		}
	}
	return r.keys[0].tokenKey
}

// published returns the public keys that the key set lists at now.
func (r keyRing) published(now time.Time) []any {
	out := []any{}
	for _, k := range r.keys {
		if k.retireAt.IsZero() || now.Before(k.retireAt) {
			out = append(out, k.public)
		}
	}
	return out
}

// sealedKey is the stored form of one key: the PKCS #8 key under
// AES-256-GCM, with its times.
type sealedKey struct {
	Kid        string    `json:"kid"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
	ActiveFrom time.Time `json:"active_from,omitzero"`
	RetireAt   time.Time `json:"retire_at,omitzero"`
}

// ringDoc is the stored key ring.
type ringDoc struct {
	Keys []sealedKey `json:"keys"`
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

// RotationToken returns the token that a rotation request carries: the
// HMAC-SHA256 of a fixed label under the pair session key, in hex. vca
// dpg rotate-authz-key derives the same value from the .env of the pair.
func RotationToken(secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(rotationLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

// loadRing opens the stored key ring. On the first start it moves the
// key of an earlier release into the ring, or makes a key. Two starts
// at once agree on one ring: the second write fails its compare and
// swap and reads the ring of the first.
func loadRing(ctx context.Context, kv store.KeyValue, secret []byte) (keyRing, error) {
	aead, err := sealer(secret)
	if err != nil {
		return keyRing{}, err
	}
	for range 2 {
		raw, gerr := kv.Get(ctx, ringStoreKey)
		if gerr == nil {
			return openRing(aead, raw)
		}
		if !errors.Is(gerr, store.ErrNotFound) {
			return keyRing{}, fmt.Errorf("authz: read the token keys: %w", gerr)
		}
		first, ferr := firstKey(ctx, kv, aead)
		if ferr != nil {
			return keyRing{}, ferr
		}
		sealed, serr := seal(aead, ringStoreKey, first, time.Time{}, time.Time{})
		if serr != nil {
			return keyRing{}, serr
		}
		doc, merr := json.Marshal(ringDoc{Keys: []sealedKey{sealed}})
		if merr != nil {
			return keyRing{}, merr
		}
		cerr := kv.CompareAndSwap(ctx, ringStoreKey, nil, doc)
		if cerr == nil {
			// The ring holds the old key now, so its old record goes.
			if derr := kv.Delete(ctx, keyStoreKey); derr != nil {
				return keyRing{}, fmt.Errorf("authz: remove the old token key: %w", derr)
			}
			return keyRing{keys: []ringKey{{tokenKey: first}}}, nil
		}
		if !errors.Is(cerr, store.ErrConflict) {
			return keyRing{}, fmt.Errorf("authz: store the token keys: %w", cerr)
		}
	}
	return keyRing{}, errors.New("authz: the token keys changed twice during the start")
}

// firstKey returns the key of an earlier release, or a new key.
func firstKey(ctx context.Context, kv store.KeyValue, aead cipher.AEAD) (tokenKey, error) {
	raw, err := kv.Get(ctx, keyStoreKey)
	if errors.Is(err, store.ErrNotFound) {
		return makeKey()
	}
	if err != nil {
		return tokenKey{}, fmt.Errorf("authz: read the token key: %w", err)
	}
	var sealed sealedKey
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return tokenKey{}, fmt.Errorf("authz: open the token key: %w", err)
	}
	return open(aead, keyStoreKey, sealed)
}

// openRing opens every key of a stored ring.
func openRing(aead cipher.AEAD, raw []byte) (keyRing, error) {
	var doc ringDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return keyRing{}, fmt.Errorf("authz: open the token key: %w", err)
	}
	if len(doc.Keys) == 0 {
		return keyRing{}, errors.New("authz: open the token key: the ring holds no key")
	}
	ring := keyRing{}
	for _, sealed := range doc.Keys {
		k, err := open(aead, ringStoreKey, sealed)
		if err != nil {
			return keyRing{}, err
		}
		ring.keys = append(ring.keys, ringKey{tokenKey: k, activeFrom: sealed.ActiveFrom, retireAt: sealed.RetireAt})
	}
	return ring, nil
}

// makeKey makes a new token key.
func makeKey() (tokenKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, tokenKeyBits)
	if err != nil {
		return tokenKey{}, fmt.Errorf("authz: make the token key: %w", err)
	}
	return withPublic(private)
}

// seal returns the stored form of a key. The additional data binds the
// ciphertext to its store key and its kid.
func seal(aead cipher.AEAD, storeKey string, k tokenKey, activeFrom, retireAt time.Time) (sealedKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.private)
	if err != nil {
		return sealedKey{}, fmt.Errorf("authz: encode the token key: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, rerr := rand.Read(nonce); rerr != nil {
		return sealedKey{}, fmt.Errorf("authz: seal the token key: %w", rerr)
	}
	return sealedKey{
		Kid: k.public.KeyID, Nonce: nonce, ActiveFrom: activeFrom, RetireAt: retireAt,
		Ciphertext: aead.Seal(nil, nonce, der, []byte(storeKey+"|"+k.public.KeyID)),
	}, nil
}

// open reads one sealed key.
func open(aead cipher.AEAD, storeKey string, sealed sealedKey) (tokenKey, error) {
	if len(sealed.Nonce) != aead.NonceSize() {
		return tokenKey{}, errors.New("authz: open the token key: the nonce has the wrong size")
	}
	der, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, []byte(storeKey+"|"+sealed.Kid))
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

// Rotation is the outcome of a rotation of the token key.
type Rotation struct {
	// Kid is the kid of the new key.
	Kid string `json:"kid"`
	// ActiveFrom is when the new key starts to sign.
	ActiveFrom time.Time `json:"active_from"`
	// Retiring lists the old keys that leave the key set, by kid, with
	// the time they leave.
	Retiring map[string]time.Time `json:"retiring,omitempty"`
}

// Rotate adds a new token key to the ring (ADR-056 decision 6). The new
// key sits in the key set at once and signs after PublishLead, so every
// Certify knows it first. The keys that signed until then leave the key
// set once their last token expires. An immediate rotation, for a
// compromised key, signs with the new key at once and drops every old
// key from the key set: Certify then refuses new tokens until its key
// set cache ends. Keys that left the key set leave the store.
func (s *Server) Rotate(ctx context.Context, immediate bool) (Rotation, error) {
	aead, err := sealer(s.secret)
	if err != nil {
		return Rotation{}, err
	}
	for range 3 {
		raw, gerr := s.kv.Get(ctx, ringStoreKey)
		if gerr != nil {
			return Rotation{}, fmt.Errorf("authz: read the token keys: %w", gerr)
		}
		var doc ringDoc
		if uerr := json.Unmarshal(raw, &doc); uerr != nil {
			return Rotation{}, fmt.Errorf("authz: read the token keys: %w", uerr)
		}
		next, rot, merr := s.nextRing(aead, doc, immediate)
		if merr != nil {
			return Rotation{}, merr
		}
		updated, merr := json.Marshal(next)
		if merr != nil {
			return Rotation{}, merr
		}
		cerr := s.kv.CompareAndSwap(ctx, ringStoreKey, raw, updated)
		if errors.Is(cerr, store.ErrConflict) {
			continue
		}
		if cerr != nil {
			return Rotation{}, fmt.Errorf("authz: store the token keys: %w", cerr)
		}
		ring, oerr := openRing(aead, updated)
		if oerr != nil {
			return Rotation{}, oerr
		}
		s.setRing(ring)
		s.log.Warn("the token key of the holder authorization server rotated",
			"kid", rot.Kid, "active_from", rot.ActiveFrom, "immediate", immediate)
		return rot, nil
	}
	return Rotation{}, errors.New("authz: the token keys changed three times during the rotation")
}

// nextRing returns the stored ring with a new key and the times of the
// old keys set.
func (s *Server) nextRing(aead cipher.AEAD, doc ringDoc, immediate bool) (ringDoc, Rotation, error) {
	now := s.now()
	made, err := makeKey()
	if err != nil {
		return ringDoc{}, Rotation{}, err
	}
	rot := Rotation{Kid: made.public.KeyID, ActiveFrom: now.Add(PublishLead), Retiring: map[string]time.Time{}}
	retire := rot.ActiveFrom.Add(retireLag)
	if immediate {
		rot.ActiveFrom, retire = now, now
	}
	var next ringDoc
	for _, k := range doc.Keys {
		if !k.RetireAt.IsZero() && !now.Before(k.RetireAt) {
			continue
		}
		if k.RetireAt.IsZero() || retire.Before(k.RetireAt) {
			k.RetireAt = retire
		}
		rot.Retiring[k.Kid] = k.RetireAt
		if !immediate {
			next.Keys = append(next.Keys, k)
		}
	}
	sealed, err := seal(aead, ringStoreKey, made, rot.ActiveFrom, time.Time{})
	if err != nil {
		return ringDoc{}, Rotation{}, err
	}
	next.Keys = append(next.Keys, sealed)
	return next, rot, nil
}

// reloadKeys reads the ring again, so a rotation through another
// replica reaches this one.
func (s *Server) reloadKeys(ctx context.Context) error {
	ring, err := loadRing(ctx, s.kv, s.secret)
	if err != nil {
		return err
	}
	s.setRing(ring)
	return nil
}

func (s *Server) setRing(r keyRing) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	s.ring = r
}

func (s *Server) keyRing() keyRing {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.ring
}

// RotationHandler serves the rotation for vca dpg rotate-authz-key. The
// adapter mounts it at RotatePath on the compose network; the proxy of
// the pair publishes no such route. A request carries the rotation
// token of the pair session key as a bearer token. immediate=true asks
// for an immediate rotation.
func (s *Server) RotationHandler() http.Handler {
	want := []byte(RotationToken(s.secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Use POST.", http.StatusMethodNotAllowed)
			return
		}
		got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			s.log.Warn("a rotation of the token key was refused: the rotation token does not match")
			http.Error(w, "The rotation token does not match the pair session key.", http.StatusUnauthorized)
			return
		}
		rot, err := s.Rotate(r.Context(), r.URL.Query().Get("immediate") == "true")
		if err != nil {
			s.log.Warn("the rotation of the token key failed", "error", err)
			http.Error(w, "The rotation failed.", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rot)
	})
}
