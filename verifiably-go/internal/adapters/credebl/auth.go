package credebl

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/internal/httpx"
)

// tokenCache holds a cached CREDEBL JWT and its expiry.
type tokenCache struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

// get returns the cached token if still valid (with a 60 s safety buffer).
func (tc *tokenCache) get() (string, bool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.token == "" || time.Now().After(tc.expires.Add(-60*time.Second)) {
		return "", false
	}
	return tc.token, true
}

// set stores a token and derives its expiry from the JWT exp claim.
func (tc *tokenCache) set(token string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.token = token
	exp := parseJWTExpiry(token)
	if exp.IsZero() {
		tc.expires = time.Now().Add(time.Hour)
	} else {
		tc.expires = exp
	}
}

// getToken returns a valid CREDEBL JWT, fetching a fresh one when the cache is stale.
func (a *Adapter) getToken(ctx context.Context) (string, error) {
	if tok, ok := a.cache.get(); ok {
		return tok, nil
	}
	enc, err := cryptoJSEncrypt(a.cfg.Password, a.cfg.CryptoPrivateKey)
	if err != nil {
		return "", fmt.Errorf("credebl: encrypt password: %w", err)
	}
	body := map[string]string{"email": a.cfg.Email, "password": enc}
	var resp struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := a.client.DoJSON(ctx, http.MethodPost, "/v1/auth/signin", body, &resp, nil); err != nil {
		return "", fmt.Errorf("credebl: signin: %w", err)
	}
	if resp.Data.AccessToken == "" {
		return "", fmt.Errorf("credebl: signin returned empty access_token")
	}
	a.cache.set(resp.Data.AccessToken)
	return resp.Data.AccessToken, nil
}

// authCtx returns a derived context with the CREDEBL JWT injected as a bearer
// token. The httpx.Client reads this via httpx.WithToken and sets Authorization.
func (a *Adapter) authCtx(ctx context.Context) (context.Context, error) {
	tok, err := a.getToken(ctx)
	if err != nil {
		return ctx, err
	}
	return httpx.WithToken(ctx, tok), nil
}

// cryptoJSEncrypt encrypts plaintext using CryptoJS-compatible AES-256-CBC
// (OpenSSL salted MD5 KDF). CREDEBL's /v1/auth/signin requires the password
// in exactly this form: CryptoJS.AES.encrypt(JSON.stringify(password), key).
func cryptoJSEncrypt(plaintext, passphrase string) (string, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key, iv := evpBytesToKey([]byte(passphrase), salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// JSON.stringify wraps the plaintext in double quotes before encrypting.
	data := []byte(`"` + plaintext + `"`)
	padded := pkcs7Pad(data, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	// OpenSSL wire format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext.
	out := make([]byte, 0, 16+len(ct))
	out = append(out, []byte("Salted__")...)
	out = append(out, salt...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// evpBytesToKey is the OpenSSL / CryptoJS MD5-based key derivation function.
func evpBytesToKey(password, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var derived []byte
	prev := []byte{}
	for len(derived) < keyLen+ivLen {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		derived = append(derived, prev...)
	}
	return derived[:keyLen], derived[keyLen : keyLen+ivLen]
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+n)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

// parseJWTExpiry extracts the exp claim from a JWT without signature verification.
func parseJWTExpiry(token string) time.Time {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}
