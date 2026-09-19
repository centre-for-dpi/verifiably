// SPDX-License-Identifier: Apache-2.0

// Package credebl talks to a CREDEBL 2.x platform over its api gateway.
// The vendor name and every vendor detail stay in this service
// (ADR-001 decision 4).
//
// The gateway needs a bearer token. The sign in call takes the password
// in the CryptoJS form of AES 256 in cipher block chaining mode, with
// the OpenSSL key derivation that uses MD5. The platform accepts no
// other form.
//
// The adapter caches the token until it expires.
package credebl

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // G501: the CREDEBL key derivation fixes MD5
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// TokenMargin is the time before the end of a token at which the
// adapter fetches a new one.
const TokenMargin = time.Minute

// ErrNoPlatform reports that the CREDEBL URL is not configured.
var ErrNoPlatform = errors.New("credebl: no platform URL")

// Account is the platform administrator the adapter signs in as.
type Account struct {
	// Email is the login name.
	Email string
	// Password is the login secret in plain text.
	Password string
	// CryptoKey is the pass phrase of the on the wire encryption.
	CryptoKey string
}

// Client calls one CREDEBL platform.
type Client struct {
	client  *dpgclient.Client
	account Account
	// orgID names the organisation the adapter works in.
	orgID string
	// issuerID names the OID4VCI issuer of the organisation.
	issuerID string
	// now returns the current time. Tests replace it.
	now func() time.Time
	// randomSalt returns the salt of the password encryption. Tests
	// replace it.
	randomSalt func() ([]byte, error)

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Options configure New.
type Options struct {
	// HTTP calls the api gateway. Nil turns every role off.
	HTTP *dpgclient.Client
	// Account is the platform administrator.
	Account Account
	// OrgID names the organisation.
	OrgID string
	// IssuerID names the OID4VCI issuer.
	IssuerID string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// RandomSalt returns the salt of the password encryption. Nil reads
	// eight bytes from crypto/rand.
	RandomSalt func() ([]byte, error)
}

// New returns a client for one CREDEBL platform. A nil HTTP client
// returns nil, which turns every role off.
func New(opts Options) *Client {
	if opts.HTTP == nil {
		return nil
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.RandomSalt == nil {
		opts.RandomSalt = randomSalt
	}
	return &Client{
		client:     opts.HTTP,
		account:    opts.Account,
		orgID:      opts.OrgID,
		issuerID:   opts.IssuerID,
		now:        opts.Now,
		randomSalt: opts.RandomSalt,
	}
}

// OrgID returns the organisation of the adapter.
func (c *Client) OrgID() string {
	if c == nil {
		return ""
	}
	return c.orgID
}

// IssuerID returns the OID4VCI issuer of the adapter.
func (c *Client) IssuerID() string {
	if c == nil {
		return ""
	}
	return c.issuerID
}

// BaseURL returns the root of the api gateway.
func (c *Client) BaseURL() string {
	if c == nil {
		return ""
	}
	return c.client.BaseURL()
}

// signinResponse is the answer of POST /v1/auth/signin.
type signinResponse struct {
	Data struct {
		AccessToken string `json:"access_token"`
	} `json:"data"`
}

// Token returns a valid bearer token. It signs in again when the cached
// token is close to its end.
func (c *Client) Token(ctx context.Context) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	c.mu.Lock()
	token, expires := c.token, c.expires
	c.mu.Unlock()
	if token != "" && c.now().Add(TokenMargin).Before(expires) {
		return token, nil
	}
	salt, err := c.randomSalt()
	if err != nil {
		return "", fmt.Errorf("credebl: make the password salt: %w", err)
	}
	secret, err := EncryptPassword(c.account.Password, c.account.CryptoKey, salt)
	if err != nil {
		return "", err
	}
	body := map[string]string{"email": c.account.Email, "password": secret}
	var out signinResponse
	if err := c.client.JSON(ctx, http.MethodPost, "/v1/auth/signin", body, &out); err != nil {
		return "", fmt.Errorf("credebl: sign in: %w", err)
	}
	if out.Data.AccessToken == "" {
		return "", errors.New("credebl: the sign in answer has no access token")
	}
	end := TokenExpiry(out.Data.AccessToken)
	if end.IsZero() {
		end = c.now().Add(time.Hour)
	}
	c.mu.Lock()
	c.token, c.expires = out.Data.AccessToken, end
	c.mu.Unlock()
	return out.Data.AccessToken, nil
}

// Forget drops the cached token. A call that fails with an
// unauthorized status uses it before it tries again.
func (c *Client) Forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.expires = "", time.Time{}
}

// call sends one request with a fresh bearer token. It signs in again
// once when CREDEBL answers with the status unauthorized.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	if c == nil {
		return ErrNoPlatform
	}
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.Token(ctx)
		if err != nil {
			return err
		}
		err = c.withToken(token).JSON(ctx, method, path, body, out)
		if err == nil {
			return nil
		}
		if attempt == 0 && dpgclient.IsStatus(err, http.StatusUnauthorized) {
			c.Forget()
			continue
		}
		return err
	}
	return errors.New("credebl: the platform refused the token twice")
}

// withToken returns the HTTP client with the bearer token.
func (c *Client) withToken(token string) *dpgclient.Client {
	return c.client.WithToken(token)
}

// EncryptPassword returns the password in the CryptoJS form: the marker
// "Salted__", the salt, and the cipher text, all in standard base64.
//
// CryptoJS encrypts the JSON form of the value, so the plain text
// carries the quotation marks of a JSON string.
func EncryptPassword(password, passphrase string, salt []byte) (string, error) {
	if len(salt) != 8 {
		return "", errors.New("credebl: the password salt must be eight bytes")
	}
	key, iv := deriveKey([]byte(passphrase), salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("credebl: make the cipher: %w", err)
	}
	plain := pad([]byte(`"`+password+`"`), aes.BlockSize)
	cipherText := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, plain)
	out := make([]byte, 0, 16+len(cipherText))
	out = append(out, []byte("Salted__")...)
	out = append(out, salt...)
	out = append(out, cipherText...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// deriveKey is the OpenSSL key derivation that CryptoJS uses. It hashes
// with MD5, which the format fixes.
func deriveKey(password, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var derived []byte
	var previous []byte
	for len(derived) < keyLen+ivLen {
		h := md5.New() //nolint:gosec // G401: the CREDEBL key derivation fixes MD5
		_, _ = h.Write(previous)
		_, _ = h.Write(password)
		_, _ = h.Write(salt)
		previous = h.Sum(nil)
		derived = append(derived, previous...)
	}
	return derived[:keyLen], derived[keyLen : keyLen+ivLen]
}

// pad adds PKCS number 7 padding.
func pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+n)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// randomSalt returns eight random bytes.
func randomSalt() ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// TokenExpiry returns the end of a JSON web token. It reads the exp
// claim and checks no signature, because the platform owns the token.
func TokenExpiry(token string) time.Time {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return time.Time{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// isConflict reports whether the platform answered with the status
// conflict, which means the thing already exists.
func isConflict(err error) bool {
	return dpgclient.IsStatus(err, http.StatusConflict)
}
