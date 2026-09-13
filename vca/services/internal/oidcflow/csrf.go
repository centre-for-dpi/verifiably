// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

// CSRFHeader is the request header that carries the synchronizer token.
const CSRFHeader = "X-CSRF-Token"

// CSRFField is the form field that carries the synchronizer token.
const CSRFField = "csrf_token"

// CSRF makes and checks synchronizer tokens (ADR-010 decision 7). A token
// is bound to one session id, so a token from one session does not work
// with another. The service keeps no token table: the token carries a
// random part and an HMAC over the session id and that part.
type CSRF struct {
	key []byte
}

// NewCSRF returns a token maker for key. The key must have 16 bytes or more.
func NewCSRF(key []byte) (CSRF, error) {
	if len(key) < 16 {
		return CSRF{}, wrap(ErrCSRF, "key must have at least 16 bytes")
	}
	return CSRF{key: append([]byte(nil), key...)}, nil
}

// Token returns a new token for sid.
func (c CSRF) Token(sid string) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	n := base64.RawURLEncoding.EncodeToString(nonce)
	return n + "." + c.mac(sid, n)
}

// Check reports whether token belongs to sid.
func (c CSRF) Check(sid, token string) bool {
	n, mac, ok := strings.Cut(token, ".")
	if !ok || sid == "" || n == "" {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(c.mac(sid, n)))
}

func (c CSRF) mac(sid, nonce string) string {
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte(sid))
	h.Write([]byte{0})
	h.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// CSRFFromRequest reads the token from the header or the form field.
func CSRFFromRequest(r *http.Request) string {
	if v := r.Header.Get(CSRFHeader); v != "" {
		return v
	}
	return r.PostFormValue(CSRFField)
}
