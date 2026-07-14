package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"sync"
	"time"
)

// otp.go — in-memory one-time-code store for holder-identity activation.
//
// Activation proves the holder controls the email on file in the identity
// registry before they may set a PIN. A code is issued + emailed at step 1 and
// verified at step 2. Single-instance, in-memory (the demo runs one replica);
// a multi-replica deployment would back this with Redis/Postgres. Codes are
// stored hashed, expire quickly, and are rate-limited per token.

const (
	otpTTL         = 10 * time.Minute
	otpMaxAttempts = 5
)

// Mailer sends one transactional email. Satisfied by *mailer.Mailer; kept as an
// interface here so the activation handlers can be tested with a capture-only
// fake and so a nil mailer cleanly means "email not configured".
type Mailer interface {
	Send(to, subject, body string) error
}

type otpEntry struct {
	individualID string
	email        string
	codeHash     [32]byte
	expiry       time.Time
	attempts     int
}

// OTPStore holds pending activation codes keyed by an opaque token (which the
// caller stashes on the session). Concurrency-safe.
type OTPStore struct {
	mu sync.Mutex
	m  map[string]*otpEntry
}

// NewOTPStore returns an empty store. Always non-nil so callers needn't nil-check.
func NewOTPStore() *OTPStore { return &OTPStore{m: map[string]*otpEntry{}} }

// Issue mints a 6-digit code for (individualID, email), stores its hash under a
// fresh token, and returns (token, code). The caller emails code and stashes
// token on the session.
func (s *OTPStore) Issue(individualID, email string) (token, code string) {
	token = randHex(16)
	code = randCode6()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.m[token] = &otpEntry{
		individualID: individualID,
		email:        email,
		codeHash:     sha256.Sum256([]byte(code)),
		expiry:       time.Now().Add(otpTTL),
	}
	return token, code
}

// Peek returns the (individualID, email) for a token without consuming it, so
// step 2 can re-render the masked email. ok is false if the token is unknown or
// expired.
func (s *OTPStore) Peek(token string) (individualID, email string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[token]
	if e == nil || time.Now().After(e.expiry) {
		return "", "", false
	}
	return e.individualID, e.email, true
}

// Verify checks code against the token. On success it consumes the entry and
// returns the bound individualID. reason is a human-facing failure cause
// ("expired" / "too many attempts" / "incorrect code").
func (s *OTPStore) Verify(token, code string) (individualID string, ok bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[token]
	if e == nil || time.Now().After(e.expiry) {
		delete(s.m, token)
		return "", false, "the code has expired — request a new one"
	}
	if e.attempts >= otpMaxAttempts {
		delete(s.m, token)
		return "", false, "too many attempts — request a new code"
	}
	e.attempts++
	want := e.codeHash
	got := sha256.Sum256([]byte(code))
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return "", false, "incorrect code"
	}
	id := e.individualID
	delete(s.m, token)
	return id, true, ""
}

// gcLocked drops expired entries. Caller holds s.mu.
func (s *OTPStore) gcLocked() {
	now := time.Now()
	for k, e := range s.m {
		if now.After(e.expiry) {
			delete(s.m, k)
		}
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randCode6 returns a uniformly-random 6-digit decimal string (zero-padded).
func randCode6() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "000000"
	}
	s := n.String()
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

// maskEmail renders "jo***@gmail.com" for display in the step-2 prompt.
func maskEmail(e string) string {
	at := -1
	for i := 0; i < len(e); i++ {
		if e[i] == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return "your email"
	}
	local, domain := e[:at], e[at:]
	if len(local) <= 2 {
		return local[:1] + "***" + domain
	}
	return local[:2] + "***" + domain
}
