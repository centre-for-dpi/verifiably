package handlers

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"
)

func TestOTPStore_IssuePeekVerify(t *testing.T) {
	s := NewOTPStore()
	token, code := s.Issue("ind-1", "alice@example.org")
	if len(token) != 32 || len(code) != 6 {
		t.Fatalf("token/code = %q/%q", token, code)
	}
	if id, email, ok := s.Peek(token); !ok || id != "ind-1" || email != "alice@example.org" {
		t.Errorf("Peek = %q %q %v", id, email, ok)
	}
	if _, _, ok := s.Peek("unknown"); ok {
		t.Error("Peek unknown token should be false")
	}

	if _, ok, reason := s.Verify(token, "not-it"); ok || reason != "incorrect code" {
		t.Errorf("wrong code: ok=%v reason=%q", ok, reason)
	}
	if id, ok, reason := s.Verify(token, code); !ok || id != "ind-1" || reason != "" {
		t.Errorf("right code: id=%q ok=%v reason=%q", id, ok, reason)
	}
	// Consumed on success.
	if _, ok, reason := s.Verify(token, code); ok || reason != "the code has expired — request a new one" {
		t.Errorf("reuse: ok=%v reason=%q", ok, reason)
	}
}

func TestOTPStore_ExpiryAndAttempts(t *testing.T) {
	s := NewOTPStore()
	token, code := s.Issue("ind-2", "bob@example.org")
	s.mu.Lock()
	s.m[token].expiry = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if _, _, ok := s.Peek(token); ok {
		t.Error("expired Peek should be false")
	}
	if _, ok, reason := s.Verify(token, code); ok || reason != "the code has expired — request a new one" {
		t.Errorf("expired Verify: ok=%v reason=%q", ok, reason)
	}
	if _, present := s.m[token]; present {
		t.Error("expired entry should be deleted on Verify")
	}

	token, code = s.Issue("ind-3", "carol@example.org")
	for i := 0; i < otpMaxAttempts; i++ {
		if _, ok, _ := s.Verify(token, "000001"); ok {
			t.Fatal("wrong code accepted")
		}
	}
	if _, ok, reason := s.Verify(token, code); ok || reason != "too many attempts — request a new code" {
		t.Errorf("lockout: ok=%v reason=%q", ok, reason)
	}
	if _, present := s.m[token]; present {
		t.Error("locked-out entry should be deleted")
	}
}

func TestOTPStore_GCDropsExpiredOnIssue(t *testing.T) {
	s := NewOTPStore()
	stale, _ := s.Issue("old", "old@example.org")
	fresh, _ := s.Issue("new", "new@example.org")
	s.mu.Lock()
	s.m[stale].expiry = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	s.Issue("trigger", "gc@example.org") // Issue runs gcLocked
	if _, present := s.m[stale]; present {
		t.Error("stale entry should be garbage-collected")
	}
	if _, present := s.m[fresh]; !present {
		t.Error("fresh entry must survive GC")
	}
}

type otpFailingReader struct{}

func (otpFailingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestRandCode6(t *testing.T) {
	for i := 0; i < 50; i++ {
		c := randCode6()
		if len(c) != 6 {
			t.Fatalf("code %q not 6 chars", c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Fatalf("code %q not numeric", c)
			}
		}
	}
	// Entropy failure degrades to the all-zero code rather than panicking.
	orig := rand.Reader
	rand.Reader = io.Reader(otpFailingReader{})
	defer func() { rand.Reader = orig }()
	if c := randCode6(); c != "000000" {
		t.Errorf("code on rand failure = %q, want 000000", c)
	}
}

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"johanna@example.org": "jo***@example.org",
		"jo@example.org":      "j***@example.org",
		"j@example.org":       "j***@example.org",
		"@example.org":        "your email",
		"no-at-sign":          "your email",
		"":                    "your email",
	}
	for in, want := range cases {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
