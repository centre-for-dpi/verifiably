package handlers

import (
	"testing"
	"time"
)

func TestNonceStoreIssueProducesUniqueNonces(t *testing.T) {
	s := NewNonceStore(time.Minute)
	a := s.Issue()
	b := s.Issue()
	if a == "" || b == "" {
		t.Fatal("Issue must return a non-empty nonce")
	}
	if a == b {
		t.Fatal("two calls to Issue must not return the same nonce")
	}
}

func TestNonceStoreConsumeAcceptsValidNonceOnce(t *testing.T) {
	s := NewNonceStore(time.Minute)
	n := s.Issue()
	if !s.Consume(n) {
		t.Fatal("Consume must accept a freshly issued nonce")
	}
	if s.Consume(n) {
		t.Fatal("Consume must reject the same nonce a second time — replay")
	}
}

func TestNonceStoreConsumeRejectsUnknownNonce(t *testing.T) {
	s := NewNonceStore(time.Minute)
	if s.Consume("never-issued") {
		t.Fatal("Consume must reject a nonce it never issued")
	}
}

func TestNonceStoreConsumeRejectsExpiredNonce(t *testing.T) {
	s := NewNonceStore(10 * time.Millisecond)
	n := s.Issue()
	time.Sleep(30 * time.Millisecond)
	if s.Consume(n) {
		t.Fatal("Consume must reject a nonce past its TTL")
	}
}
