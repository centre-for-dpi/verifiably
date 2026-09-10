package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The persistent session store is what makes a container restart invisible to a
// logged-in operator: sessions are flushed to disk as AES-256-GCM blobs and
// replayed on the next boot. Nothing exercised the flush/load round trip, so a
// regression there would only ever show up as everyone being logged out after a
// deploy.

func TestPersistentStore_FlushAndReloadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	s := NewPersistentStore(dir, "test-secret")
	sess := &Session{IssuerDpg: "Walt Community Stack", VerifierDpg: "Inji Verify"}
	s.mu.Lock()
	s.sessions["sess-abc"] = sess
	s.mu.Unlock()

	s.flush()

	// One encrypted file per session, 0600 — session blobs carry OIDC subject
	// and email, so the mode matters.
	path := filepath.Join(dir, "sess-abc.sess")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("flush wrote no file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("session file mode = %o, want 600", perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Walt Community Stack") {
		t.Error("session file is not encrypted — plaintext field found on disk")
	}

	// A fresh store over the same dir must replay what the first one wrote.
	s2 := NewPersistentStore(dir, "test-secret")
	s2.mu.Lock()
	got, ok := s2.sessions["sess-abc"]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("reloaded store lost the session")
	}
	if got.IssuerDpg != "Walt Community Stack" || got.VerifierDpg != "Inji Verify" {
		t.Errorf("reloaded session = %+v, want the flushed values", got)
	}
}

// A different secret must not decrypt an existing store's files. The wrong-key
// sessions are skipped rather than crashing the boot.
func TestPersistentStore_WrongSecretSkipsSessions(t *testing.T) {
	dir := t.TempDir()

	s := NewPersistentStore(dir, "right-secret")
	s.mu.Lock()
	s.sessions["sess-abc"] = &Session{IssuerDpg: "Walt Community Stack"}
	s.mu.Unlock()
	s.flush()

	s2 := NewPersistentStore(dir, "wrong-secret")
	s2.mu.Lock()
	n := len(s2.sessions)
	s2.mu.Unlock()
	if n != 0 {
		t.Errorf("loaded %d session(s) with the wrong secret, want 0", n)
	}
}

// StartFlusher is a no-op for an in-memory store, and cancelling its context
// performs a final flush so a graceful shutdown does not drop the last few
// seconds of session activity.
func TestStartFlusher(t *testing.T) {
	t.Run("in-memory store is a no-op", func(t *testing.T) {
		s := NewStore()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s.StartFlusher(ctx) // must not panic or spawn a writer with no dir
	})

	t.Run("final flush on context cancel", func(t *testing.T) {
		dir := t.TempDir()
		s := NewPersistentStore(dir, "test-secret")
		s.mu.Lock()
		s.sessions["on-shutdown"] = &Session{IssuerDpg: "CREDEBL"}
		s.mu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		s.StartFlusher(ctx)
		cancel()

		// The final flush happens on the flusher goroutine. Reload until it
		// lands rather than sleeping for a fixed interval.
		path := filepath.Join(dir, "on-shutdown.sess")
		for range 200 {
			if _, err := os.Stat(path); err == nil {
				return
			}
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("context cancel did not trigger a final flush: %v", err)
		}
	})
}
