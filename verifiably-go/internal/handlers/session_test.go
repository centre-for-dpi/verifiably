package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sessionTestKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// sessionWriteFile encrypts plain with the store key derived from secret and
// writes it as <dir>/<id>.sess.
func sessionWriteFile(t *testing.T, dir, secret, id string, plain []byte) string {
	t.Helper()
	enc, err := SessionEncrypt(sessionTestKey(secret), plain)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, id+".sess")
	if err := os.WriteFile(p, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSessionEncryptDecrypt(t *testing.T) {
	key := sessionTestKey("s3cret")
	enc, err := SessionEncrypt(key, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("hello")) {
		t.Error("ciphertext contains plaintext")
	}
	plain, err := SessionDecrypt(key, enc)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("roundtrip = %q, %v", plain, err)
	}
	// Two encryptions of the same plaintext differ (fresh nonce).
	enc2, _ := SessionEncrypt(key, []byte("hello"))
	if bytes.Equal(enc, enc2) {
		t.Error("nonce reuse: identical ciphertexts")
	}

	if _, err := SessionEncrypt([]byte("short"), []byte("x")); err == nil {
		t.Error("SessionEncrypt with a bad key length must fail")
	}
	if _, err := SessionDecrypt([]byte("short"), enc); err == nil {
		t.Error("SessionDecrypt with a bad key length must fail")
	}
	if _, err := SessionDecrypt(key, enc[:3]); err != os.ErrInvalid {
		t.Errorf("short data: err = %v, want os.ErrInvalid", err)
	}
	tampered := append([]byte{}, enc...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := SessionDecrypt(key, tampered); err == nil {
		t.Error("tampered ciphertext must not decrypt")
	}
	if _, err := SessionDecrypt(sessionTestKey("other"), enc); err == nil {
		t.Error("wrong key must not decrypt")
	}
}

func TestNewPersistentStore_FallsBackWhenDirUnusable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewPersistentStore(filepath.Join(file, "sessions"), "secret")
	if s.dir != "" || s.key != nil {
		t.Errorf("expected in-memory fallback, got dir=%q keylen=%d", s.dir, len(s.key))
	}
	// Still usable as an in-memory store.
	rr := httptest.NewRecorder()
	if sess := s.MustGet(rr, httptest.NewRequest(http.MethodGet, "/", nil)); sess == nil || sess.ID == "" {
		t.Error("fallback store must mint sessions")
	}
}

func TestNewPersistentStore_LoadsAndSkipsBadFiles(t *testing.T) {
	dir := t.TempDir()
	const secret = "secret"

	// good: loaded
	good, _ := json.Marshal(&Session{ID: "good", Role: "issuer", SchemaID: "Person"})
	sessionWriteFile(t, dir, secret, "good", good)
	// stale: valid but mtime 25 h ago → removed on load
	stale := sessionWriteFile(t, dir, secret, "stale", good)
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	// garbage: not decryptable
	if err := os.WriteFile(filepath.Join(dir, "garbage.sess"), []byte("not encrypted at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	// notjson: decrypts to invalid JSON
	sessionWriteFile(t, dir, secret, "notjson", []byte("{nope"))
	// unreadable: permissions deny ReadFile
	unreadable := sessionWriteFile(t, dir, secret, "unreadable", good)
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	// wrong suffix + a directory named like a session file: ignored
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir.sess"), 0o700); err != nil {
		t.Fatal(err)
	}

	s := NewPersistentStore(dir, secret)
	if s.dir != dir || len(s.key) != 32 {
		t.Fatalf("store not persistent: dir=%q keylen=%d", s.dir, len(s.key))
	}
	if len(s.sessions) != 1 {
		t.Fatalf("loaded %d sessions, want 1 (%v)", len(s.sessions), s.sessions)
	}
	if got := s.sessions["good"]; got == nil || got.Role != "issuer" || got.SchemaID != "Person" {
		t.Errorf("good session not restored: %+v", got)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale session file should have been removed, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "garbage.sess")); err != nil {
		t.Errorf("undecryptable file must be left alone: %v", err)
	}

	// A loaded session is served for its cookie.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "verifiably_session", Value: "good"})
	if got := s.Get(req); got == nil || got.ID != "good" {
		t.Errorf("Get(loaded cookie) = %+v", got)
	}
}

func TestStore_LoadMissingDirIsNoop(t *testing.T) {
	s := &Store{sessions: map[string]*Session{}, dir: filepath.Join(t.TempDir(), "absent"), key: sessionTestKey("k")}
	s.load()
	if len(s.sessions) != 0 {
		t.Errorf("sessions = %d, want 0", len(s.sessions))
	}
}

func TestStore_FlushWritesEncryptedFilesAndSkipsBadKey(t *testing.T) {
	dir := t.TempDir()
	s := NewPersistentStore(dir, "secret")
	rr := httptest.NewRecorder()
	sess := s.MustGet(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	sess.Role = "holder"
	sess.AccessToken = "never-on-disk"
	s.flush()

	p := filepath.Join(dir, sess.ID+".sess")
	enc, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("flush did not write %s: %v", p, err)
	}
	plain, err := SessionDecrypt(sessionTestKey("secret"), enc)
	if err != nil {
		t.Fatal(err)
	}
	var back Session
	if err := json.Unmarshal(plain, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != sess.ID || back.Role != "holder" {
		t.Errorf("flushed session = %+v", back)
	}
	if back.AccessToken != "" || bytes.Contains(plain, []byte("never-on-disk")) {
		t.Error("json:\"-\" token leaked to disk")
	}

	// A store whose key is unusable cannot encrypt: nothing is written, no panic.
	bad := &Store{sessions: map[string]*Session{"x": {ID: "x"}}, dir: dir, key: []byte("short")}
	bad.flush()
	if _, err := os.Stat(filepath.Join(dir, "x.sess")); !os.IsNotExist(err) {
		t.Errorf("bad-key flush must not write a file, stat err = %v", err)
	}
}

func TestStore_StartFlusher(t *testing.T) {
	// In-memory store: no goroutine, cancelled ctx never flushes anything.
	mem := NewStore()
	ctx, cancel := context.WithCancel(context.Background())
	mem.StartFlusher(ctx)
	cancel()

	dir := t.TempDir()
	s := NewPersistentStore(dir, "secret")
	rr := httptest.NewRecorder()
	sess := s.MustGet(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	ctx, cancel = context.WithCancel(context.Background())
	s.StartFlusher(ctx)
	cancel() // triggers the final flush
	p := filepath.Join(dir, sess.ID+".sess")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("final flush on ctx cancel did not write %s", p)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStore_Get(t *testing.T) {
	s := NewStore()
	if got := s.Get(httptest.NewRequest(http.MethodGet, "/", nil)); got != nil {
		t.Errorf("no cookie: got %+v, want nil", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "verifiably_session", Value: "unknown"})
	if got := s.Get(req); got != nil {
		t.Errorf("unknown cookie: got %+v, want nil", got)
	}
	rr := httptest.NewRecorder()
	sess := s.MustGet(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	if got := s.Get(req); got != sess {
		t.Errorf("known cookie: got %+v, want the minted session", got)
	}
}
