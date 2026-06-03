package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/internal/handlers"
	"github.com/verifiably/verifiably-go/vctypes"
)

const (
	sessionTTL    = 24 * time.Hour
	keyPrefix     = "vsess:"
	flushInterval = 5 * time.Second
)

// SessionStore is the Redis-backed implementation of handlers.SessionStore.
// Sessions are stored as JSON blobs at vsess:<id> with a 24-hour TTL.
// An in-memory write-through cache avoids a Redis round-trip on every
// handler call; dirty sessions are flushed every 5 seconds and on shutdown.
//
// Multi-replica: every replica reads the same Redis, so sessions are visible
// immediately after creation regardless of which replica handled the request.
// Pair with Caddy's lb_policy=cookie or ip_hash for full statefulness.
type SessionStore struct {
	client *Client
	key    []byte // 32-byte AES-256-GCM key; nil = plain-text fallback (dev only)

	mu    sync.Mutex
	dirty map[string]*handlers.Session // sessions mutated since last flush
	inMem map[string]*handlers.Session // hot cache for the current replica
}

// NewSessionStore creates the store. key is the 32-byte AES key used to
// encrypt session blobs before writing to Redis. Pass nil only in development;
// production must supply a key so that a Redis credential leak does not expose
// live OAuth tokens. Call StartFlusher after construction.
func NewSessionStore(client *Client, key []byte) *SessionStore {
	return &SessionStore{
		client: client,
		key:    key,
		dirty:  map[string]*handlers.Session{},
		inMem:  map[string]*handlers.Session{},
	}
}

// Get returns the existing session or nil if absent / expired.
func (s *SessionStore) Get(r *http.Request) *handlers.Session {
	c, err := r.Cookie("verifiably_session")
	if err != nil || c.Value == "" {
		return nil
	}
	return s.load(r.Context(), c.Value)
}

// MustGet returns the existing session or mints a new one.
func (s *SessionStore) MustGet(w http.ResponseWriter, r *http.Request) *handlers.Session {
	s.mu.Lock()
	var id string
	if c, err := r.Cookie("verifiably_session"); err == nil {
		id = c.Value
	}
	if id != "" {
		if sess := s.inMem[id]; sess != nil {
			s.mu.Unlock()
			return sess
		}
	}
	s.mu.Unlock()

	// Try Redis if not in local cache.
	if id != "" {
		if sess := s.loadFromRedis(id); sess != nil {
			s.mu.Lock()
			s.inMem[id] = sess
			s.mu.Unlock()
			return sess
		}
	}

	// Create new session.
	id = newRedisSessionID()
	sess := &handlers.Session{
		ID:            id,
		WalletPending: []vctypes.Credential{},
		CustomSchemas: []vctypes.Schema{},
		Scale:         "single",
		Dest:          "wallet",
		BulkSource:    "csv",
		SchemaFilter:  "all",
	}
	s.mu.Lock()
	s.inMem[id] = sess
	s.dirty[id] = sess
	s.mu.Unlock()
	// Write immediately so other replicas can see it.
	s.saveToRedis(sess)

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "verifiably_session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})
	return sess
}

// StartFlusher starts the background flush loop. Flushes dirty sessions to
// Redis every 5 seconds and performs a final flush when ctx is cancelled.
func (s *SessionStore) StartFlusher(ctx context.Context) {
	go func() {
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.flush()
			case <-ctx.Done():
				s.flush()
				return
			}
		}
	}()
}

func (s *SessionStore) load(_ context.Context, id string) *handlers.Session {
	s.mu.Lock()
	if sess := s.inMem[id]; sess != nil {
		s.mu.Unlock()
		return sess
	}
	s.mu.Unlock()
	sess := s.loadFromRedis(id)
	if sess != nil {
		s.mu.Lock()
		s.inMem[id] = sess
		s.mu.Unlock()
	}
	return sess
}

func (s *SessionStore) loadFromRedis(id string) *handlers.Session {
	data, err := s.client.Get(keyPrefix + id)
	if err != nil || data == nil {
		return nil
	}
	if s.key != nil {
		data, err = handlers.SessionDecrypt(s.key, data)
		if err != nil {
			return nil
		}
	}
	var sess handlers.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil
	}
	return &sess
}

func (s *SessionStore) saveToRedis(sess *handlers.Session) {
	data, err := json.Marshal(sess)
	if err != nil {
		return
	}
	if s.key != nil {
		data, err = handlers.SessionEncrypt(s.key, data)
		if err != nil {
			return
		}
	}
	_ = s.client.Set(keyPrefix+sess.ID, data, sessionTTL)
}

func (s *SessionStore) flush() {
	s.mu.Lock()
	dirty := s.dirty
	s.dirty = map[string]*handlers.Session{}
	s.mu.Unlock()
	for _, sess := range dirty {
		s.saveToRedis(sess)
	}
}

func newRedisSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
