package pg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verifiably/verifiably-go/internal/handlers"
	"github.com/verifiably/verifiably-go/vctypes"
)

// SessionStore is the PostgreSQL-backed implementation of handlers.SessionStore.
// It mirrors the file-backed store: an in-memory map is the hot path; a
// background goroutine flushes to Postgres every 5 seconds and cleans expired
// rows every 10 minutes. On startup it replays live sessions from the DB so
// sessions survive container restarts.
//
// Multi-replica note: each replica keeps its own in-memory map. A request that
// lands on a different replica after creation will trigger a new session. Use
// Redis (Fase 2) for true stateless replicas with L7 sticky sessions as the
// intermediate stepping stone.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*handlers.Session
	pool     *pgxpool.Pool
	key      []byte // 32-byte AES-256-GCM key; nil = plain-text fallback (dev only)
}

// NewSessionStore creates the store and loads any live sessions from the DB.
// key is the 32-byte AES key used to encrypt session blobs before writing to
// Postgres. Pass nil only in development; production must supply a key so that
// a DB credential leak does not expose live OAuth tokens.
func NewSessionStore(pool *pgxpool.Pool, key []byte) *SessionStore {
	s := &SessionStore{
		sessions: map[string]*handlers.Session{},
		pool:     pool,
		key:      key,
	}
	s.load()
	return s
}

// Get returns the existing session for the cookie, or nil.
func (s *SessionStore) Get(r *http.Request) *handlers.Session {
	c, err := r.Cookie("verifiably_session")
	if err != nil || c.Value == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[c.Value]
}

// MustGet returns the existing session or creates a new one, setting the cookie.
func (s *SessionStore) MustGet(w http.ResponseWriter, r *http.Request) *handlers.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var id string
	if c, err := r.Cookie("verifiably_session"); err == nil {
		id = c.Value
	}
	if id != "" {
		if sess := s.sessions[id]; sess != nil {
			return sess
		}
	}
	id = newPGSessionID()
	sess := &handlers.Session{
		ID:            id,
		WalletPending: []vctypes.Credential{},
		CustomSchemas: []vctypes.Schema{},
		Scale:         "single",
		Dest:          "wallet",
		BulkSource:    "csv",
		SchemaFilter:  "all",
	}
	s.sessions[id] = sess
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "verifiably_session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	return sess
}

// StartFlusher starts the background flush (5 s) and expiry cleanup (10 min).
func (s *SessionStore) StartFlusher(ctx context.Context) {
	go func() {
		flush := time.NewTicker(5 * time.Second)
		clean := time.NewTicker(10 * time.Minute)
		defer flush.Stop()
		defer clean.Stop()
		for {
			select {
			case <-flush.C:
				s.flush(ctx)
			case <-clean.C:
				_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
			case <-ctx.Done():
				s.flush(ctx)
				return
			}
		}
	}()
}

func (s *SessionStore) load() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx,
		`SELECT id, data FROM sessions WHERE expires_at > now()`)
	if err != nil {
		return
	}
	defer rows.Close()
	loaded := 0
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		if s.key != nil {
			var err error
			data, err = handlers.SessionDecrypt(s.key, data)
			if err != nil {
				continue
			}
		}
		var sess handlers.Session
		if err := json.Unmarshal(data, &sess); err != nil {
			continue
		}
		s.sessions[id] = &sess
		loaded++
	}
	_ = loaded
}

func (s *SessionStore) flush(ctx context.Context) {
	s.mu.Lock()
	type pending struct {
		id   string
		data []byte
	}
	items := make([]pending, 0, len(s.sessions))
	for id, sess := range s.sessions {
		data, err := json.Marshal(sess)
		if err != nil {
			continue
		}
		items = append(items, pending{id, data})
	}
	s.mu.Unlock()

	expires := time.Now().Add(24 * time.Hour)
	for _, p := range items {
		blob := p.data
		if s.key != nil {
			var err error
			blob, err = handlers.SessionEncrypt(s.key, p.data)
			if err != nil {
				continue
			}
		}
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO sessions (id, data, expires_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at`,
			p.id, blob, expires,
		)
	}
}

func newPGSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
