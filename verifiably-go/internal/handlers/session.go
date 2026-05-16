package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/vctypes"
)

// Session holds per-user in-memory state. For a real deployment, swap this
// for a server-side store (Redis, Postgres) keyed by the session cookie.
//
// CONCURRENCY: once a *Session is handed out by the Store, handlers read and
// mutate its fields without explicit locking. In practice this is safe for a
// single-user demo because the HTML-based UI serializes requests at the browser
// level (one form submission in flight at a time) for most interactions. The
// schema-builder's debounced keystroke endpoint can overlap with add/remove-field
// clicks; in the unlikely race the worst outcome is a briefly-stale JSON preview,
// not corrupted session state. A real deployment should add a per-session
// sync.Mutex or move to an external session store.
type Session struct {
	ID string

	// Onboarding selections — selected DPG per role
	Role        string // "issuer" | "holder" | "verifier"
	AuthOK      bool
	IssuerDpg   string
	HolderDpg   string
	VerifierDpg string

	// IsAdmin is the standalone admin-session flag. Independent of the OIDC
	// Role/AuthOK so an operator can be signed in as both admin (managing
	// providers) and as an issuer/holder/verifier (using the demo). Set by
	// AdminLogin, cleared by AdminLogout.
	IsAdmin bool

	// DPG-picker state — which card is expanded on each picker screen.
	// Expansion and selection are the same action in this UI: expanding a
	// card selects that DPG; collapsing it unselects.
	ExpandedIssuerDpg   string
	ExpandedHolderDpg   string
	ExpandedVerifierDpg string

	// Issuer flow state
	SchemaID         string          // selected schema id
	Scale            string          // "single" | "bulk"
	Dest             string          // "wallet" | "pdf"
	BulkSource       string          // "csv" | "api" | "db" — active bulk source
	ExpandedSchemaID string          // currently expanded card
	SchemaFilter     string          // "all" or one of the stds
	SchemaQuery      string          // current search text
	CustomSchemas    []vctypes.Schema   // in-session custom schemas

	// Issued-credentials list page filter state. Persisted on the session
	// so that a Revoke action's row-fragment re-render preserves whatever
	// the user was viewing.
	IssuedQuery  string
	IssuedStd    string // "" or one of the stds; "all" maps to ""
	IssuedFormat string
	IssuedState  string // "", "active", "revoked"

	// Wallet state
	WalletCreds   []vctypes.Credential
	WalletPending []vctypes.Credential

	// Verifier state
	CurrentOID4VPLink      string
	CurrentOID4VPState     string
	CurrentOID4VPTemplate  string
	// Custom template the user assembled via the "Build custom request"
	// flow. Set by BuildVerifierTemplate; consumed by RequestCustomPresentation
	// and echoed back to the preview fragment so the user can review what
	// they're about to request before hitting Generate.
	CustomOID4VPTemplate *vctypes.OID4VPTemplate
	// CustomOID4VPSchemaID is the schema the custom template was built from,
	// so the field-picker fragment can re-render with its selections intact.
	CustomOID4VPSchemaID string
	// VerifierSchemaFilter / VerifierSchemaQuery drive the card-browser's
	// std chips + search input on the verifier's custom-request section.
	// Mirrors SchemaFilter/SchemaQuery on the issuer side but kept separate
	// so switching role doesn't blow away the other role's filter state.
	VerifierSchemaFilter string
	VerifierSchemaQuery  string

	// LastWalletError is the most recent error from a wallet action
	// (paste, scan, accept). Rendered as an inline banner on the wallet
	// page so the user sees what failed instead of a silent toast.
	LastWalletError string

	// Auth: OIDC round-trip state + tokens stored after callback.
	PendingProvider string
	PendingState    string
	PendingPKCE     string
	AuthProvider    string // id of the provider that completed auth
	AccessToken     string
	RefreshToken    string
	IDToken         string
	UserEmail       string
	// UserSubject is the OIDC `sub` claim — the stable per-user id the
	// provider assigns. Used (combined with AuthProvider) as the
	// partition key for upstream wallet accounts so two users logging
	// into the same browser session don't collide on an email-less key.
	UserSubject     string

	// WalletUserKey is the frozen identity the upstream wallet is
	// partitioned by. Computed once, on the first call to holderCtx, from
	// the best-available identity at that moment (AuthProvider+Subject >
	// email > session-id). Never re-derived — if it flipped mid-session
	// whenever the OIDC subject appeared/disappeared, credentials claimed
	// before the flip would be stranded in a wallet the browser session
	// no longer addresses. Cleared in AuthCallback alongside WalletCreds
	// so a fresh login starts from a clean derivation.
	WalletUserKey string

	// Misc
	NextExampleIdx int
}

// Store is a thread-safe session store keyed by cookie ID.
//
// Persistence: when dir != "" the store periodically flushes all sessions to
// encrypted JSON files in dir (one file per session, AES-256-GCM). On the
// next startup it replays them so sessions survive container restarts.
// The flush interval is 5 seconds; a final flush runs on Stop().
// When dir == "" the store is purely in-memory (original behaviour).
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session

	dir string   // "" = in-memory only
	key []byte   // 32-byte AES key; nil when dir == ""
}

// NewStore returns a purely in-memory session store (original behaviour).
func NewStore() *Store {
	return &Store{sessions: map[string]*Session{}}
}

// NewPersistentStore returns a session store that flushes to dir every 5 s.
// secret is any string; it is SHA-256'd to derive the 32-byte AES key.
// Existing sessions in dir are loaded immediately so they survive restarts.
func NewPersistentStore(dir, secret string) *Store {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("session store: cannot create dir %q, falling back to in-memory: %v", dir, err)
		return NewStore()
	}
	h := sha256.Sum256([]byte(secret))
	s := &Store{
		sessions: map[string]*Session{},
		dir:      dir,
		key:      h[:],
	}
	s.load()
	return s
}

// StartFlusher starts the background goroutine that periodically flushes
// sessions to disk. It stops when ctx is cancelled, performing a final flush.
// Call this after NewPersistentStore; it is a no-op for in-memory stores.
func (s *Store) StartFlusher(ctx context.Context) {
	if s.dir == "" {
		return
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
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

func (s *Store) load() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sess") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".sess")
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		plain, err := sessionDecrypt(s.key, data)
		if err != nil {
			continue
		}
		var sess Session
		if err := json.Unmarshal(plain, &sess); err != nil {
			continue
		}
		// Discard sessions that have gone stale (>24 h since cookie expiry).
		// We use the file mtime as the last-active timestamp.
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > 24*time.Hour {
			os.Remove(filepath.Join(s.dir, e.Name()))
			continue
		}
		s.sessions[id] = &sess
		loaded++
	}
	if loaded > 0 {
		log.Printf("session store: loaded %d session(s) from %s", loaded, s.dir)
	}
}

func (s *Store) flush() {
	s.mu.Lock()
	snapshot := make(map[string]*Session, len(s.sessions))
	for id, sess := range s.sessions {
		snapshot[id] = sess
	}
	s.mu.Unlock()

	for id, sess := range snapshot {
		data, err := json.Marshal(sess)
		if err != nil {
			continue
		}
		enc, err := sessionEncrypt(s.key, data)
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(s.dir, id+".sess"), enc, 0o600)
	}
}

// sessionEncrypt encrypts plain with AES-256-GCM. Output: nonce || ciphertext.
func sessionEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// sessionDecrypt reverses sessionEncrypt.
func sessionDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, os.ErrInvalid
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func (s *Store) getOrCreate(r *http.Request, w http.ResponseWriter) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var id string
	if c, err := r.Cookie("verifiably_session"); err == nil {
		id = c.Value
	}
	if id == "" || s.sessions[id] == nil {
		id = newSessionID()
		sess := &Session{
			ID:            id,
			WalletCreds:   nil, // lazy-loaded by ShowWallet via BACKEND.ListWalletCredentials
			WalletPending: []vctypes.Credential{},
			CustomSchemas: []vctypes.Schema{},
			Scale:         "single",
			Dest:          "wallet",
			BulkSource:    "csv",
			SchemaFilter:  "all",
		}
		s.sessions[id] = sess
		http.SetCookie(w, &http.Cookie{
			Name:     "verifiably_session",
			Value:    id,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(24 * time.Hour),
		})
	}
	return s.sessions[id]
}

// Get returns the existing session or nil. Used by handlers that should not
// accidentally mint a session (e.g. API endpoints called without a prior visit).
func (s *Store) Get(r *http.Request) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := r.Cookie("verifiably_session")
	if err != nil {
		return nil
	}
	return s.sessions[c.Value]
}

// MustGet is getOrCreate — handlers use this when they need a session to exist.
func (s *Store) MustGet(w http.ResponseWriter, r *http.Request) *Session {
	return s.getOrCreate(r, w)
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
