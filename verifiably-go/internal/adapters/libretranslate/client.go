// Package libretranslate is a tiny client for a LibreTranslate instance.
// It caches every translated string both in memory and on disk under
// locales/<lang>.json so repeat renders don't hit the network.
package libretranslate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/verifiably/verifiably-go/internal/httpx"
)

// Client translates strings via a LibreTranslate endpoint with a persistent
// disk cache. Safe for concurrent use.
type Client struct {
	BaseURL    string
	Source     string // source language; defaults to "en"
	LocalesDir string

	mu    sync.Mutex
	http  *httpx.Client
	cache map[string]map[string]string // target → (source → translation)
}

// New constructs a Client. localesDir is where per-language JSON files are
// persisted (created on first write).
func New(baseURL, localesDir string) *Client {
	if localesDir == "" {
		localesDir = "locales"
	}
	return &Client{
		BaseURL:    baseURL,
		Source:     "en",
		LocalesDir: localesDir,
		http:       httpx.New(baseURL),
		cache:      map[string]map[string]string{},
	}
}

// Translate returns the translated text for the given target language. For
// target=="" or target=="en" the source string is returned unchanged.
func (c *Client) Translate(ctx context.Context, text, target string) string {
	if os.Getenv("VERIFIABLY_I18N_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "i18n: Translate target=%q textlen=%d\n", target, len(text))
	}
	if target == "" || target == "en" || text == "" {
		return text
	}
	// Memory cache hit?
	c.mu.Lock()
	if m, ok := c.cache[target]; ok {
		if t, ok := m[text]; ok {
			c.mu.Unlock()
			return t
		}
	}
	c.mu.Unlock()

	// Disk cache next — may have been populated by a prior process.
	if t := c.loadFromDisk(target, text); t != "" {
		c.storeInMemory(target, text, t)
		return t
	}

	// Live API call. Fall back to source on any error so the UI never breaks.
	tr, err := c.translateAPI(ctx, text, target)
	if err != nil || tr == "" {
		if debug := os.Getenv("VERIFIABLY_I18N_DEBUG"); debug != "" {
			// Surface silent fallbacks when debugging.
			fmt.Fprintf(os.Stderr, "i18n: translate fallback target=%s err=%v empty=%v\n",
				target, err, tr == "")
		}
		return text
	}
	c.storeInMemory(target, text, tr)
	c.persistToDisk(target, text, tr)
	return tr
}

type translateRequest struct {
	Q      string `json:"q"`
	Source string `json:"source"`
	Target string `json:"target"`
	Format string `json:"format,omitempty"`
}

type translateResponse struct {
	TranslatedText string `json:"translatedText"`
}

func (c *Client) translateAPI(ctx context.Context, text, target string) (string, error) {
	var resp translateResponse
	err := c.http.DoJSON(ctx, http.MethodPost, "/translate", translateRequest{
		Q: text, Source: c.Source, Target: target, Format: "text",
	}, &resp, nil)
	if err != nil {
		return "", err
	}
	return resp.TranslatedText, nil
}

func (c *Client) loadFromDisk(target, text string) string {
	c.mu.Lock()
	_, ok := c.cache[target]
	c.mu.Unlock()
	if ok {
		// Cache already loaded — memory check above already missed.
		return ""
	}
	path := filepath.Join(c.LocalesDir, target+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		c.mu.Lock()
		c.cache[target] = map[string]string{} // mark loaded-but-empty
		c.mu.Unlock()
		return ""
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		c.mu.Lock()
		c.cache[target] = map[string]string{}
		c.mu.Unlock()
		return ""
	}
	c.mu.Lock()
	c.cache[target] = m
	c.mu.Unlock()
	return m[text]
}

func (c *Client) storeInMemory(target, text, tr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.cache[target]
	if !ok {
		m = map[string]string{}
		c.cache[target] = m
	}
	m[text] = tr
}

func (c *Client) persistToDisk(target, text, tr string) {
	c.mu.Lock()
	m := make(map[string]string, len(c.cache[target]))
	for k, v := range c.cache[target] {
		m[k] = v
	}
	m[text] = tr
	c.mu.Unlock()
	_ = os.MkdirAll(c.LocalesDir, 0o755)
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := filepath.Join(c.LocalesDir, target+".json.tmp")
	final := filepath.Join(c.LocalesDir, target+".json")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, final)
}

// SupportedLanguages returns the static set this deployment declares it can
// translate into. LibreTranslate is configured via LT_LOAD_ONLY=en,es,fr so
// the UI offers exactly those three.
func SupportedLanguages() []Language {
	return []Language{
		{Code: "en", Name: "English", Native: "English"},
		{Code: "fr", Name: "French", Native: "Français"},
		{Code: "es", Name: "Spanish", Native: "Español"},
	}
}

// Language describes one selectable UI language.
type Language struct {
	Code   string
	Name   string
	Native string
}

// KnownLanguage returns true if the language code is in SupportedLanguages.
func KnownLanguage(code string) bool {
	for _, l := range SupportedLanguages() {
		if l.Code == code {
			return true
		}
	}
	return false
}

// NormalizeLang trims whitespace, lowercases, and clamps the value to a
// supported code (defaulting to "en" for unknown inputs).
func NormalizeLang(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if KnownLanguage(s) {
		return s
	}
	return "en"
}
