// Package httpx is a small shared HTTP client layer for adapter packages.
// It handles: Authorization bearer injection from context, default timeouts,
// JSON marshalling, and vendor-neutral error mapping. Adapter packages build
// on this instead of rolling their own http.Client each time.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/internal/tracing"
)

// tokenCtxKey is the private context key for a bearer token. Handlers put the
// session's access token into request context via WithToken; adapters pull it
// out here without ever naming an IDP.
type tokenCtxKey struct{}

// WithToken returns a derived context carrying a bearer token.
func WithToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, tokenCtxKey{}, token)
}

// tokenFrom returns the bearer token on ctx, if any.
func tokenFrom(ctx context.Context) string {
	if v, ok := ctx.Value(tokenCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// Client wraps http.Client with adapter-friendly helpers.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// UserAgent is sent on every request (helpful when tracing demo traffic
	// through upstream DPG containers).
	UserAgent string
}

// New constructs a Client with a default 30s timeout.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		UserAgent: "verifiably-go/1.0",
	}
}

// WithTimeout returns a copy of c with a different overall request timeout.
func (c *Client) WithTimeout(d time.Duration) *Client {
	cc := *c
	cc.HTTP = &http.Client{Timeout: d}
	return &cc
}

// DoJSON sends method+path (joined against BaseURL) with an optional JSON body
// and decodes a JSON response into out. out may be nil. Headers provided in h
// are applied after defaults so callers can override Content-Type when needed.
func (c *Client) DoJSON(ctx context.Context, method, path string, body any, out any, h http.Header) error {
	u, err := c.url(path)
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if tok := tokenFrom(ctx); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	tracing.Inject(ctx, req.Header)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return &StatusError{Method: method, URL: u, Status: resp.StatusCode, Body: string(b)}
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

// DoForm sends application/x-www-form-urlencoded with the given values.
func (c *Client) DoForm(ctx context.Context, method, path string, form url.Values, out any, h http.Header) error {
	u, err := c.url(path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if tok := tokenFrom(ctx); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	tracing.Inject(ctx, req.Header)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return &StatusError{Method: method, URL: u, Status: resp.StatusCode, Body: string(b)}
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

// DoRaw returns the raw response body bytes after status-code enforcement.
// Use for endpoints returning text/plain (bare strings, JWTs, PDFs, etc.).
func (c *Client) DoRaw(ctx context.Context, method, path string, body io.Reader, contentType string, h http.Header) ([]byte, error) {
	u, err := c.url(path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if tok := tokenFrom(ctx); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	tracing.Inject(ctx, req.Header)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, &StatusError{Method: method, URL: u, Status: resp.StatusCode, Body: string(b)}
	}
	return b, nil
}

func (c *Client) url(path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	if c.BaseURL == "" {
		return "", errors.New("httpx: empty BaseURL with relative path")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.BaseURL + path, nil
}

// StatusError is returned when the HTTP status is >= 400. Adapter code can
// inspect it to translate into typed domain errors (backend.ErrNotSupported,
// ErrOfferUnresolvable, etc.).
type StatusError struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	snippet := e.Body
	if len(snippet) > 240 {
		snippet = snippet[:240] + "…"
	}
	return fmt.Sprintf("%s %s: %d %s", e.Method, e.URL, e.Status, snippet)
}

// IsStatus returns true if err is a StatusError with the given HTTP status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status == status
	}
	return false
}
