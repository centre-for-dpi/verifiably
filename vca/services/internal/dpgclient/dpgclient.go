// SPDX-License-Identifier: Apache-2.0

// Package dpgclient makes outbound HTTP calls to a DPG. Every DPG
// adapter talks to its DPG over the HTTP API of the DPG and never over
// its database or the Docker socket (ADR-002 decision 4).
//
// The client adds one bearer token, a request timeout, a retry with a
// growing wait for a temporary failure, a limit on the response size,
// and W3C trace context propagation (ADR-002 decision 6). It replaces
// the legacy internal/httpx package.
//
// The package is small on purpose. Request bodies and response bodies
// are bytes or JSON. The caller owns the paths and the payload shapes.
package dpgclient

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

	"github.com/centre-for-dpi/vc-adapters/services/internal/serve/trace"
)

// DefaultTimeout bounds one attempt.
const DefaultTimeout = 30 * time.Second

// DefaultMaxBytes bounds the response body the client reads.
const DefaultMaxBytes = 8 << 20

// DefaultRetries is the number of extra attempts after the first one.
const DefaultRetries = 2

// DefaultBackoff is the wait before the first retry. Each further retry
// waits twice as long.
const DefaultBackoff = 200 * time.Millisecond

// UserAgent names the caller in the DPG access log.
const UserAgent = "vc-adapters/1"

// ErrTooLarge reports a response body above the size limit.
var ErrTooLarge = errors.New("dpgclient: the response is above the size limit")

// ErrNoBaseURL reports a client without a base URL.
var ErrNoBaseURL = errors.New("dpgclient: no base URL")

// StatusError reports a response with a status of 400 or above.
type StatusError struct {
	// Method is the HTTP method of the request.
	Method string
	// URL is the request URL.
	URL string
	// Status is the HTTP status code.
	Status int
	// Body is the start of the response body, for the operator log.
	Body string
}

func (e *StatusError) Error() string {
	body := e.Body
	if len(body) > 240 {
		body = body[:240] + "..."
	}
	return fmt.Sprintf("dpgclient: %s %s returned %d: %s", e.Method, e.URL, e.Status, body)
}

// IsStatus reports whether err is a StatusError with the status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == status
}

// Options configure New.
type Options struct {
	// BaseURL is the root of the DPG API, for example
	// http://issuer-api:7002. A path that starts with http keeps its
	// own host.
	BaseURL string
	// Token is a static bearer token. A call can override it.
	Token string
	// Timeout bounds one attempt. Zero means DefaultTimeout.
	Timeout time.Duration
	// Retries is the number of extra attempts. A value below zero means
	// no retry. Zero means DefaultRetries.
	Retries int
	// Backoff is the wait before the first retry. Zero means
	// DefaultBackoff.
	Backoff time.Duration
	// MaxBytes bounds the response body. Zero means DefaultMaxBytes.
	MaxBytes int64
	// HTTP replaces the transport. Tests set it to an httptest client.
	HTTP *http.Client
	// Sleep waits between two attempts. Nil means time.Sleep. Tests set
	// it so a retry costs no time.
	Sleep func(time.Duration)
}

// Client calls one DPG.
type Client struct {
	baseURL  string
	token    string
	retries  int
	backoff  time.Duration
	maxBytes int64
	http     *http.Client
	sleep    func(time.Duration)
}

// New returns a client for one DPG.
func New(opts Options) *Client {
	c := &Client{
		baseURL:  strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/"),
		token:    opts.Token,
		retries:  opts.Retries,
		backoff:  opts.Backoff,
		maxBytes: opts.MaxBytes,
		http:     opts.HTTP,
		sleep:    opts.Sleep,
	}
	if c.retries == 0 {
		c.retries = DefaultRetries
	}
	if c.retries < 0 {
		c.retries = 0
	}
	if c.backoff <= 0 {
		c.backoff = DefaultBackoff
	}
	if c.maxBytes <= 0 {
		c.maxBytes = DefaultMaxBytes
	}
	if c.http == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		c.http = &http.Client{Timeout: timeout}
	}
	if c.sleep == nil {
		c.sleep = time.Sleep
	}
	return c
}

// BaseURL returns the root of the DPG API.
func (c *Client) BaseURL() string { return c.baseURL }

// WithToken returns a copy of the client that sends another bearer
// token. The original client does not change.
func (c *Client) WithToken(token string) *Client {
	copied := *c
	copied.token = token
	return &copied
}

// Request describes one call.
type Request struct {
	// Method is the HTTP method.
	Method string
	// Path is the path on the DPG, or a full URL.
	Path string
	// Body is the request body. Nil sends no body.
	Body []byte
	// ContentType names the media type of Body.
	ContentType string
	// Accept names the media types the caller wants.
	Accept string
	// Header adds or replaces request headers.
	Header http.Header
	// Token overrides the bearer token of the client.
	Token string
}

// Response is one answer from the DPG.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// Header holds the response headers.
	Header http.Header
	// Body holds the response body up to the size limit.
	Body []byte
}

// Do sends the request and returns the response. It retries a network
// error, a 429, and a 5xx status up to the configured count.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	target, err := c.url(r.Path)
	if err != nil {
		return nil, err
	}
	wait := c.backoff
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			c.sleep(wait)
			wait *= 2
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		resp, err := c.attempt(ctx, target, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

// attempt sends the request once.
func (c *Client) attempt(ctx context.Context, target string, r Request) (*Response, error) {
	var body io.Reader
	if r.Body != nil {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target, body)
	if err != nil {
		return nil, fmt.Errorf("dpgclient: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	token := r.Token
	if token == "" {
		token = c.token
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	trace.Inject(ctx, req.Header)
	for name, values := range r.Header {
		for _, v := range values {
			req.Header.Set(name, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dpgclient: %s %s: %w", r.Method, target, err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if readErr != nil {
		return nil, fmt.Errorf("dpgclient: read %s: %w", target, readErr)
	}
	if int64(len(raw)) > c.maxBytes {
		return nil, fmt.Errorf("dpgclient: %s is above %d bytes: %w", target, c.maxBytes, ErrTooLarge)
	}
	if resp.StatusCode >= 400 {
		return nil, &StatusError{Method: r.Method, URL: target, Status: resp.StatusCode, Body: string(raw)}
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

// retryable reports whether another attempt can succeed.
func retryable(err error) bool {
	if errors.Is(err, ErrTooLarge) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status == http.StatusTooManyRequests || se.Status >= 500
	}
	return true
}

// url joins the path with the base URL.
func (c *Client) url(path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	if c.baseURL == "" {
		return "", ErrNoBaseURL
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL + path, nil
}

// JSON sends a JSON body and decodes a JSON response into out. Either
// body or out may be nil.
func (c *Client) JSON(ctx context.Context, method, path string, body, out any) error {
	r := Request{Method: method, Path: path, Accept: "application/json"}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("dpgclient: encode the request: %w", err)
		}
		r.Body = raw
		r.ContentType = "application/json"
	}
	resp, err := c.Do(ctx, r)
	if err != nil {
		return err
	}
	return decode(resp.Body, out)
}

// Form sends an application/x-www-form-urlencoded body and decodes a
// JSON response into out.
func (c *Client) Form(ctx context.Context, method, path string, form url.Values, out any) error {
	resp, err := c.Do(ctx, Request{
		Method:      method,
		Path:        path,
		Body:        []byte(form.Encode()),
		ContentType: "application/x-www-form-urlencoded",
		Accept:      "application/json",
	})
	if err != nil {
		return err
	}
	return decode(resp.Body, out)
}

// Text sends a body of the media type and returns the response body as a
// trimmed string. Several DPG endpoints answer with a bare URL.
func (c *Client) Text(ctx context.Context, method, path, contentType string, body []byte) (string, error) {
	resp, err := c.Do(ctx, Request{Method: method, Path: path, Body: body, ContentType: contentType})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(resp.Body)), nil
}

// decode reads JSON into out. A nil out drops the body. An empty body
// leaves out unchanged.
func decode(raw []byte, out any) error {
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber keeps a whole number whole, so a credential claim never
	// travels through a float.
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("dpgclient: decode the response: %w", err)
	}
	return nil
}
