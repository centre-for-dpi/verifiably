// SPDX-License-Identifier: Apache-2.0

package httpsrc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/table"
)

// Errors the fetcher returns.
var (
	ErrMethod    = errors.New("httpsrc: the method must be GET or POST")
	ErrRedirect  = errors.New("httpsrc: the API answered with a redirect, redirects are not followed")
	ErrStatus    = errors.New("httpsrc: the API answered with an error status")
	ErrTooLarge  = errors.New("httpsrc: the response is larger than the limit")
	ErrNotJSON   = errors.New("httpsrc: the response is not JSON")
	ErrRowsPath  = errors.New("httpsrc: the rows path does not point at an array of objects")
	ErrBadMTLS   = errors.New("httpsrc: the client certificate or key is not valid")
	ErrNoAddress = errors.New("httpsrc: no checked address for the host")
)

// Limits when a Request or Fetcher field is zero.
const (
	DefaultTimeout  = 30 * time.Second
	DefaultMaxBytes = 8 << 20
)

// Auth is the credential of one request, already resolved.
type Auth struct {
	// Bearer is the token of a bearer credential.
	Bearer string
	// BasicUser and BasicPassword are the values of a basic credential.
	BasicUser, BasicPassword string
	// CertPEM and KeyPEM are the client certificate chain and key for mTLS.
	CertPEM, KeyPEM []byte
}

// Request describes one read of an API.
type Request struct {
	URL     string
	Method  string
	Headers map[string]string
	Auth    Auth
	// RowsPath is the RFC 6901 JSON pointer of the array of rows.
	// Empty means the body itself is the array.
	RowsPath string
	// Timeout bounds the whole request. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Fetcher reads rows from APIs that pass its guard.
type Fetcher struct {
	Guard Guard
	// MaxBytes caps the response body. Zero means DefaultMaxBytes.
	MaxBytes int64
	// RootCAs are the trusted roots for TLS. Nil means the system roots.
	RootCAs *x509.CertPool
}

// Fetch does the request and returns the rows.
func (f Fetcher) Fetch(ctx context.Context, r Request) (table.Table, error) {
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return table.Table{}, fmt.Errorf("%w: %s", ErrMethod, r.Method)
	}
	u, ips, err := f.Guard.Check(ctx, r.URL)
	if err != nil {
		return table.Table{}, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := f.client(u.Hostname(), ips, r.Auth)
	if err != nil {
		return table.Table{}, err
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return table.Table{}, fmt.Errorf("httpsrc: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	switch {
	case r.Auth.Bearer != "":
		req.Header.Set("Authorization", "Bearer "+r.Auth.Bearer)
	case r.Auth.BasicUser != "":
		req.SetBasicAuth(r.Auth.BasicUser, r.Auth.BasicPassword)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return table.Table{}, ErrRedirect
		}
		return table.Table{}, fmt.Errorf("httpsrc: %s %s: %w", method, u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return table.Table{}, fmt.Errorf("%w: %d", ErrStatus, resp.StatusCode)
	}
	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return table.Table{}, fmt.Errorf("httpsrc: read body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return table.Table{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, maxBytes)
	}
	return Rows(body, r.RowsPath)
}

// client builds a client that dials only ips for host and follows no
// redirect.
func (f Fetcher) client(host string, ips []net.IP, auth Auth) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.RootCAs, ServerName: host}
	if len(auth.CertPEM) > 0 || len(auth.KeyPEM) > 0 {
		cert, err := tls.X509KeyPair(auth.CertPEM, auth.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadMTLS, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var last error = ErrNoAddress
			for _, ip := range ips {
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}, nil
}

// Rows decodes body and returns the array of objects at pointer as rows.
// Nested values become JSON text. Numbers keep their source text.
func Rows(body []byte, pointer string) (table.Table, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return table.Table{}, fmt.Errorf("%w: %v", ErrNotJSON, err)
	}
	node, err := Pointer(doc, pointer)
	if err != nil {
		return table.Table{}, err
	}
	items, ok := node.([]any)
	if !ok {
		return table.Table{}, fmt.Errorf("%w: %q", ErrRowsPath, pointer)
	}
	rows := make([]map[string]string, 0, len(items))
	for i, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			return table.Table{}, fmt.Errorf("%w: item %d is not an object", ErrRowsPath, i)
		}
		row := make(map[string]string, len(obj))
		for k, v := range obj {
			row[k] = Stringify(v)
		}
		rows = append(rows, row)
	}
	return table.Table{Fields: table.FieldsOf(rows, nil), Rows: rows, Total: int64(len(rows))}, nil
}

// Pointer evaluates an RFC 6901 JSON pointer against doc.
func Pointer(doc any, pointer string) (any, error) {
	if pointer == "" {
		return doc, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("%w: pointer %q must start with /", ErrRowsPath, pointer)
	}
	node := doc
	for _, tok := range strings.Split(pointer[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch n := node.(type) {
		case map[string]any:
			v, ok := n[tok]
			if !ok {
				return nil, fmt.Errorf("%w: no member %q", ErrRowsPath, tok)
			}
			node = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(n) {
				return nil, fmt.Errorf("%w: no index %q", ErrRowsPath, tok)
			}
			node = n[i]
		default:
			return nil, fmt.Errorf("%w: %q is not an object or array", ErrRowsPath, tok)
		}
	}
	return node, nil
}

// Stringify turns a decoded JSON value into a row value.
func Stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	// Maps and slices from the decoder always encode.
	b, _ := json.Marshal(v)
	return string(b)
}
