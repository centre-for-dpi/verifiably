// SPDX-License-Identifier: Apache-2.0

// Package ports holds the outbound calls of the wallet portal: the
// catalogue of the discovery service, the eligibility hook, the trust
// registry lookup, and a size limited HTTP fetcher with a cache.
//
// Every port is an interface or a function value. A test injects a
// fake, so no test needs a network (ADR-004).
package ports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
)

// ErrTooLarge reports a document above the size cap.
var ErrTooLarge = errors.New("ports: the document is too large")

// ErrNoCatalogue reports a deployment with no discovery service.
var ErrNoCatalogue = errors.New("ports: no catalogue is configured")

// Catalogue returns the credential types that issuers publish
// (ADR-021 decision 1, ADR-022 decision 5).
type Catalogue interface {
	// Offerings returns one entry per published credential type.
	Offerings(ctx context.Context) ([]*walletportalv1.Offering, error)
}

// CatalogueFunc makes a function a Catalogue. A test uses it.
type CatalogueFunc func(ctx context.Context) ([]*walletportalv1.Offering, error)

// Offerings calls the function.
func (f CatalogueFunc) Offerings(ctx context.Context) ([]*walletportalv1.Offering, error) {
	return f(ctx)
}

// discovery reads the catalogue of the verifier discovery service.
type discovery struct {
	client   discoveryv1connect.DiscoveryServiceClient
	pageSize int32
}

// DefaultPageSize is the page size of one catalogue call.
const DefaultPageSize = 100

// NewCatalogue returns a catalogue over the discovery service client.
func NewCatalogue(client discoveryv1connect.DiscoveryServiceClient, pageSize int) (Catalogue, error) {
	if client == nil {
		return nil, ErrNoCatalogue
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	return &discovery{client: client, pageSize: toInt32(int64(pageSize))}, nil
}

// Offerings reads the issuers and their credential types.
func (d *discovery) Offerings(ctx context.Context) ([]*walletportalv1.Offering, error) {
	issuers, err := d.issuers(ctx)
	if err != nil {
		return nil, err
	}
	var out []*walletportalv1.Offering
	token := ""
	for {
		resp, err := d.client.ListCredentialTypes(ctx, connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{
			Page: &commonv1.Pagination{PageSize: d.pageSize, PageToken: token},
		}))
		if err != nil {
			return nil, fmt.Errorf("ports: read the catalogue: %w", err)
		}
		for _, item := range resp.Msg.GetTypes() {
			issuer := issuers[item.GetCredentialIssuer()]
			out = append(out, offeringOf(item, issuer))
		}
		token = resp.Msg.GetPage().GetNextPageToken()
		if token == "" {
			return out, nil
		}
	}
}

// issuers reads the crawled issuers, keyed by issuer URL.
func (d *discovery) issuers(ctx context.Context) (map[string]*discoveryv1.Issuer, error) {
	out := map[string]*discoveryv1.Issuer{}
	token := ""
	for {
		resp, err := d.client.ListIssuers(ctx, connect.NewRequest(&discoveryv1.ListIssuersRequest{
			Page: &commonv1.Pagination{PageSize: d.pageSize, PageToken: token},
		}))
		if err != nil {
			return nil, fmt.Errorf("ports: read the issuers: %w", err)
		}
		for _, issuer := range resp.Msg.GetIssuers() {
			out[issuer.GetCredentialIssuer()] = issuer
		}
		token = resp.Msg.GetPage().GetNextPageToken()
		if token == "" {
			return out, nil
		}
	}
}

// offeringOf maps one catalogue entry to an offering.
func offeringOf(item *discoveryv1.CredentialType, issuer *discoveryv1.Issuer) *walletportalv1.Offering {
	schema := &schemav1.PublicSchema{
		Id:      item.GetSchemaId(),
		Version: item.GetSchemaVersion(),
		Type:    item.GetType(),
		Display: item.GetDisplay(),
	}
	if item.GetFormat() != commonv1.Format_FORMAT_UNSPECIFIED {
		schema.Formats = []commonv1.Format{item.GetFormat()}
	}
	if id := item.GetConfigurationId(); id != "" {
		schema.ConfigurationIds = map[string]string{item.GetFormat().String(): id}
	}
	if schema.GetId() == "" {
		schema.Id = item.GetType()
	}
	return &walletportalv1.Offering{
		CredentialIssuer: item.GetCredentialIssuer(),
		IssuerName:       issuer.GetDisplayName(),
		Trust:            issuer.GetTrust(),
		Schema:           schema,
	}
}

// cached holds the offerings of a catalogue for a time.
type cached struct {
	next    Catalogue
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	items   []*walletportalv1.Offering
	expires time.Time
}

// Cached returns a catalogue that keeps the offerings for ttl.
func Cached(next Catalogue, ttl time.Duration, now func() time.Time) Catalogue {
	if now == nil {
		now = time.Now
	}
	return &cached{next: next, ttl: ttl, now: now}
}

// Offerings answers from the cache when it can.
func (c *cached) Offerings(ctx context.Context) ([]*walletportalv1.Offering, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items != nil && c.now().Before(c.expires) {
		return c.items, nil
	}
	items, err := c.next.Offerings(ctx)
	if err != nil {
		return nil, err
	}
	c.items, c.expires = items, c.now().Add(c.ttl)
	return items, nil
}

// DisplayOf returns a card display lookup over a catalogue. The card
// builder uses it for the title and the colours.
func DisplayOf(cat Catalogue) cards.Display {
	if cat == nil {
		return nil
	}
	return func(ctx context.Context, issuer, credentialType string) *schemav1.Display {
		items, err := cat.Offerings(ctx)
		if err != nil {
			return nil
		}
		for _, o := range items {
			if !strings.EqualFold(o.GetSchema().GetType(), credentialType) {
				continue
			}
			if issuer != "" && o.GetCredentialIssuer() != "" && o.GetCredentialIssuer() != issuer {
				continue
			}
			if list := o.GetSchema().GetDisplay(); len(list) > 0 {
				return list[0]
			}
		}
		return nil
	}
}

// Eligibility answers whether one citizen can get one credential. The
// answer is yes or no and nothing more (ADR-021 decision 2).
type Eligibility func(ctx context.Context, subjectRef string, o *walletportalv1.Offering) (bool, error)

// StaticEligibility returns a hook that always gives the same answer.
// A deployment with no hook uses it.
func StaticEligibility(answer bool) Eligibility {
	return func(context.Context, string, *walletportalv1.Offering) (bool, error) {
		return answer, nil
	}
}

// eligibilityRequest is the body the hook receives. It carries the
// salted subject reference, never the subject itself.
type eligibilityRequest struct {
	Subject          string `json:"subject_ref"`
	CredentialIssuer string `json:"credential_issuer"`
	SchemaID         string `json:"schema_id"`
	Type             string `json:"type"`
}

// eligibilityResponse is the answer of the hook.
type eligibilityResponse struct {
	Eligible bool `json:"eligible"`
}

// Poster sends one JSON body and returns the answer.
type Poster func(ctx context.Context, url string, body []byte) ([]byte, error)

// HTTPEligibility returns a hook that asks an HTTP endpoint. The hook
// sees the salted subject reference and the schema only.
func HTTPEligibility(endpoint string, post Poster) (Eligibility, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, errors.New("ports: the eligibility URL is empty")
	}
	if post == nil {
		return nil, errors.New("ports: the eligibility hook needs a poster")
	}
	return func(ctx context.Context, subjectRef string, o *walletportalv1.Offering) (bool, error) {
		body, err := json.Marshal(eligibilityRequest{
			Subject:          subjectRef,
			CredentialIssuer: o.GetCredentialIssuer(),
			SchemaID:         o.GetSchema().GetId(),
			Type:             o.GetSchema().GetType(),
		})
		if err != nil {
			return false, fmt.Errorf("ports: encode the question: %w", err)
		}
		raw, err := post(ctx, endpoint, body)
		if err != nil {
			return false, fmt.Errorf("ports: ask the eligibility hook: %w", err)
		}
		var answer eligibilityResponse
		if err := json.Unmarshal(raw, &answer); err != nil {
			return false, fmt.Errorf("ports: the hook answer does not parse: %w", err)
		}
		return answer.Eligible, nil
	}, nil
}

// SubjectRef returns the salted, one way reference of a subject
// (ADR-017 decision 2). The hook never sees the subject itself.
func SubjectRef(salt, subject string) string {
	sum := sha256.Sum256([]byte(salt + "|" + subject))
	return hex.EncodeToString(sum[:16])
}

// Trust returns a lookup that asks the trust registry service.
func Trust(client trustv1connect.TrustServiceClient, role commonv1.Role) cards.TrustLookup {
	if client == nil {
		return nil
	}
	return func(ctx context.Context, issuer, credentialType string) (cards.Trust, error) {
		resp, err := client.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{
			Identifier:     identifierOf(issuer),
			Role:           role,
			CredentialType: credentialType,
		}))
		if err != nil {
			return cards.Trust{}, fmt.Errorf("ports: trust lookup: %w", err)
		}
		return cards.Trust{
			Outcome: resp.Msg.GetOutcome(),
			Name:    resp.Msg.GetEntry().GetDisplayName(),
		}, nil
	}
}

// identifierOf maps an issuer string to a trust list identifier. An
// issuer that is not a DID goes in the x509 subject field, which the
// trust registry also matches on.
func identifierOf(issuer string) *trustv1.TrustEntry_Identifier {
	if strings.HasPrefix(issuer, "did:") {
		return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: issuer}}
	}
	return &trustv1.TrustEntry_Identifier{
		Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: issuer},
	}
}

// Fetcher reads one document over HTTP.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// HTTPFetcher returns a fetcher that does one GET with a size cap. It
// accepts http and https URLs only.
func HTTPFetcher(client *http.Client, maxBytes int64) Fetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, target string) ([]byte, error) {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			return nil, fmt.Errorf("ports: %q is not an http URL", target)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		// Nothing can act on a close fault of a response body.
		defer func() { ignored := resp.Body.Close(); _ = ignored }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ports: %s returned %d", target, resp.StatusCode)
		}
		return read(resp.Body, maxBytes)
	}
}

// HTTPPoster returns a poster that sends one JSON body with a size cap.
func HTTPPoster(client *http.Client, maxBytes int64) Poster {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, target string, body []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		// Nothing can act on a close fault of a response body.
		defer func() { ignored := resp.Body.Close(); _ = ignored }()
		if resp.StatusCode >= 400 {
			// The body of a refusal names the reason, such as an OAuth
			// error, so the caller gets it. A body that does not read
			// leaves the status alone.
			body, rerr := read(resp.Body, maxBytes)
			if rerr != nil {
				body = nil
			}
			return nil, &StatusError{URL: target, Status: resp.StatusCode, Body: body}
		}
		return read(resp.Body, maxBytes)
	}
}

// FormPoster returns a poster that sends a form body, as the
// direct_post response mode of OID4VP needs.
func FormPoster(client *http.Client, maxBytes int64) func(context.Context, string, url.Values) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, target string, form url.Values) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target,
			strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		// Nothing can act on a close fault of a response body.
		defer func() { ignored := resp.Body.Close(); _ = ignored }()
		if resp.StatusCode >= 400 {
			// The body of a refusal names the reason, such as an OAuth
			// error, so the caller gets it. A body that does not read
			// leaves the status alone.
			body, rerr := read(resp.Body, maxBytes)
			if rerr != nil {
				body = nil
			}
			return nil, &StatusError{URL: target, Status: resp.StatusCode, Body: body}
		}
		return read(resp.Body, maxBytes)
	}
}

// StatusError is an answer with an HTTP status of 400 or more. It keeps
// the body up to the size cap.
type StatusError struct {
	// URL is the address of the call.
	URL string
	// Status is the HTTP status.
	Status int
	// Body is the answer body.
	Body []byte
}

// Error returns the address and the status.
func (e *StatusError) Error() string { return fmt.Sprintf("ports: %s returned %d", e.URL, e.Status) }

// read reads a body up to the size cap.
func read(body io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

// entry is one cached document.
type entry struct {
	body    []byte
	expires time.Time
}

// Cache holds fetched documents for a time. It drops the oldest entry
// when it is full (ADR-021 decision 6).
type Cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]entry
	order   []string
}

// NewCache builds a cache. A nil now means time.Now.
func NewCache(ttl time.Duration, max int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	if max <= 0 {
		max = 1
	}
	return &Cache{ttl: ttl, max: max, now: now, entries: map[string]entry{}}
}

// Wrap returns a fetcher that answers from the cache when it can.
func (c *Cache) Wrap(next Fetcher) Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		if body, ok := c.get(url); ok {
			return body, nil
		}
		body, err := next(ctx, url)
		if err != nil {
			return nil, err
		}
		c.put(url, body)
		return body, nil
	}
}

func (c *Cache) get(url string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[url]
	if !ok || c.now().After(e.expires) {
		return nil, false
	}
	return e.body, true
}

func (c *Cache) put(url string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.entries[url]; !seen {
		c.order = append(c.order, url)
	}
	c.entries[url] = entry{body: body, expires: c.now().Add(c.ttl)}
	for len(c.order) > c.max {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
}

// toInt32 converts n to int32. A value out of range clamps to the limit.
func toInt32(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
