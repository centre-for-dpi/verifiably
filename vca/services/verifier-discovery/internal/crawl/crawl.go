// SPDX-License-Identifier: Apache-2.0

// Package crawl reads the trusted issuers of the trust registry and
// fetches the metadata and the schemas of each one (ADR-022 decision 1).
//
// The crawler calls the trust registry through the injected Connect
// client, so a test injects a fake. It fetches through the injected
// fetcher, which guards against server side request forgery and caches
// with a time to live and an entity tag.
package crawl

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/fetch"
)

// PageSize is the page size of the trust list call.
const PageSize = 100

// MaxPages bounds the pages the crawler reads from the trust registry.
const MaxPages = 50

// Writer stores the crawled issuers.
type Writer interface {
	PutIssuer(ctx context.Context, issuer catalog.Issuer) error
	GetIssuer(ctx context.Context, url string) (catalog.Issuer, error)
}

// Getter fetches one document.
type Getter interface {
	Get(ctx context.Context, url string) (fetch.Doc, error)
	Forget(url string)
}

// Options configure a crawler.
type Options struct {
	// Trust calls the trust registry. Nil turns the crawler off.
	Trust trustv1connect.TrustServiceClient
	// Fetch reads the issuer documents.
	Fetch Getter
	// Store keeps the crawled issuers.
	Store Writer
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Crawler reads issuers and stores their catalogue.
type Crawler struct {
	opts Options
}

// New builds a crawler.
func New(opts Options) (*Crawler, error) {
	if opts.Fetch == nil {
		return nil, errors.New("crawl: a fetcher is required")
	}
	if opts.Store == nil {
		return nil, errors.New("crawl: a store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Crawler{opts: opts}, nil
}

// Enabled reports whether the crawler has a trust registry client.
func (c *Crawler) Enabled() bool { return c.opts.Trust != nil }

// Result counts one crawl.
type Result struct {
	// Crawled is the number of issuers the crawl read.
	Crawled int
	// Failed maps an issuer URL to the error of its crawl.
	Failed map[string]string
	// At is the time of the crawl.
	At time.Time
}

// Run crawls the issuers. An empty list crawls every trusted issuer of
// the trust registry.
func (c *Crawler) Run(ctx context.Context, only []string) (Result, error) {
	res := Result{Failed: map[string]string{}, At: c.opts.Now()}
	entries, err := c.issuers(ctx, only)
	if err != nil {
		return Result{}, err
	}
	for _, e := range entries {
		if err := c.one(ctx, e); err != nil {
			res.Failed[e.Endpoint] = err.Error()
			continue
		}
		res.Crawled++
	}
	return res, nil
}

// Entry is one issuer the crawler reads.
type Entry struct {
	// Endpoint is the base URL of the issuer deployment.
	Endpoint string
	// DID is the issuer identifier of the trust list.
	DID string
	// DisplayName is the name of the trust list entry.
	DisplayName string
	// Trust is the trust outcome name.
	Trust string
}

// issuers returns the entries to crawl.
func (c *Crawler) issuers(ctx context.Context, only []string) ([]Entry, error) {
	if c.opts.Trust == nil {
		return nil, errors.New("crawl: no trust registry is configured")
	}
	entries, err := c.trusted(ctx)
	if err != nil {
		return nil, err
	}
	if len(only) == 0 {
		return entries, nil
	}
	wanted := map[string]bool{}
	for _, url := range only {
		wanted[strings.TrimRight(url, "/")] = true
	}
	out := make([]Entry, 0, len(only))
	for _, e := range entries {
		if wanted[strings.TrimRight(e.Endpoint, "/")] {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("crawl: the trust list holds none of the %d issuers of the request", len(only))
	}
	return out, nil
}

// trusted reads the issuer entries of the trust registry in pages.
func (c *Crawler) trusted(ctx context.Context) ([]Entry, error) {
	var out []Entry
	token := ""
	for page := 0; page < MaxPages; page++ {
		req := &trustv1.ListEntriesRequest{
			Page:   &commonv1.Pagination{PageSize: PageSize, PageToken: token},
			Role:   commonv1.Role_ROLE_ISSUER,
			Status: trustv1.Status_STATUS_ACTIVE,
		}
		resp, err := c.opts.Trust.ListEntries(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, fmt.Errorf("crawl: read the trust list: %w", err)
		}
		for _, entry := range resp.Msg.GetEntries() {
			if entry.GetServiceEndpoint() == "" {
				continue
			}
			out = append(out, Entry{
				Endpoint:    strings.TrimRight(entry.GetServiceEndpoint(), "/"),
				DID:         entry.GetIdentifier().GetDid(),
				DisplayName: entry.GetDisplayName(),
				Trust:       c.lookup(ctx, entry),
			})
		}
		token = resp.Msg.GetPage().GetNextPageToken()
		if token == "" {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out, nil
}

// lookup asks the trust registry for the outcome of one entry.
func (c *Crawler) lookup(ctx context.Context, entry *trustv1.TrustEntry) string {
	req := &trustv1.TrustLookupRequest{Identifier: entry.GetIdentifier(), Role: commonv1.Role_ROLE_ISSUER}
	resp, err := c.opts.Trust.TrustLookup(ctx, connect.NewRequest(req))
	if err != nil {
		return catalog.TrustUnavailable
	}
	return catalog.TrustName(resp.Msg.GetOutcome())
}

// one crawls a single issuer and stores the result. It keeps the last
// good catalogue when the fetch fails, so the pages stay useful.
func (c *Crawler) one(ctx context.Context, e Entry) error {
	metadataURL := catalog.URLFor(e.Endpoint, catalog.MetadataPath)
	c.opts.Fetch.Forget(metadataURL)
	doc, err := c.opts.Fetch.Get(ctx, metadataURL)
	if err != nil {
		return c.fail(ctx, e, err)
	}
	issuerURL, display, types, err := catalog.ReadMetadata(doc.Body)
	if err != nil {
		return c.fail(ctx, e, err)
	}
	if issuerURL == "" {
		issuerURL = e.Endpoint
	}
	schemas, schemaErr := c.schemas(ctx, e.Endpoint)
	record := catalog.Issuer{
		CredentialIssuer: issuerURL,
		DID:              e.DID,
		DisplayName:      displayName(e, display),
		Trust:            e.Trust,
		Types:            catalog.Merge(types, schemas),
		CrawledAt:        c.opts.Now(),
	}
	if schemaErr != nil {
		record.LastError = schemaErr.Error()
	}
	return c.opts.Store.PutIssuer(ctx, record)
}

// schemas reads the published schema list of an issuer. A missing list
// is not an error for the metadata, so the caller keeps the types.
func (c *Crawler) schemas(ctx context.Context, endpoint string) (map[string]catalog.CredentialType, error) {
	url := catalog.URLFor(endpoint, catalog.SchemasPath)
	c.opts.Fetch.Forget(url)
	doc, err := c.opts.Fetch.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("crawl: read %s: %w", url, err)
	}
	schemas, err := catalog.ReadSchemas(doc.Body)
	if err != nil {
		return nil, err
	}
	return schemas, nil
}

// fail stores the error of a crawl against the last good record.
func (c *Crawler) fail(ctx context.Context, e Entry, cause error) error {
	record, err := c.opts.Store.GetIssuer(ctx, e.Endpoint)
	if err != nil {
		record = catalog.Issuer{CredentialIssuer: e.Endpoint, DID: e.DID, DisplayName: e.DisplayName}
	}
	record.Trust = e.Trust
	record.LastError = cause.Error()
	if putErr := c.opts.Store.PutIssuer(ctx, record); putErr != nil {
		return putErr
	}
	return cause
}

// displayName returns the name of an issuer from the trust list or the
// metadata.
func displayName(e Entry, display []catalog.Display) string {
	if e.DisplayName != "" {
		return e.DisplayName
	}
	if len(display) > 0 && display[0].Name != "" {
		return display[0].Name
	}
	return e.Endpoint
}
