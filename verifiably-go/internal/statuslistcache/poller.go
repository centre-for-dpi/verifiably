package statuslistcache

import (
	"context"
	"log/slog"
	"time"

	"github.com/verifiably/verifiably-go/internal/trust"
)

// Poller warms the status list cache for every trusted issuer in the registry.
// It runs hourly so the Hub always has a recent copy available as a fallback
// when an issuer's endpoint is temporarily unreachable.
type Poller struct {
	fetcher  *Fetcher
	registry trust.Registry
	interval time.Duration
}

// NewPoller creates a Poller that uses f to fetch and r to discover issuers.
func NewPoller(f *Fetcher, r trust.Registry) *Poller {
	return &Poller{
		fetcher:  f,
		registry: r,
		interval: time.Hour,
	}
}

// Start launches the background poll loop. An initial poll runs immediately so
// the cache is warm before the first citizen reaches /verify.
func (p *Poller) Start(ctx context.Context) {
	go func() {
		p.poll(ctx)
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.poll(ctx)
			}
		}
	}()
}

func (p *Poller) poll(ctx context.Context) {
	if p.registry == nil {
		return
	}
	issuers, err := p.registry.TrustedIssuers(ctx)
	if err != nil {
		slog.Warn("status list poller: query trust registry", "err", err)
		return
	}
	refreshed := 0
	for _, issuer := range issuers {
		for _, url := range issuer.StatusListEndpoints {
			if _, err := p.fetcher.Fetch(ctx, issuer.DID, url); err != nil {
				slog.Warn("status list poller: refresh failed",
					"did", issuer.DID, "url", url, "err", err)
			} else {
				refreshed++
			}
		}
	}
	if refreshed > 0 {
		slog.Info("status list poller: cache refreshed", "endpoints", refreshed)
	}
}
