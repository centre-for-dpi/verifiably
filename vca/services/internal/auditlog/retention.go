// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// RetentionKey is the store key of the retention setting. It sits
// outside Prefix, so a query never reads it as a record.
const RetentionKey = "auditmeta/retention"

// MaxRetentionDays caps the retention at ten years.
const MaxRetentionDays = 3650

// PruneEvery is the least time between two prunes that an append starts.
const PruneEvery = time.Hour

// ErrRetention reports a retention outside 0 to MaxRetentionDays.
var ErrRetention = fmt.Errorf("auditlog: the retention must be 0 to %d days", MaxRetentionDays)

// Open returns the log of a service. An empty dir keeps the events in
// memory. Otherwise the log keeps one file per event under dir.
func Open(dir string, now func() time.Time) (*Log, error) {
	if dir == "" {
		return New(store.Memory(), now)
	}
	if strings.ContainsRune(dir, 0) {
		return nil, fmt.Errorf("auditlog: the directory %q is not valid", dir)
	}
	kv, err := store.File(dir)
	if err != nil {
		return nil, err
	}
	return New(kv, now)
}

// Retention returns the number of days the log keeps. Zero means the
// log keeps every event.
func (l *Log) Retention(ctx context.Context) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retention(ctx)
}

// retention reads the setting once and keeps it. The caller holds mu.
func (l *Log) retention(ctx context.Context) (int, error) {
	if l.known {
		return l.days, nil
	}
	raw, err := l.kv.Get(ctx, RetentionKey)
	if errors.Is(err, store.ErrNotFound) {
		l.days, l.known = 0, true
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("auditlog: %w", err)
	}
	days, err := strconv.Atoi(string(raw))
	if err != nil || days < 0 || days > MaxRetentionDays {
		return 0, fmt.Errorf("auditlog: the stored retention %q is not valid", raw)
	}
	l.days, l.known = days, true
	return days, nil
}

// SetRetention stores the number of days the log keeps and removes the
// older events at once. Zero keeps every event. It returns the number
// of events it removed.
func (l *Log) SetRetention(ctx context.Context, days int) (int, error) {
	if days < 0 || days > MaxRetentionDays {
		return 0, ErrRetention
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.kv.Put(ctx, RetentionKey, []byte(strconv.Itoa(days))); err != nil {
		return 0, fmt.Errorf("auditlog: %w", err)
	}
	l.days, l.known = days, true
	if days == 0 {
		return 0, nil
	}
	now := l.now()
	l.lastPrune = now
	return l.Prune(ctx, now.AddDate(0, 0, -days))
}

// Prune removes every event older than before. It reads the time from
// the record id, so it never opens a record. It returns the number of
// events it removed.
func (l *Log) Prune(ctx context.Context, before time.Time) (int, error) {
	keys, err := l.kv.List(ctx, Prefix)
	if err != nil {
		return 0, fmt.Errorf("auditlog: %w", err)
	}
	cutoff := before.UTC().UnixMilli()
	removed := 0
	for _, k := range keys {
		ms, ok := idTime(strings.TrimPrefix(k, Prefix))
		if !ok || ms >= cutoff {
			continue
		}
		if err := l.kv.Delete(ctx, k); err != nil {
			return removed, fmt.Errorf("auditlog: %w", err)
		}
		removed++
	}
	return removed, nil
}

// pruneDue prunes when the log has a retention and the last prune is
// older than PruneEvery. A fault waits for the next append.
func (l *Log) pruneDue(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.lastPrune.IsZero() && now.Sub(l.lastPrune) < PruneEvery {
		return
	}
	days, err := l.retention(ctx)
	if err != nil || days == 0 {
		return
	}
	l.lastPrune = now
	_, ignored := l.Prune(ctx, now.AddDate(0, 0, -days))
	_ = ignored
}

// idTime reads the time in milliseconds at the start of a record id:
// its first 15 digits, in the older form and the newer one.
func idTime(id string) (int64, bool) {
	head, _, ok := strings.Cut(id, "-")
	if !ok || len(head) < msDigits {
		return 0, false
	}
	ms, err := strconv.ParseInt(head[:msDigits], 10, 64)
	return ms, err == nil
}

// msDigits is the width of the millisecond part of a record id.
const msDigits = 15
