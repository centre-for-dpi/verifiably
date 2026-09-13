// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"sync"
	"time"
)

// PendingStore keeps started logins until the callback takes them.
type PendingStore interface {
	// Put stores one pending login under its state.
	Put(p Pending) error
	// Take removes and returns the login for state. ok is false when
	// the state is unknown or expired.
	Take(state string) (p Pending, ok bool)
}

// MemoryPending is a PendingStore in process memory. Expired entries
// are dropped on every Put.
type MemoryPending struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]Pending
}

// NewMemoryPending returns an empty store.
func NewMemoryPending(now func() time.Time) *MemoryPending {
	if now == nil {
		now = time.Now
	}
	return &MemoryPending{now: now, m: map[string]Pending{}}
}

// Put implements PendingStore.
func (s *MemoryPending) Put(p Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.now()
	for k, v := range s.m {
		if t.After(v.ExpiresAt) {
			delete(s.m, k)
		}
	}
	s.m[p.State] = p
	return nil
}

// Take implements PendingStore.
func (s *MemoryPending) Take(state string) (Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[state]
	if !ok {
		return Pending{}, false
	}
	delete(s.m, state)
	if s.now().After(p.ExpiresAt) {
		return Pending{}, false
	}
	return p, true
}

// DenyList records ended sessions until their tokens expire.
type DenyList interface {
	// Revoke marks sid as ended until exp.
	Revoke(sid string, exp time.Time) error
	// Revoked reports whether sid is on the list.
	Revoked(sid string) bool
}

// MemoryDenyList is a DenyList in process memory.
type MemoryDenyList struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]time.Time
}

// NewMemoryDenyList returns an empty list.
func NewMemoryDenyList(now func() time.Time) *MemoryDenyList {
	if now == nil {
		now = time.Now
	}
	return &MemoryDenyList{now: now, m: map[string]time.Time{}}
}

// Revoke implements DenyList. Expired entries are dropped on each call.
func (d *MemoryDenyList) Revoke(sid string, exp time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.now()
	for k, v := range d.m {
		if t.After(v) {
			delete(d.m, k)
		}
	}
	d.m[sid] = exp
	return nil
}

// Revoked implements DenyList.
func (d *MemoryDenyList) Revoked(sid string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.m[sid]
	return ok && d.now().Before(exp)
}
