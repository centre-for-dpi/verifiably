// SPDX-License-Identifier: Apache-2.0

// Package pdfcache keeps the PDF preview documents the builder renders.
// The preview RPC returns a reference. The page then fetches the bytes
// with GET /pdf/preview/{ref} (ADR-014 decision 3).
//
// The cache holds a fixed number of documents. The oldest entry leaves
// when the cache is full. The cache is the only mutable state of the
// service, and it is per instance, never per package.
package pdfcache

import (
	"net/http"
	"sync"
)

// DefaultSize is the number of documents a cache holds.
const DefaultSize = 64

// Path is the URL prefix of the PDF preview handler.
const Path = "/pdf/preview/"

// Cache holds recent PDF documents by reference.
type Cache struct {
	mu    sync.Mutex
	size  int
	items map[string][]byte
	order []string
}

// New builds a cache for size documents. A size of zero or less means
// DefaultSize.
func New(size int) *Cache {
	if size <= 0 {
		size = DefaultSize
	}
	return &Cache{size: size, items: map[string][]byte{}}
}

// Put stores doc under ref. A reference that is already present keeps its
// place in the order.
func (c *Cache) Put(ref string, doc []byte) {
	if ref == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, has := c.items[ref]; !has {
		c.order = append(c.order, ref)
	}
	c.items[ref] = doc
	for len(c.order) > c.size {
		delete(c.items, c.order[0])
		c.order = c.order[1:]
	}
}

// Get returns the document of ref.
func (c *Cache) Get(ref string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, ok := c.items[ref]
	return doc, ok
}

// Len returns the number of documents the cache holds.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Register adds GET /pdf/preview/{ref} to mux. The handler serves the
// bytes as application/pdf. An unknown reference gives 404.
func (c *Cache) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+Path+"{ref}", func(w http.ResponseWriter, r *http.Request) {
		doc, ok := c.Get(r.PathValue("ref"))
		if !ok {
			http.Error(w, "no preview document has that reference", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `inline; filename="preview.pdf"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(doc)
	})
}

// URL returns the path that serves the document of ref.
func URL(ref string) string { return Path + ref }
