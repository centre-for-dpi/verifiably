// SPDX-License-Identifier: Apache-2.0

package pdfcache_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pdfcache"
)

func TestPutAndGet(t *testing.T) {
	c := pdfcache.New(0)
	c.Put("a", []byte("one"))
	c.Put("a", []byte("two"))
	if got, ok := c.Get("a"); !ok || string(got) != "two" {
		t.Errorf("get = %q %v", got, ok)
	}
	if c.Len() != 1 {
		t.Errorf("len = %d", c.Len())
	}
	if _, ok := c.Get("b"); ok {
		t.Error("an unknown reference must miss")
	}
}

func TestPutIgnoresEmptyRef(t *testing.T) {
	c := pdfcache.New(2)
	c.Put("", []byte("one"))
	if c.Len() != 0 {
		t.Errorf("len = %d", c.Len())
	}
}

func TestOldestLeavesWhenFull(t *testing.T) {
	c := pdfcache.New(2)
	for i := 0; i < 4; i++ {
		c.Put(strconv.Itoa(i), []byte{byte(i)})
	}
	if c.Len() != 2 {
		t.Fatalf("len = %d", c.Len())
	}
	if _, ok := c.Get("0"); ok {
		t.Error("the oldest entry must leave")
	}
	if _, ok := c.Get("3"); !ok {
		t.Error("the newest entry must stay")
	}
}

func TestHandler(t *testing.T) {
	c := pdfcache.New(2)
	c.Put("ref1", []byte("%PDF-1.4"))
	mux := http.NewServeMux()
	c.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, pdfcache.URL("ref1"), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/pdf" {
		t.Errorf("content type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("cache control = %q", got)
	}
	if rec.Body.String() != "%PDF-1.4" {
		t.Errorf("body = %q", rec.Body.String())
	}

	miss := httptest.NewRecorder()
	mux.ServeHTTP(miss, httptest.NewRequest(http.MethodGet, pdfcache.URL("nope"), nil))
	if miss.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", miss.Code)
	}
}

func TestConcurrentUse(t *testing.T) {
	c := pdfcache.New(8)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ref := strconv.Itoa(n % 8)
			c.Put(ref, []byte(ref))
			c.Get(ref)
			c.Len()
		}(i)
	}
	wg.Wait()
	if c.Len() != 8 {
		t.Errorf("len = %d", c.Len())
	}
}
