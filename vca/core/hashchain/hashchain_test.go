// SPDX-License-Identifier: Apache-2.0

package hashchain

import (
	"errors"
	"strings"
	"testing"
)

type body struct {
	Z string `json:"z"`
	A int    `json:"a"`
}

func TestCanonicalSortsKeys(t *testing.T) {
	got, err := Canonical(body{Z: "x", A: 1})
	if err != nil || string(got) != `{"a":1,"z":"x"}` {
		t.Fatalf("got %s err %v", got, err)
	}
	got, err = Canonical(map[string]any{"b": []any{map[string]any{"y": 1.5, "x": "s"}}, "a": nil})
	if err != nil || string(got) != `{"a":null,"b":[{"x":"s","y":1.5}]}` {
		t.Fatalf("got %s err %v", got, err)
	}
	if _, err := Canonical(make(chan int)); err == nil {
		t.Fatal("chan must fail")
	}
}

func TestAppendHeadVerify(t *testing.T) {
	c := New()
	if _, ok := c.Head(); ok || c.Len() != 0 {
		t.Fatal("empty head")
	}
	c, e0, err := c.Append(body{Z: "first"})
	if err != nil || e0.Index != 0 || e0.PreviousHash != "" || e0.Hash != HashOf("", e0.Body) {
		t.Fatalf("e0 %+v err %v", e0, err)
	}
	before := c
	c, e1, err := c.Append(map[string]string{"k": "second"})
	if err != nil || e1.Index != 1 || e1.PreviousHash != e0.Hash {
		t.Fatalf("e1 %+v err %v", e1, err)
	}
	if before.Len() != 1 || c.Len() != 2 {
		t.Fatal("append must not change the receiver")
	}
	head, ok := c.Head()
	if !ok || head.Hash != e1.Hash {
		t.Fatal("head")
	}
	if err := Verify(c.Entries()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Append(make(chan int)); err == nil {
		t.Fatal("bad body must fail")
	}
	loaded, err := Load(c.Entries())
	if err != nil || loaded.Len() != 2 {
		t.Fatalf("load %v", err)
	}
	entries := c.Entries()
	entries[0] = e1
	if _, err := Load(entries); err == nil {
		t.Fatal("load must verify")
	}
}

func TestVerifyFailures(t *testing.T) {
	c := New()
	c, _, _ = c.Append("a")
	c, _, _ = c.Append("b")
	c, _, _ = c.Append("c")
	good := c.Entries()

	tamperedBody := c.Entries()
	tamperedBody[1].Body = []byte(`"x"`)
	brokenLink := c.Entries()
	brokenLink[2].PreviousHash = "00"
	brokenLink[2].Hash = HashOf("00", brokenLink[2].Body)
	badIndex := c.Entries()
	badIndex[1].Index = 5
	removed := []Entry{good[0], good[2]}

	tests := []struct {
		name    string
		entries []Entry
		want    error
		index   int64
	}{
		{"empty", nil, nil, 0},
		{"good", good, nil, 0},
		{"tampered body", tamperedBody, ErrBadHash, 1},
		{"broken link", brokenLink, ErrBrokenLink, 2},
		{"bad index", badIndex, ErrBrokenLink, 1},
		{"removed entry", removed, ErrBrokenLink, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(tc.entries)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil {
				return
			}
			var ve *VerifyError
			if !errors.As(err, &ve) || ve.Index != tc.index || !strings.Contains(ve.Error(), "index") {
				t.Fatalf("verify error %v", err)
			}
		})
	}
}
