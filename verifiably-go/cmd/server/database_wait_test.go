package main

import (
	"testing"
	"time"
)

func TestDatabaseWait(t *testing.T) {
	cases := map[string]time.Duration{
		"":      60 * time.Second,
		"90s":   90 * time.Second,
		"2m":    2 * time.Minute,
		"45":    45 * time.Second,
		"0":     0,
		"later": 60 * time.Second,
		"-5s":   60 * time.Second,
	}
	for in, want := range cases {
		t.Setenv("VERIFIABLY_DATABASE_WAIT", in)
		if got := databaseWait(); got != want {
			t.Errorf("VERIFIABLY_DATABASE_WAIT=%q: got %s, want %s", in, got, want)
		}
	}
}
