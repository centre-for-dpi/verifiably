// SPDX-License-Identifier: Apache-2.0

package retention_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/retention"
)

func TestParsePeriod(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30d", 30 * retention.Day},
		{"2w", 2 * retention.Week},
		{"1.5y", time.Duration(1.5 * float64(retention.Year))},
		{"90m", 90 * time.Minute},
		{"0", 0},
		{"12h", 12 * time.Hour},
	}
	for _, c := range cases {
		got, err := retention.ParsePeriod(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("%s = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParsePeriodRejectsBadValues(t *testing.T) {
	for _, in := range []string{"", "ten", "-5h", "-3d", "xd", "5q"} {
		if _, err := retention.ParsePeriod(in); !errors.Is(err, retention.ErrPeriod) {
			t.Errorf("%q: err = %v, want ErrPeriod", in, err)
		}
	}
}

func TestParse(t *testing.T) {
	p, err := retention.Parse(" default=5y , diploma=10y, visitor=30d ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Default != 5*retention.Year {
		t.Errorf("default = %v", p.Default)
	}
	if got := p.Period("diploma"); got != 10*retention.Year {
		t.Errorf("diploma = %v", got)
	}
	if got := p.Period("licence"); got != 5*retention.Year {
		t.Errorf("an unnamed schema uses the default, got %v", got)
	}
	if want := []string{"diploma", "visitor"}; !reflect.DeepEqual(p.Schemas(), want) {
		t.Errorf("schemas = %v, want %v", p.Schemas(), want)
	}
}

func TestParseEmptyKeepsEveryRecord(t *testing.T) {
	p, err := retention.Parse("  , ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Period("any") != 0 {
		t.Error("an empty setting must keep every record")
	}
	if len(p.Schemas()) != 0 {
		t.Error("an empty setting has no named schema")
	}
}

func TestParseRejectsBadRules(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"diploma", retention.ErrSyntax},
		{"=5y", retention.ErrSyntax},
		{"diploma=never", retention.ErrPeriod},
		{"diploma=1y,diploma=2y", retention.ErrDuplicate},
		{"default=1y,default=2y", retention.ErrDuplicate},
	}
	for _, c := range cases {
		if _, err := retention.Parse(c.in); !errors.Is(err, c.want) {
			t.Errorf("%q: err = %v, want %v", c.in, err, c.want)
		}
	}
}

func TestRetainUntil(t *testing.T) {
	p, err := retention.Parse("default=1y,visitor=30d,forever=0")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := p.RetainUntil("visitor", issued); !got.Equal(issued.Add(30 * retention.Day)) {
		t.Errorf("visitor = %v", got)
	}
	if got := p.RetainUntil("other", issued); !got.Equal(issued.Add(retention.Year)) {
		t.Errorf("other = %v", got)
	}
	if got := p.RetainUntil("forever", issued); !got.IsZero() {
		t.Errorf("a zero period must mean forever, got %v", got)
	}
}
