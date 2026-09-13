// SPDX-License-Identifier: Apache-2.0

package csvsrc

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func TestParseHeader(t *testing.T) {
	in := "\xef\xbb\xbffullName, dateOfBirth,,fullName\nGrace Atieno,1988-03-14,x\nDavid,1979-11-02,y,z,extra\n"
	tb, err := Parse(strings.NewReader(in), Options{HasHeader: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tb.Fields, []string{"fullName", "dateOfBirth", "column_3", "fullName_2", "column_5"}) {
		t.Fatalf("%v", tb.Fields)
	}
	if tb.Total != 2 || tb.Rows[0]["fullName"] != "Grace Atieno" || tb.Rows[0]["column_5"] != "" || tb.Rows[1]["column_5"] != "extra" {
		t.Fatalf("%+v", tb.Rows)
	}
}

func TestParseNoHeaderAndDelimiter(t *testing.T) {
	tb, err := Parse(strings.NewReader("a;b\nc;d;e\n"), Options{Delimiter: ";"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tb.Fields, []string{"column_1", "column_2", "column_3"}) || tb.Rows[0]["column_3"] != "" || tb.Rows[1]["column_3"] != "e" {
		t.Fatalf("%+v", tb)
	}
	tb, err = Parse(strings.NewReader("holder\n"), Options{HasHeader: true})
	if err != nil || len(tb.Rows) != 0 || tb.Fields[0] != "holder" {
		t.Fatalf("%+v %v", tb, err)
	}
	tb, err = Parse(strings.NewReader(""), Options{HasHeader: true})
	if err != nil || len(tb.Rows) != 0 || len(tb.Fields) != 0 {
		t.Fatalf("%+v %v", tb, err)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		o    Options
		want error
	}{
		{"bad quoting", "holder,note\nAisha,\"unterminated\nDavid,ok\n", Options{HasHeader: true}, ErrBadCSV},
		{"too large", "abcdefgh", Options{MaxBytes: 4}, ErrTooLarge},
		{"not utf8", "a\xffb", Options{}, ErrNotUTF8},
		{"bad delimiter", "a", Options{Delimiter: ";;"}, ErrBadOptions},
		{"quote delimiter", "a", Options{Delimiter: "\""}, ErrBadOptions},
		{"bad encoding", "a", Options{Encoding: "latin1"}, ErrBadOptions},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.in), tc.o); !errors.Is(err, tc.want) {
				t.Fatalf("err %v want %v", err, tc.want)
			}
		})
	}
	if _, err := Parse(iotest.ErrReader(errors.New("boom")), Options{Encoding: "UTF8"}); err == nil || errors.Is(err, ErrBadOptions) {
		t.Fatalf("read error %v", err)
	}
}
