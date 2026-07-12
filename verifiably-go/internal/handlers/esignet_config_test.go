package handlers

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// frame builds one Docker multiplexed stream frame.
func frame(stream byte, payload string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:8], uint32(len(payload)))
	return append(h, []byte(payload)...)
}

func TestDemuxDockerStream(t *testing.T) {
	t.Run("framed stdout+stderr", func(t *testing.T) {
		var b bytes.Buffer
		b.Write(frame(1, `["mosip:idp:acr:static-code"]`))
		b.Write(frame(2, "NOTICE: something"))
		b.Write(frame(1, "\n"))
		out, errs := demuxDockerStream(b.Bytes())
		if out != `["mosip:idp:acr:static-code"]`+"\n" {
			t.Fatalf("stdout=%q", out)
		}
		if errs != "NOTICE: something" {
			t.Fatalf("stderr=%q", errs)
		}
	})

	t.Run("raw (non-framed) returned as stdout", func(t *testing.T) {
		raw := []byte("plain psql output no header\n")
		out, errs := demuxDockerStream(raw)
		if out != string(raw) || errs != "" {
			t.Fatalf("out=%q errs=%q", out, errs)
		}
	})

	t.Run("truncated frame is clamped, not panicking", func(t *testing.T) {
		h := make([]byte, 8)
		h[0] = 1
		binary.BigEndian.PutUint32(h[4:8], 100) // claims 100 bytes but only 3 follow
		b := append(h, []byte("abc")...)
		out, _ := demuxDockerStream(b)
		if out != "abc" {
			t.Fatalf("out=%q, want abc", out)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		out, errs := demuxDockerStream(nil)
		if out != "" || errs != "" {
			t.Fatalf("out=%q errs=%q", out, errs)
		}
	})
}

func TestEsignetBackedACRs(t *testing.T) {
	t.Run("default is PIN+OTP+Wallet", func(t *testing.T) {
		t.Setenv("ESIGNET_BACKED_ACRS", "")
		b := esignetBackedACRs()
		for _, want := range []string{"mosip:idp:acr:static-code", "mosip:idp:acr:generated-code", "mosip:idp:acr:linked-wallet"} {
			if !b[want] {
				t.Fatalf("default missing %s", want)
			}
		}
		if b["mosip:idp:acr:biometrics"] {
			t.Fatalf("biometrics should not be backed by default")
		}
	})
	t.Run("env override widens the set (space or comma)", func(t *testing.T) {
		t.Setenv("ESIGNET_BACKED_ACRS", "mosip:idp:acr:static-code, mosip:idp:acr:biometrics")
		b := esignetBackedACRs()
		if !b["mosip:idp:acr:static-code"] || !b["mosip:idp:acr:biometrics"] {
			t.Fatalf("override not honoured: %v", b)
		}
		if b["mosip:idp:acr:generated-code"] {
			t.Fatalf("override should replace, not extend defaults")
		}
	})
}

func TestSortACRsByDisplayAndNames(t *testing.T) {
	in := []string{"mosip:idp:acr:linked-wallet", "mosip:idp:acr:static-code", "mosip:idp:acr:generated-code"}
	got := sortACRsByDisplay(in)
	want := []string{"mosip:idp:acr:static-code", "mosip:idp:acr:generated-code", "mosip:idp:acr:linked-wallet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sort got %v want %v", got, want)
	}
	// original slice not mutated
	if in[0] != "mosip:idp:acr:linked-wallet" {
		t.Fatalf("input slice was mutated: %v", in)
	}
	names := acrNames(want)
	if !reflect.DeepEqual(names, []string{"PIN", "OTP", "Wallet"}) {
		t.Fatalf("names got %v", names)
	}
	// unknown acr falls back to the raw value
	if n := acrNames([]string{"mosip:idp:acr:unknown"}); n[0] != "mosip:idp:acr:unknown" {
		t.Fatalf("unknown name got %v", n)
	}
}
