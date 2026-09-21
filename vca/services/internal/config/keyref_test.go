// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"errors"
	"testing"
)

const testPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"

func TestReadKeyForms(t *testing.T) {
	files := map[string][]byte{"/run/key.pem": []byte(testPEM)}
	read := func(path string) ([]byte, error) {
		data, ok := files[path]
		if !ok {
			return nil, errors.New("no such file")
		}
		return data, nil
	}
	cases := map[string]string{
		"":      "",
		testPEM: testPEM + "\n",
		"base64:" + base64.StdEncoding.EncodeToString([]byte(testPEM)):    testPEM,
		"base64:" + base64.RawURLEncoding.EncodeToString([]byte(testPEM)): testPEM,
		"file:/run/key.pem": testPEM,
		"/run/key.pem":      testPEM,
		"  /run/key.pem  ":  testPEM,
	}
	for ref, want := range cases {
		got, err := ReadKey(read, ref)
		if err != nil {
			t.Errorf("%q: %v", ref, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%q: got %q, want %q", ref, got, want)
		}
	}
	if got, err := ReadKey(read, ""); got != nil || err != nil {
		t.Errorf("empty: %v %v", got, err)
	}
}

func TestReadKeyErrors(t *testing.T) {
	read := func(string) ([]byte, error) { return nil, errors.New("no such file") }
	if _, err := ReadKey(read, "base64:***"); !errors.Is(err, ErrKeyRef) {
		t.Errorf("bad base64: %v", err)
	}
	if _, err := ReadKey(read, "/missing.pem"); err == nil {
		t.Error("a missing file passed")
	}
	if _, err := ReadKey(nil, "/missing.pem"); !errors.Is(err, ErrKeyRef) {
		t.Errorf("no reader: %v", err)
	}
}
