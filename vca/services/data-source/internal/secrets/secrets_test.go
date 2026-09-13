// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		ref  Ref
		want error
	}{
		{Ref{Env, "API_TOKEN"}, nil},
		{Ref{Env, "lower"}, ErrBadRef},
		{Ref{Env, ""}, ErrBadRef},
		{Ref{File, "token"}, nil},
		{Ref{File, "../etc/passwd"}, ErrBadRef},
		{Ref{File, "a/b"}, ErrBadRef},
		{Ref{File, ".hidden"}, ErrBadRef},
		{Ref{File, ""}, ErrBadRef},
		{Ref{KMS, "projects/x/keys/y"}, nil},
		{Ref{KMS, ""}, ErrBadRef},
		{Ref{"vault", "x"}, ErrBadRef},
	}
	for _, tc := range tests {
		if err := tc.ref.Validate(); !errors.Is(err, tc.want) {
			t.Errorf("%+v: err %v want %v", tc.ref, err, tc.want)
		}
	}
	if !(Ref{}).IsZero() || (Ref{Env, "X"}).IsZero() {
		t.Fatal("zero")
	}
}

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dsn"), []byte("postgres://u:p@h/db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"TOKEN": "t0k"}
	r := Resolver{Getenv: func(k string) string { return env[k] }, ReadFile: os.ReadFile, Dir: dir}
	tests := []struct {
		name string
		r    Resolver
		ref  Ref
		want string
		err  error
	}{
		{"env", r, Ref{Env, "TOKEN"}, "t0k", nil},
		{"env missing", r, Ref{Env, "NOPE"}, "", ErrNotFound},
		{"env unsupported", Resolver{}, Ref{Env, "TOKEN"}, "", ErrUnsupported},
		{"file", r, Ref{File, "dsn"}, "postgres://u:p@h/db", nil},
		{"file missing", r, Ref{File, "nope"}, "", ErrNotFound},
		{"file empty", r, Ref{File, "empty"}, "", ErrNotFound},
		{"file unsupported", Resolver{ReadFile: os.ReadFile}, Ref{File, "dsn"}, "", ErrUnsupported},
		{"kms", r, Ref{KMS, "k"}, "", ErrUnsupported},
		{"bad ref", r, Ref{Env, "bad name"}, "", ErrBadRef},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.r.Resolve(tc.ref)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("got %q err %v", got, err)
			}
		})
	}
}
