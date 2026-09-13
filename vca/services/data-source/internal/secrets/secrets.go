// SPDX-License-Identifier: Apache-2.0

// Package secrets resolves secret references at use time
// (ADR-015 decision 2). A source record holds a Ref. The service reads the
// value from the environment or from a mounted file only when it opens
// the source. No response and no log carries a value.
package secrets

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Store names where a secret lives.
type Store string

// Stores the package knows.
const (
	Env  Store = "env"
	File Store = "file"
	KMS  Store = "kms"
)

// Errors the package returns.
var (
	ErrBadRef      = errors.New("secrets: the reference is not valid")
	ErrNotFound    = errors.New("secrets: the secret is empty or missing")
	ErrUnsupported = errors.New("secrets: the store is not supported in this deployment")
)

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Ref points at a secret.
type Ref struct {
	Store Store  `json:"store"`
	Name  string `json:"name"`
}

// IsZero reports whether the reference is empty.
func (r Ref) IsZero() bool { return r.Store == "" && r.Name == "" }

// Validate checks the shape of the reference without resolving it.
func (r Ref) Validate() error {
	switch r.Store {
	case Env:
		if !envName.MatchString(r.Name) {
			return fmt.Errorf("%w: env name %q", ErrBadRef, r.Name)
		}
	case File:
		if r.Name == "" || r.Name != filepath.Base(r.Name) || strings.HasPrefix(r.Name, ".") {
			return fmt.Errorf("%w: file name %q must be a plain file name", ErrBadRef, r.Name)
		}
	case KMS:
		if r.Name == "" {
			return fmt.Errorf("%w: kms name is empty", ErrBadRef)
		}
	default:
		return fmt.Errorf("%w: store %q", ErrBadRef, r.Store)
	}
	return nil
}

// Resolver reads secret values.
type Resolver struct {
	// Getenv reads an environment variable, for example os.Getenv.
	Getenv func(string) string
	// ReadFile reads a file, for example os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Dir is the directory of file secrets. A file name joins it.
	Dir string
}

// Resolve returns the value of ref. The value is trimmed of a trailing
// new line.
func (r Resolver) Resolve(ref Ref) (string, error) {
	if err := ref.Validate(); err != nil {
		return "", err
	}
	switch ref.Store {
	case Env:
		if r.Getenv == nil {
			return "", fmt.Errorf("%w: env", ErrUnsupported)
		}
		v := r.Getenv(ref.Name)
		if v == "" {
			return "", fmt.Errorf("%w: env %s", ErrNotFound, ref.Name)
		}
		return v, nil
	case File:
		if r.ReadFile == nil || r.Dir == "" {
			return "", fmt.Errorf("%w: file", ErrUnsupported)
		}
		data, err := r.ReadFile(filepath.Join(r.Dir, ref.Name))
		if err != nil {
			return "", fmt.Errorf("%w: file %s", ErrNotFound, ref.Name)
		}
		v := strings.TrimRight(string(data), "\r\n")
		if v == "" {
			return "", fmt.Errorf("%w: file %s", ErrNotFound, ref.Name)
		}
		return v, nil
	}
	return "", fmt.Errorf("%w: kms", ErrUnsupported)
}
