// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Base64Prefix marks a key reference that carries the PEM itself, as
// standard base64, in the variable. The vca setup command writes the
// generated signing key this way, because a file on the host belongs to
// the operator and the container user cannot read it.
const Base64Prefix = "base64:"

// FilePrefix marks a key reference that names a file.
const FilePrefix = "file:"

// ErrKeyRef reports a key reference that no form matches.
var ErrKeyRef = errors.New("config: bad key reference")

// ReadKey returns the bytes behind a key reference. The reference is one
// of: the PEM text itself; "base64:" and the PEM as base64; "file:" and
// a path; or a bare path. read opens a path, for example os.ReadFile.
// An empty reference returns nil and no error, so a caller keeps its
// "no key configured" branch.
func ReadKey(read func(string) ([]byte, error), ref string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	switch {
	case ref == "":
		return nil, nil
	case strings.HasPrefix(ref, "-----BEGIN"):
		return []byte(ref + "\n"), nil
	case strings.HasPrefix(ref, Base64Prefix):
		raw, err := decodeBase64(strings.TrimPrefix(ref, Base64Prefix))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyRef, err)
		}
		return raw, nil
	case strings.HasPrefix(ref, FilePrefix):
		return readPath(read, strings.TrimPrefix(ref, FilePrefix))
	default:
		return readPath(read, ref)
	}
}

// readPath reads a file and names it in the error.
func readPath(read func(string) ([]byte, error), path string) ([]byte, error) {
	if read == nil {
		return nil, fmt.Errorf("%w: no file reader for %s", ErrKeyRef, path)
	}
	data, err := read(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	return data, nil
}

// decodeBase64 accepts standard and URL safe base64, with or without
// padding.
func decodeBase64(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(text); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("not base64")
}
