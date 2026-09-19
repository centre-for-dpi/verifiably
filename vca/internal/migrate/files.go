// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// The file names of an export. An import writes the same names under
// the state directory, so a status service reads its lists directly.
const (
	// IssuedFile holds the log of the issued-credentials service. Point
	// VCA_ISSUED_STORE_FILE at it.
	IssuedFile = "issued-credentials.json"
	// TrustFile holds the state of the trust-registry service. Point
	// VCA_TRUST_STORE_FILE at it.
	TrustFile = "trust-registry.json"
	// BitstringDir holds the state of the status-bitstring service.
	// Point VCA_STATUS_BITSTRING_STATE_DIR at it.
	BitstringDir = "status-bitstring"
	// TokenDir holds the state of the status-token service. Point
	// VCA_STATUS_TOKEN_STATE_DIR at it.
	TokenDir = "status-token"
	// ListsDir holds one file per status list inside a state directory.
	ListsDir = "lists"
)

// validKeySegment reports whether s is a legal store key segment. The
// rule is the rule of services/internal/store.
func validKeySegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// listPath returns the file of one status list inside an export.
func listPath(dir string, rec ListRecord) (string, error) {
	if !validKeySegment(rec.ID) {
		return "", fmt.Errorf("%w: the list id %q is not a store key", ErrInput, rec.ID)
	}
	return dir + "/" + ListsDir + "/" + rec.ID + ".json", nil
}

// Files returns the export as a map of relative path to content. The
// paths use "/" on every platform.
func (b Bundle) Files() (map[string][]byte, error) {
	// Every document holds strings, numbers, times, and byte slices, so
	// the encoder cannot fail.
	out := map[string][]byte{}
	issued, _ := json.Marshal(b.Issued)
	out[IssuedFile] = issued
	trust, _ := json.Marshal(b.Trust)
	out[TrustFile] = trust
	for dir, records := range map[string][]ListRecord{BitstringDir: b.Bitstring, TokenDir: b.Token} {
		for _, rec := range records {
			path, err := listPath(dir, rec)
			if err != nil {
				return nil, err
			}
			data, _ := json.Marshal(rec)
			out[path] = data
		}
	}
	return out, nil
}

// Write writes every file of the bundle under dir. It returns the paths
// it wrote, sorted. It writes nothing when a file exists and force is
// false.
func (b Bundle) Write(dir string, force bool) ([]string, error) {
	files, err := b.Files()
	if err != nil {
		return nil, err
	}
	return writeAll(dir, files, force)
}

// writeAll writes every file under dir. It checks every target first,
// so a run that stops leaves no half written export.
func writeAll(dir string, files map[string][]byte, force bool) ([]string, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if !force {
		for _, p := range paths {
			target := filepath.Join(dir, filepath.FromSlash(p))
			if _, err := os.Stat(target); err == nil {
				return nil, fmt.Errorf("%w: %s; use --force to replace it", ErrExists, target)
			}
		}
	}
	var written []string
	for _, p := range paths {
		target := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, fmt.Errorf("migrate: create %s: %w", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, files[p], 0o600); err != nil {
			return nil, fmt.Errorf("migrate: write %s: %w", target, err)
		}
		written = append(written, target)
	}
	return written, nil
}

// Read reads an export from dir and checks that every document parses.
func Read(dir string) (Bundle, error) {
	var b Bundle
	issued, err := readOptional(filepath.Join(dir, IssuedFile))
	if err != nil {
		return Bundle{}, err
	}
	if len(issued) > 0 {
		if issuedErr := json.Unmarshal(issued, &b.Issued); issuedErr != nil {
			return Bundle{}, fmt.Errorf("%w: read %s: %w", ErrInput, IssuedFile, issuedErr)
		}
	}
	trust, err := readOptional(filepath.Join(dir, TrustFile))
	if err != nil {
		return Bundle{}, err
	}
	b.Trust.Entries = map[string]TrustEntry{}
	if len(trust) > 0 {
		if trustErr := json.Unmarshal(trust, &b.Trust); trustErr != nil {
			return Bundle{}, fmt.Errorf("%w: read %s: %w", ErrInput, TrustFile, trustErr)
		}
	}
	if b.Bitstring, err = readLists(dir, BitstringDir); err != nil {
		return Bundle{}, err
	}
	if b.Token, err = readLists(dir, TokenDir); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// readLists reads every status list of one service directory.
func readLists(dir, service string) ([]ListRecord, error) {
	base := filepath.Join(dir, service, ListsDir)
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", base, err)
	}
	var out []ListRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(base, e.Name())) // #nosec G304 -- the operator names the directory
		if err != nil {
			return nil, fmt.Errorf("migrate: read %s: %w", e.Name(), err)
		}
		var rec ListRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("%w: read %s: %w", ErrInput, e.Name(), err)
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Import copies an export from the directory from into the service
// state directory into. It reads every document first, so a broken
// export writes nothing.
func Import(from, into string, force bool) ([]string, error) {
	b, err := Read(from)
	if err != nil {
		return nil, err
	}
	return b.Write(into, force)
}
