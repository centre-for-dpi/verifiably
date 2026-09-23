// SPDX-License-Identifier: Apache-2.0

// Package uikittest gives the tests of the HTML services a theme file that
// fails validation, so each service proves it stops at start on a bad look.
package uikittest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
)

// Pairing is the kit pairing the low contrast file breaks. An error of a
// service that read the file names it.
const Pairing = `pairing "primary button label"`

// pineLine is the light primary line of the embedded default.
const pineLine = `primary: "#21663F"      # pine: links, primary buttons, emphasis`

// LowContrastYAML returns the embedded default with a light primary colour
// too light for a button label.
func LowContrastYAML() ([]byte, error) {
	data := strings.Replace(string(themefile.Default()), pineLine, `primary: "#5B9E73"`, 1)
	if !strings.Contains(data, "#5B9E73") {
		return nil, errors.New("the embedded default no longer holds the pine primary line")
	}
	return []byte(data), nil
}

// LowContrastFile writes the low contrast file under a temporary directory
// of t and returns its path.
func LowContrastFile(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "theme.yaml")
	if err := writeLowContrast(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeLowContrast writes the low contrast file at path.
func writeLowContrast(path string) error {
	data, err := LowContrastYAML()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Problems lists what is wrong with the error of a service that read the
// file at path: nothing when the error names the path and the pairing.
func Problems(err error, path string) []string {
	if err == nil {
		return []string{"the service started with a low contrast theme file"}
	}
	var out []string
	if !strings.HasPrefix(err.Error(), "theme file "+path+": ") {
		out = append(out, "the error does not start with the file path: "+err.Error())
	}
	if !strings.Contains(err.Error(), Pairing) {
		out = append(out, "the error does not name the pairing: "+err.Error())
	}
	return out
}

// AssertBadThemeError fails t with every problem of Problems.
func AssertBadThemeError(t testing.TB, err error, path string) {
	t.Helper()
	for _, p := range Problems(err, path) {
		t.Error(p)
	}
}
