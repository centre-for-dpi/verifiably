// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ParseDotenv reads a dotenv file into a map of variable names to values.
// It accepts NAME=value lines, blank lines, and # comment lines. It also
// accepts the export prefix and single or double quoted values.
// It reports an error with the line number for any other line.
func ParseDotenv(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")
		name, value, found := strings.Cut(text, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return nil, fmt.Errorf("dotenv line %d: expected NAME=value", line)
		}
		out[name] = unquote(strings.TrimSpace(value))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dotenv: %w", err)
	}
	return out, nil
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// RenderDotenv writes the values of the resolutions as a dotenv file.
// Each variable carries its description as a comment, so the file is the
// documentation of the deployment. A value that needs a quote gets one.
// The output is deterministic: the order is the order of the settings.
func RenderDotenv(header string, list []Resolution, extra map[string]string) string {
	var b strings.Builder
	b.WriteString("# " + header + "\n")
	b.WriteString("# The vca setup command wrote this file. Edit it and run vca deploy.\n")
	for _, r := range list {
		if r.Value == "" {
			continue
		}
		b.WriteString("\n# " + r.Setting.Description + "\n")
		if r.Setting.Validation != "" {
			b.WriteString("# Rule: " + r.Setting.Validation + "\n")
		}
		b.WriteString(r.Setting.Env + "=" + quoteValue(r.Value) + "\n")
	}
	if len(extra) > 0 {
		b.WriteString("\n# Ports, addresses, and service links that vca assigned.\n")
		names := make([]string, 0, len(extra))
		for k := range extra {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			b.WriteString(k + "=" + quoteValue(extra[k]) + "\n")
		}
	}
	return b.String()
}

// quoteValue adds double quotes when the value holds a space, a quote,
// or a character a shell would read.
func quoteValue(v string) string {
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, " \t\"'$`\\#") {
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
		return `"` + r.Replace(v) + `"`
	}
	return v
}

// ApplyEnvLine returns the text of a dotenv file with one variable set
// to one value. It replaces the line that holds the variable, or it adds
// the line at the end. The function is pure, so a test needs no file.
func ApplyEnvLine(text, name, value string) string {
	lines := strings.Split(text, "\n")
	want := name + "="
	found := false
	for i, line := range lines {
		trimmed := strings.TrimPrefix(strings.TrimSpace(line), "export ")
		if !strings.HasPrefix(trimmed, want) {
			continue
		}
		lines[i] = name + "=" + quoteValue(value)
		found = true
	}
	out := strings.Join(lines, "\n")
	if found {
		return out
	}
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out + "\n# The vca images build command set this tag.\n" +
		name + "=" + quoteValue(value) + "\n"
}

// SetEnvValue sets one variable in a dotenv file on the disk. The file
// keeps mode 0600, because it holds secrets (ADR-007 decision 5).
func SetEnvValue(path, name, value string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- the path comes from the pair name
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	next := ApplyEnvLine(string(data), name, value)
	if err := os.WriteFile(path, []byte(next), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
