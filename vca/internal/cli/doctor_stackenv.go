// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// StackEnvChecks returns one doctor check per stack of the selected
// pairs: the stack file reads deploy/<dpg>/.env, which vca setup writes
// (ADR-055 decision 1). A deploy tree from before that release has the
// .env of each pair but not the file of the stack, and compose refuses
// the configuration. One passing line covers every stack that has it.
func StackEnvChecks(deploy string, pairs []Pair) []Check {
	seen := map[configv1.Dpg]bool{}
	var out []Check
	var present []string
	for _, p := range pairs {
		if seen[p.Dpg] {
			continue
		}
		seen[p.Dpg] = true
		file := StackEnvFile(p.Dpg)
		short := ShortName(p.Dpg.String())
		_, err := os.Stat(filepath.Join(deploy, file))
		switch {
		case err == nil:
			present = append(present, short)
		case errors.Is(err, fs.ErrNotExist):
			out = append(out, Check{
				Name:   "stack env " + short,
				Detail: "deploy/" + file + " does not exist; the stack file of every " + short + " pair reads it",
				Fix:    "run vca setup for the pair again; it writes the file and keeps the secrets of the files that exist",
			})
		default:
			out = append(out, Check{Name: "stack env " + short, Detail: err.Error(), Fix: "check deploy/" + file})
		}
	}
	if len(present) > 0 {
		out = append(out, Check{Name: "stack env", OK: true, Detail: "deploy/<dpg>/.env exists for " + strings.Join(present, ", ")})
	}
	return out
}
