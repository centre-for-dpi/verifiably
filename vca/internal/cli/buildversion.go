// SPDX-License-Identifier: Apache-2.0

package cli

import "runtime/debug"

// BuildVersion returns the version of a binary that no release build
// stamped: the module version of a go install from a tag, else the
// source revision of a go install from a checkout, else a plain mark.
// It lets vca --version tell a stale binary from the checkout, which is
// the first question when deploy refuses the compose file.
func BuildVersion(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil {
		return "dev build"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	revision, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if revision == "" {
		return "dev build, " + info.GoVersion
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if dirty {
		revision += "+dirty"
	}
	return revision
}

// EffectiveVersion is Version when a release build set it, else the
// build version of the binary.
func EffectiveVersion() string {
	if Version != "" && Version != "dev" {
		return Version
	}
	return BuildVersion(debug.ReadBuildInfo())
}

// RootCommandVersion is what vca --version prints.
func RootCommandVersion() string { return EffectiveVersion() }
