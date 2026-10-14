// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestBuildVersionNamesTheRevisionOfACheckout(t *testing.T) {
	t.Parallel()
	info := &debug.BuildInfo{GoVersion: "go1.25", Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "96a9ee23abcdef0123456789"}, {Key: "vcs.modified", Value: "true"},
	}}
	if got := BuildVersion(info, true); got != "96a9ee23abcd+dirty" {
		t.Errorf("checkout build = %q", got)
	}
	info.Main.Version = "v1.2.3"
	if got := BuildVersion(info, true); got != "v1.2.3" {
		t.Errorf("tagged build = %q", got)
	}
	if got := BuildVersion(&debug.BuildInfo{GoVersion: "go1.25", Main: debug.Module{Version: "(devel)"}}, true); got != "dev build, go1.25" {
		t.Errorf("plain build = %q", got)
	}
	if got := BuildVersion(nil, false); got != "dev build" {
		t.Errorf("no build info = %q", got)
	}
	if v := EffectiveVersion(); v == "" || v == "dev" {
		t.Errorf("EffectiveVersion = %q, want a build version", v)
	}
	if !strings.Contains(RootCommandVersion(), EffectiveVersion()) {
		t.Errorf("the root command prints %q, want %q", RootCommandVersion(), EffectiveVersion())
	}
}
