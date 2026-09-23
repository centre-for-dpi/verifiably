// SPDX-License-Identifier: Apache-2.0

// Package uikit loads the look of a deployment for a service that serves
// HTML (ADR-032). Every such service calls Load once at start. It reads
// the theme file named by VCA_THEME_FILE, validates it, builds the asset
// handler and the component kit from the same values, and fails with the
// file path and every problem when the file is wrong. A service that gets
// an error exits before it listens.
package uikit

import (
	"errors"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/internal/themefile"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// ThemeFileEnv is the variable that names the theme file. Every service
// reads the same variable, so it carries no service prefix. An empty
// value selects the embedded default.
const ThemeFileEnv = themefile.EnvVar

// Load reads ThemeFileEnv through lookup, for example os.Getenv, and
// returns the asset handler for ui.Prefix, the component kit with the
// brand of the file, and the kit config. An error starts with
// "theme file <path>:" and names every problem.
func Load(lookup func(string) string) (http.Handler, *components.Kit, ui.Config, error) {
	return LoadFile(lookup(ThemeFileEnv))
}

// LoadFile is Load for one path. An empty path loads the embedded default.
func LoadFile(path string) (http.Handler, *components.Kit, ui.Config, error) {
	f, err := themefile.Load(path)
	if err != nil {
		return nil, nil, ui.Config{}, err
	}
	cfg := f.Config()
	assets, kit, err := build(cfg)
	if err != nil {
		return nil, nil, ui.Config{}, err
	}
	return assets, kit, cfg, nil
}

// build makes the asset handler and the kit from one config. The two share
// the brand, so the logo the page shows is the logo the handler serves.
func build(cfg ui.Config) (http.Handler, *components.Kit, error) {
	assets, assetsErr := ui.AssetsFor(cfg)
	kit, kitErr := components.New(components.WithBrand(cfg.Brand))
	if err := errors.Join(assetsErr, kitErr); err != nil {
		return nil, nil, err
	}
	return assets, kit, nil
}
