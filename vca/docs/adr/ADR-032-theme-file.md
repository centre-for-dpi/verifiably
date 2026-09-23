## ADR-032: Theme and brand from one declarative file
- Status: Proposed
- Owner: CDPI Architects
- Scope: Colours, fonts, wordmark, logo, radii, spacing, role accents of every page.
- Supersedes: ADR-027 decision 4 in part, ADR-027 decision 6 in part, and the wording of ADR-027 consequence 4.
  - Decision 4: a theme is one YAML file, not one Go package.
  - Decision 6: two families and a generic monospace stack replace the four font roles.
- Decision:
  1. One file, `deploy/vca/theme.yaml`, holds the look. Services read the path from `VCA_THEME_FILE`. An empty value selects the embedded default.
  2. The kit keeps the pairings and their minimum ratios. The file sets colours only. A file that fails a pairing stops the service at start with the pairing name and the ratio.
  3. The font pack has two families: Cinzel for headings and Google Sans Flex for body text. Code and numbers use a generic monospace stack. The binary embeds only these two files.
  4. The file can set the wordmark, a logo, radii, a spacing scale, and one accent per role. The logo is a data URI of at most 64 KiB.
  5. The YAML reader lives outside the kit, in `vca/internal/themefile`. The kit stays standard library only.
  6. `vca theme check` validates a file. `vca theme apply` validates it and restarts the services that draw pages.
- Consequences:
  1. A country rebrands without a build.
  2. No file can make a page fail AA.
  3. The font files shrink from four to two.
  4. The Go theme package stays the single source of the pairings.
  5. The kit keeps its no-dependency rule.
  6. A rebrand is three steps.
