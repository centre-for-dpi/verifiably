# vca UI kit

`vca/ui` is the shared user interface kit for every portal page. It gives
each service one theme, one font pack, and one asset handler. It also gives
a set of `html/template` components that meet WCAG 2.2 Level AA.

This document covers ADR-027 decisions 3 to 9 and ADR-032.

## Rules

- The kit uses the Go standard library only. It has no third-party Go module.
- All assets ship inside the binary. No page loads a file from a CDN.
- Every page has one `h1`, a `lang` attribute, a skip link, a labelled `nav`,
  and a `main` landmark with `id="page"`.
- A page has no page-local CSS. All style comes from `/static/vca.css`.
- `hx-*` attributes appear only inside kit templates or through the `Attrs`
  whitelist of a component.
- A theme that fails a contrast check cannot start a service.

## Packages

| Package | Purpose |
|---|---|
| `ui` | `Config`, `DefaultConfig`, `AssetsFor` and `Assets` handlers, `StylesheetFor`, embedded templates and static files, `HTMXVersion`, `Prefix`. |
| `ui/theme` | `Theme` type, `DefaultLight`, `DefaultDark`, `DefaultPairings`, `Required`, `Validate`, `CSS`, `ContrastRatio`. |
| `ui/brand` | `Brand` type with the wordmark, logo, radii, spacing, and role accents. `Default`, `Validate`, `CSS`, `Roles`. |
| `ui/fonts` | `Pack` type with three roles, `Default`, `Shipped`, `Validate`, `CSS`, `Files`. |
| `ui/components` | `Kit` with one template and one data struct per component. `WithBrand` sets the brand of the layout. |
| `ui/a11ytest` | `AssertPage`, `AssertFragment`, and `Check` for tests. |
| `ui/example` | Demo page that uses every component. `cmd/demo` serves it. |

## How to use the kit

1. Build the asset handler once at start with `ui.AssetsFor(cfg)`. It checks
   the themes, the font pack, and the brand, and generates `/static/vca.css`.
   `ui.DefaultConfig` returns the shipped look.
2. Parse the templates once with `components.New(components.WithBrand(cfg.Brand))`.
   Use the same brand as the assets, so the logo path resolves.
3. Mount the assets under `ui.Prefix`, which is `/static/`.
4. In each page handler, compose the body with `Kit.HTML` and `components.Join`.
5. Call `Kit.RenderPage`. It writes the full layout, or only the page partial
   for an htmx request, and sets the `HX-Title` header.

```go
cfg := ui.DefaultConfig()
assets, err := ui.AssetsFor(cfg)
if err != nil {
	return err
}
kit, err := components.New(components.WithBrand(cfg.Brand))
if err != nil {
	return err
}
mux := http.NewServeMux()
mux.Handle("GET "+ui.Prefix, assets)
mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
	card, err := kit.HTML("card", components.Card{ID: "verdict", Title: "Result", Text: "Valid."})
	if err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	page := components.Page{
		Title:   "Verify",
		Nav:     components.Nav{Links: []components.Link{{Href: "/", Text: "Home", Current: true}}},
		Content: components.Join(card),
	}
	if err := kit.RenderPage(w, r, page); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
})
```

Run the demo and open `http://localhost:8080/`:

```sh
cd vca && go run ./ui/example/cmd/demo
```

The asset handler answers `GET` and `HEAD` only. Every response carries an
`ETag`, `Cache-Control: public, max-age=31536000, immutable`, and
`X-Content-Type-Options: nosniff`. A request with a matching `If-None-Match`
gets `304 Not Modified`.

| Path | Content |
|---|---|
| `/static/vca.css` | Font faces, light tokens, dark tokens, brand properties, then the base stylesheet. |
| `/static/htmx.min.js` | htmx, version in `ui.HTMXVersion`. |
| `/static/fonts/<file>.woff2` | One file per font role that has a file: the heading and the body font. |
| `/static/logo.svg`, `.png`, or `.webp` | The brand logo, when the brand has one. |

The logo response carries `Content-Security-Policy: default-src 'none';
style-src 'unsafe-inline'; sandbox`. Pages show the logo only through an
`img` element, so an SVG logo cannot run script.

## Change the look after deployment

One file holds the look of every page: `deploy/vca/theme.yaml`
(ADR-032 decision 1). A deployment rebrands by editing it, with no build
and no Go code. Every service that draws pages reads the file at
start through `VCA_THEME_FILE`. An empty variable selects the embedded
default, which is the tracked file byte for byte.

A national rebrand takes three steps:

1. Edit `deploy/vca/theme.yaml`, or a copy named by `VCA_THEME_HOST_FILE`:
   the colours, the wordmark, the logo, the radii, the role accents.
2. Run `vca theme check`. It names every pairing below AA with its ratio
   and every bad value with its YAML path.
3. Run `vca theme apply`. It checks again and restarts only the services
   that draw pages. On Kubernetes run
   `helm upgrade vca deploy/vca/helm/vca --set-file global.theme.file=theme.yaml`.

`vca theme print-default` prints the shipped file. Copy it to
`deploy/theme.local.yaml`, which git ignores, and export
`VCA_THEME_HOST_FILE=../theme.local.yaml` to keep the tree clean.

| Key | Value | Rule |
|---|---|---|
| `version` | `1` | The one version this reader accepts. |
| `name` | A short name. | Not empty. It names the themes in the stylesheet. |
| `wordmark.text` | The name in the header and the footer. | 1 to 32 characters. No `<`, `>`, `&`, or `"`. |
| `wordmark.emphasis` | An optional second part in the primary colour. | 0 to 32 characters, same characters. |
| `logo.data_uri` | An optional `data:image/svg+xml;base64,`, `data:image/png;base64,` or `data:image/webp;base64,` URI. | 64 KiB or less after decoding. |
| `logo.alt` | The text a screen reader says for the logo. | Required with `logo.data_uri`. |
| `fonts.heading.family`, `fonts.body.family` | `Cinzel` or `Google Sans Flex`. | The binary embeds these two families only. |
| `fonts.heading.fallback`, `fonts.body.fallback`, `fonts.mono.fallback` | The fallback stack. | Letters, digits, spaces, commas, hyphens, and single quotes only. The mono stack ends in `monospace`. |
| `colors.light.<token>`, `colors.dark.<token>` | The fifteen tokens of the token table below. | Every token present, six digit hex. Every kit pairing at its minimum ratio. |
| `radii.small`, `radii.medium`, `radii.pill` | `0` or a number of `rem`. | `small` and `medium` are 1rem or less. |
| `spacing` | Seven `rem` values. | Strictly increasing. |
| `roles.<role>.light`, `roles.<role>.dark` | An optional accent per role: `admin`, `issuer`, `holder`, `verifier`. | 4.5:1 on the paper of its mode. Empty inherits `accent`. |

The kit owns the pairings and their minimum ratios
(`theme.DefaultPairings`). The file sets colours only, so no file can make
a page fail AA (ADR-032 decision 2). A file with a problem stops the
service before it listens, and the log holds the same lines that
`vca theme check` prints. Each line starts with `theme file <path>:` and
the YAML path of the value:

| Problem | Example |
|---|---|
| Unknown key | `line 12: field colours not found in type themefile.File` |
| Wrong version | `version: 2 is not supported; use 1` |
| Missing token | `colors.dark.invert-fg: missing` |
| Pairing below its minimum | `colors.light: pairing "primary button label": contrast 3.10:1 is below 4.5:1 (#F0EFE9 on #5B9E73)` |
| Family not shipped | `fonts.heading.family: "Papyrus" is not shipped; use Cinzel or Google Sans Flex` |
| Bad fallback stack | `fonts.mono.fallback: must end with monospace` |
| Long wordmark | `wordmark.text: 40 characters, the limit is 32` |
| Logo without text | `logo.alt: required when logo.data_uri is set` |
| Radius in pixels | `radii.small: use rem, got 3px` |
| Spacing out of order | `spacing[3]: 0.5rem is not larger than spacing[2] 0.75rem` |
| Role accent too faint | `roles.issuer.dark: contrast 2.91:1 is below 4.5:1 on #000000` |

The reader lives in `vca/internal/themefile`, outside the kit, so the kit
stays standard library only (ADR-032 decision 5). Services load the file
through `services/internal/uikit`, which builds the asset handler and
the component kit from the same values. Compose mounts the file at
`/etc/vca/theme.yaml`, and the umbrella chart holds it in a ConfigMap.
See `deploy.md` for both.

## Brand

`brand.Brand` holds the brand data. `brand.CSS` writes it as custom
properties. `brand.Validate` checks it against the two themes.

| Field | Rule | CSS |
|---|---|---|
| `Wordmark` | 1 to 32 characters. No `<`, `>`, `&`, or `"`. | None. The layout draws it in the header and the footer. |
| `Emphasis` | 0 to 32 characters, same characters. | None. The layout draws it in an `em` in the primary colour. |
| `Logo` | A base64 data URI of an SVG, PNG, or WebP image, 64 KiB or less. A logo needs an `Alt` text. | None. The layout draws it in an `img` with its `alt`. |
| `Radii` | `Small` and `Medium` are `0` or 1rem or less. `Pill` is `0` or a `rem` value. | `--radius-s`, `--radius-m`, `--radius-pill` |
| `Spacing` | Seven `rem` values that increase. | `--space-1` to `--space-7` |
| `RoleAccents` | One `Accent` per role: `admin`, `issuer`, `holder`, `verifier`. A set colour needs 4.5:1 on the paper of its mode. | `--role-accent`, one rule per `data-role` value |

`--role-accent` is the theme accent until a role sets its own colour. The
bar under the wordmark, the page header label, and the navigation underline
use it.

## How to add a theme

A deployment sets its colours in the theme file above. This section is
for work on the kit itself. A theme is one Go value of type
`theme.Theme`. The tokens are the single source of truth. `theme.CSS`
writes them as CSS custom properties, so CSS and Go can never disagree on
a colour.

1. Copy `theme.DefaultLight` into your package. Give the theme a new name.
2. Set the fifteen tokens of the table below. Use six digit hex colours.
3. Keep the pairings. Each pairing names a foreground token, a background
   token, and the minimum ratio the stylesheet needs.
4. Do the same for a dark theme and set `Dark: true`.
5. Pass both themes to `ui.Assets`. `Validate` runs first. It reports every
   pairing below its minimum and every missing token.
6. Add a unit test that calls `theme.Validate` on your theme. A theme that
   fails AA then fails the build.

| Token | Default light | Used for |
|---|---|---|
| `ink` | ink `#0B0B09` | Text. |
| `paper` | paper `#F0EFE9` | The page canvas. |
| `primary` | pine `#21663F` | Links, primary buttons, and the emphasis of the wordmark. |
| `accent` | gold `#7A632A` | Labels, the bar under the wordmark, rules, and the focus ring. |
| `spark` | brass `#F0D053` | A rare highlight on a dark surface. |
| `secondary` | charcoal `#3B3F39` | Secondary text and navigation labels. |
| `muted` | stone `#6A6A65` | Meta text and input borders. |
| `line` | mist `#D9DAD6` | Hairlines. |
| `invert-bg` | pine `#21663F` | The surface of a tile or link card on hover and focus. |
| `invert-fg` | paper `#F0EFE9` | Text on that surface. |
| `invert-muted` | mist `#D9DAD6` | Secondary text on that surface. |
| `invert-accent` | brass `#F0D053` | Labels, rules, and arrows on that surface. |
| `warn` | `#7A4B00` | Warning state. |
| `bad` | `#A61B1B` | Error state. |
| `ok` | `#1E6B3B` | Success state. |

The default palette comes from the adamndegwa brand. The dark theme uses a
black canvas. There, the inverted surface is moss, and all text on it is
black. `theme.DefaultPairings` lists every pairing with its minimum ratio.

A light theme renders under `:root`. A dark theme renders under
`[data-theme="dark"]` and again under `prefers-color-scheme: dark` for
documents with no stamp. The stamp `light` forces light, `dark` forces dark,
and no stamp follows the system.

The layout applies the stored choice before first paint. A `localStorage`
call that throws falls back to the system preference. The theme toggle in the
header cycles through system, light, and dark.

## How to swap a font pack

A deployment picks its families in the theme file above. This section is
for work on the kit itself. A font pack is one Go value of type
`fonts.Pack` with three roles.

| Role | CSS variable | Used for |
|---|---|---|
| `Heading` | `--font-heading` | Page titles, section headings, and the brand. |
| `Body` | `--font-body` | Body copy, labels, navigation, badges, buttons, and numbers. |
| `Mono` | `--font-mono` | Code. |

The default pack uses Cinzel for `Heading` and Google Sans Flex for
`Body`. The kit ships these two files only. `Shipped` returns them by
family name. `Mono` is a generic monospace stack with no file, so the
browser uses a monospace font of the system.

1. Put one `.woff2` file each for `Heading` and `Body` under
   `ui/static/fonts/`. Use lower case file names. Keep the sum of the
   files below 1 MB.
2. Add the licence file of each font next to it and list it in `ui/NOTICE`.
3. Copy `fonts.Default` into your package. Set `Family`, `Fallback`, `File`,
   and `Weight` for `Heading` and `Body`. Set only `Fallback` for `Mono`.
4. Pass the pack to `ui.Assets`. `Validate` rejects an empty role and a
   family with quotes. It rejects a file name that is not `.woff2` and a
   fallback with CSS syntax in it.
5. `Validate` rejects a `Mono` role with a family, a file, or a weight.
   The `Mono` fallback must end in `monospace`.

`fonts.CSS` writes one `@font-face` per role with a file, with
`font-display: swap`. The browser shows the fallback stack until the file
arrives.

## Components

Each component is one template name and one data struct in `ui/components`.
`Kit.Render` fills defaults and rejects data that cannot render an accessible
component. `components.Names` lists every template.

| Name | Struct | Renders | Required fields |
|---|---|---|---|
| `layout` | `Page` | Full document: head, skip link, header with wordmark, nav, theme toggle, `main`, toasts, and a footer with the monogram. | `Title` |
| `page` | `Page` | The page header with `Label`, the `h1`, and `Lead`, then `Content`. htmx requests get only this part. | `Title` |
| `card` | `Card` | `section` labelled by its `h2`. | `ID` |
| `field` | `Field` | `label` plus `input`, `textarea`, or `select`, with hint and error text. | `ID`, `Label` |
| `table` | `Table` | Table with `caption`, `th scope="col"`, and an empty row text. | `Caption`, `Columns` |
| `badge` | `Badge` | Status label. The text carries the meaning. | `Status`, `Text` |
| `toast` | `Toast` | One message for the `aria-live` region. `OOB` adds an htmx out-of-band swap. | `Level`, `Text` |
| `dialog` | `Dialog` | Native `dialog` labelled by its `h2`, with a `method="dialog"` form. | `ID`, `Title` |
| `qr` | `QR` | QR image with `alt`, `width`, and `height`. | `Src`, `Alt` |
| `json` | `JSON` | `details` disclosure with a labelled `pre` region of indented JSON. | `ID`, `Summary` |
| `button` | `Button` | `button`, or `a.btn` when `Href` has a value. | `Text` or `AriaLabel` |
| `hero` | `Hero` | Two column opening block with the `h1`, a tracked label, a lead, actions, and an aside. Set `Page.Hero`; it replaces the page header. | `Title` |
| `tiles` | `Tiles` | Grid of link tiles that invert on hover and focus. | `Items` with `Title` and `Href` |
| `steps` | `Steps` | Ordered step cards. Each state carries a word: `Done`, `Current`, `Locked`. | `Items` with `Title` |
| `checklist` | `Checklist` | `section` labelled by its `h2`, with items that say `Done` or `To do`. | `ID`, `Title`, `Items` |
| `stat` | `Stat` | One summary card: label, value, sentence, link. Put several in `div.stats` for a grid. | `Label`, `Value` |
| `stepper` | `Stepper` | Progress of a multi step form. The current step carries `aria-current="step"`. | `Label`, `Steps` (two or more), `Current` |
| `choice` | `Choice` | `fieldset` with a `legend` and radio cards, or checkbox cards with `Multiple`. | `ID`, `Legend`, `Options` |
| `code` | `Code` | `figure` with a `figcaption` and a `pre` region named by it. | `ID`, `Label`, `Text` |
| `empty` | `Empty` | Empty state with a title, a sentence, and the one action that fills it. | `Title`, `Action` |
| `block` | `Block` | One section of a long page: `section` labelled by its `h2`, a lead, a meta line, a body. `Attrs` takes the htmx attributes, so a block can refresh itself. | `ID`, `Title` |
| `figure` | `Figure` | Inline SVG diagram as an image named by its title, with a hidden caption as the text equivalent. The body uses `fig-node`, `fig-edge`, `fig-label`, and `fig-text`. | `ID`, `Title`, `Caption`, `ViewBox`, `SVG` |
| `stacks` | `Stacks` | One `article` per stack: name, version, components with links, and one row per role with its state as a word. | `Items` with `ID`, `Name`, `Roles` |
| `cta` | `CTA` | Call to action band: `section` labelled by its `h2`, a sentence, and one button. | `ID`, `Title`, `Action` |
| `note` | `Note` | Small aside of a hero: a tracked label, a sentence, and the accent line. Set it as `Hero.Aside`. | `Text` |
| `tabs` | `Tabs` | A labelled nav landmark with a row of links between the views of one page group. The current view carries `aria-current="page"`. Each link loads a full page. | `Label`, two or more `Links` |
| `signin` | `SignIn` | The sign in chooser of a role. Left: role, `h1`, lead and back link. Right: provider buttons with the realm in the monospace stack, a callout, and an extra block. Then a rule, the register actions, and a note. Set `Page.SignIn`; it replaces the page header. | `Title` |

### Data structs

`Page`: `Lang` (default `en`), `Title`, `Heading` (default `Title`),
`Label`, `Lead`, `Actions`, `Description`, `Nav`, `Content`, `Toasts`,
`Footer`, `Text`. The page header shows `Label` in the accent colour above
the `h1` and `Lead` under it. `Actions` holds buttons from `Kit.HTML` in a
row under the lead.

`Nav`: `Label` (default `Main`), `Brand`, `Links`. `Link`: `Href`, `Text`,
`Current`. The wordmark links to `Brand.Href` (default `/`). `Brand.Text`
names the service beside the wordmark. A link to a path of the site
swaps the main region through htmx. An anchor and an external address
open as plain links, and an external one carries `rel="noopener"`.

`Tile`: `Num`, `Title`, `Text`, `Figure`, `Meta`, `Href`. `Figure` takes
the output of the `figure` component and sits between the text and the
meta line.

`Text`: `SkipLink`, `ThemeToggle`, `ThemeSystem`, `ThemeLight`, `ThemeDark`,
`SignOut`, `Menu`, `StackNav`, `SideNav`, `Starting`. A message catalogue
fills these for each language.

The English catalogue lives in `internal/msg`. `msg.T(key, args...)`
returns the sentence of a key with `{1}`, `{2}` and so on replaced, and
`msg.Keys` lists every key. Its test holds every value to the STE rules:
sentences of 20 words or fewer, active voice, no dash, no banned word.
A key that ends in `.label` is a short label of at most four words.
Every new sentence of a page goes into the catalogue, not into a template
or a handler.

### Portal shell

`Page.Shell` frames a portal page. A nil shell renders a plain page. The
shell adds a role chip beside the wordmark, a stack switcher, a user menu,
and a side navigation. The body carries `data-role`. The role accent of the
brand then colours the chip, the side navigation, and the header bar.

`Shell`: `Role` (one of `brand.Roles`), `RoleLabel` (default the role with
a capital), `Stacks`, `User`, `Sections`.

`StackLink`: `Name`, `Href`, `Current`, `State`. An empty state is a live
stack with a link. The state `starting` renders the name as text with a
badge. The switcher appears only with two or more stacks. The current stack
carries `aria-current="true"`.

`User`: `Name`, `SignOut` (the form action), `CSRF` (the synchronizer
token), `CSRFField` (default `csrf_token`). An empty name hides the menu.
The menu is a `details` disclosure with a POST form, so it works without
a script.

`NavSection`: `Label`, `Links`. A label renders above its list and names
it through `aria-labelledby`. The current link carries
`aria-current="page"`. A local link swaps the main region through htmx.
An external link, for example an identity console, opens as a plain link
with `rel="noopener"`. Under 56.25rem the side navigation folds into a
`details` disclosure. On a wide screen the stylesheet hides the summary and
the layout script keeps the disclosure open.

The pages of each role come from `internal/rolenav`. The package lists
the sections and the pages of a role in the order of the side navigation.
A page can carry a feature gate. `rolenav.Nav` builds the `NavSection`
list of the shell. It marks the page that the request path falls under.
A test in `internal/cli` checks every path of the table against the
route table of the pair. The navigation and the reverse proxy cannot
drift (ADR-044 decision 5).

The three nav landmarks carry different labels: `Main` for the top links,
`Stack` for the switcher, and `Portal` for the side navigation. `a11ytest`
fails a page where two nav landmarks share a label.

`Card`: `ID`, `Title`, `Text`, `Body`, `Footer`.

`Field`: `ID`, `Name` (default `ID`), `Label`, `Type` (default `text`),
`Value`, `Hint`, `Error`, `Required`, `Options`, `Attrs`, `Autocomplete`.
`Option`: `Value`, `Text`, `Selected`.

`Table`: `ID`, `Caption`, `Columns`, `Rows`, `Empty` (default `No rows`).
`Row` is a slice of `Cell`. `Cell`: `Text` or `HTML`.

`Badge`: `Status`, `Text`. `Toast`: `ID`, `Level`, `Text`, `OOB`.
`Status` and `Level` accept `ok`, `warn`, `bad`, `info`.

`Dialog`: `ID`, `Title`, `Text`, `Body`, `Actions`, `CloseText` (default
`Close`), `Open`.

`QR`: `Src` (a `data:image/` URL or a path), `Alt`, `Size` (default 256).

`JSON`: `ID`, `Summary`, `Data`, `Open`.

`Button`: `Text`, `Type` (`button` or `submit`), `Variant` (`primary`,
`secondary`, `danger`, `ghost`), `Href`, `Name`, `Value`, `Controls`,
`Expanded`, `Opens`, `Disabled`, `AriaLabel`, `Attrs`.

`Attrs` accepts only names on the whitelist in `components.SafeAttr`: the
`hx-*` attributes and common input attributes. Any other name is an error.

`Hero`: `Label`, `Title`, `Emphasis` (second line in the primary colour),
`Lead`, `Actions`, `Aside`. `Page.Hero` renders it in place of the page
header, so the hero carries the one `h1`. Container query units size
the title from its column. A long word shrinks and never breaks in the
middle.

`SignIn`: `Role`, `Title`, `Lead`, `Back`, `Label`, `Providers`, `Empty`,
`CalloutLabel`, `Callout`, `Extra`, `Or` (default `or`), `Register`, `Note`.
`SignInProvider`: `Text`, `Href`, `Meta`. The first provider renders as the
primary button, the rest as secondary buttons. `Page.SignIn` renders the
block in place of the page header, so it carries the one `h1`.

`Tiles`: `Items`. `Tile`: `Num`, `Title`, `Text`, `Meta`, `Href`.

`Steps`: `Items`, `Text`. `Step`: `Title`, `Text`, `State` (empty, `done`,
`current`, `locked`), `Href`, `LinkText` (default `Open`). `StepText`:
`Done`, `Current`, `Locked`. At most one step is current.

`Checklist`: `ID`, `Title`, `Note`, `Items`, `Text`. `Check`: `Text`,
`Detail`, `Done`. `CheckText`: `Done`, `Todo`.

`Stat`: `Label`, `Value`, `Text`, `Href`, `LinkText` (default `Open`).

`Stepper`: `Label`, `Steps`, `Current` (from 1), `Text`. Steps before the
current one carry a hidden `Done` for screen readers.

`Choice`: `ID`, `Name` (default `ID`), `Legend`, `Hint`, `Options`,
`Multiple`. `ChoiceOption`: `Value`, `Title`, `Text`, `Meta`, `Checked`,
`Disabled`. Every input has an id `<ID>-<n>` and its own `label`.

`Code`: `ID`, `Label`, `Text`. `Empty`: `Title`, `Text`, `Action`.

`Tabs`: `Label`, `Links`. Each link needs `Href` and `Text`. At most one
link is current. The label must differ from the other nav landmarks of
the page.

### Rendering

- `Kit.Render(w, name, data)` writes one component.
- `Kit.HTML(name, data)` returns one component as trusted HTML for composition.
- `components.Join(parts...)` joins trusted fragments.
- `Kit.RenderPage(w, r, page)` writes the layout. For a request with
  `HX-Request: true` it writes only the `page` partial and sets `HX-Title`.
  A history restore request gets the full layout.

### Progressive enhancement

Every page works without JavaScript. Forms post, links navigate, `details`
opens, and a `dialog` with `Open` shows at once. With JavaScript, htmx swaps
the `main` region, the theme toggle appears, disclosure buttons toggle their
region, and `Opens` buttons call `showModal`.

## Accessibility guarantees

The table maps each guarantee to a WCAG 2.2 success criterion. `a11ytest`
checks the structural rules in unit tests. The theme and font tests check the
colour and motion rules.

| Guarantee | WCAG 2.2 | Checked by |
|---|---|---|
| Every `img` has `alt`. `QR` rejects empty alt text. | [1.1.1 Non-text Content](https://www.w3.org/TR/WCAG22/#non-text-content) | `a11ytest`, `components` |
| Tables have a `caption` and column headers. Cards and dialogs have a heading. | [1.3.1 Info and Relationships](https://www.w3.org/TR/WCAG22/#info-and-relationships) | `components` tests |
| Fields link hint and error text with `aria-describedby`. | [1.3.1 Info and Relationships](https://www.w3.org/TR/WCAG22/#info-and-relationships) | `components` tests |
| Fields accept `autocomplete` for personal data. | [1.3.5 Identify Input Purpose](https://www.w3.org/TR/WCAG22/#identify-input-purpose) | `components` tests |
| Badge and toast text carry the meaning, not only the colour. | [1.4.1 Use of Color](https://www.w3.org/TR/WCAG22/#use-of-color) | `components` rejects empty text |
| Every text pairing has a ratio of at least 4.5:1. | [1.4.3 Contrast (Minimum)](https://www.w3.org/TR/WCAG22/#contrast-minimum) | `theme.Validate` |
| Font sizes use `rem`, never `px`. Text scales to 200 percent. | [1.4.4 Resize Text](https://www.w3.org/TR/WCAG22/#resize-text) | `ui` stylesheet test |
| Layout wraps at 320 CSS pixels. Only tables scroll sideways. | [1.4.10 Reflow](https://www.w3.org/TR/WCAG22/#reflow) | `ui` stylesheet test |
| Borders and focus rings have a ratio of at least 3:1. | [1.4.11 Non-text Contrast](https://www.w3.org/TR/WCAG22/#non-text-contrast) | `theme.Validate` |
| Toasts sit in a region with `aria-live="polite"`. | [4.1.3 Status Messages](https://www.w3.org/TR/WCAG22/#status-messages) | `ui` stylesheet test, `components` tests |
| All controls are native elements. Keyboard use needs no script. | [2.1.1 Keyboard](https://www.w3.org/TR/WCAG22/#keyboard) | `components` tests |
| The dialog closes with Escape and with the close button. | [2.1.2 No Keyboard Trap](https://www.w3.org/TR/WCAG22/#no-keyboard-trap) | native `dialog` |
| The stylesheet has a `prefers-reduced-motion` block. | [2.3.3 Animation from Interactions](https://www.w3.org/TR/WCAG22/#animation-from-interactions) | `ui` stylesheet test |
| Every page has a skip link to `#page`. | [2.4.1 Bypass Blocks](https://www.w3.org/TR/WCAG22/#bypass-blocks) | `a11ytest` |
| Every page has a `title`. htmx requests get `HX-Title`. | [2.4.2 Page Titled](https://www.w3.org/TR/WCAG22/#page-titled) | `components` tests |
| Focus moves to `main` after an htmx swap. | [2.4.3 Focus Order](https://www.w3.org/TR/WCAG22/#focus-order) | layout script |
| Every page has exactly one `h1`. Cards and dialogs use `h2`. | [2.4.6 Headings and Labels](https://www.w3.org/TR/WCAG22/#headings-and-labels) | `a11ytest` |
| `:focus-visible` draws a 3 pixel ring. No rule sets `outline: none`. | [2.4.7 Focus Visible](https://www.w3.org/TR/WCAG22/#focus-visible) | `ui` stylesheet test |
| The focus ring uses an offset, so no element hides it. | [2.4.11 Focus Not Obscured (Minimum)](https://www.w3.org/TR/WCAG22/#focus-not-obscured-minimum) | `ui` stylesheet test |
| Every button and link has a minimum size of 24 by 24 CSS pixels. | [2.5.8 Target Size (Minimum)](https://www.w3.org/TR/WCAG22/#target-size-minimum) | `ui` stylesheet test |
| `html lang` follows the active catalogue. Default is `en`. | [3.1.1 Language of Page](https://www.w3.org/TR/WCAG22/#language-of-page) | `a11ytest` |
| The nav landmark has the same label on every page. | [3.2.3 Consistent Navigation](https://www.w3.org/TR/WCAG22/#consistent-navigation) | `a11ytest` |
| Every nav landmark on a page has a unique label. | [1.3.6 Identify Purpose](https://www.w3.org/TR/WCAG22/#identify-purpose) | `a11ytest` |
| Every field has a `label`. Required fields carry `required`. | [3.3.2 Labels or Instructions](https://www.w3.org/TR/WCAG22/#labels-or-instructions) | `a11ytest` |
| An error sets `aria-invalid` and links the error text. | [3.3.1 Error Identification](https://www.w3.org/TR/WCAG22/#error-identification) | `components` tests |
| Icon buttons need `aria-label`. Disclosure buttons carry `aria-expanded`. | [4.1.2 Name, Role, Value](https://www.w3.org/TR/WCAG22/#name-role-value) | `a11ytest` |
| No link has `href="#"`. | [2.4.4 Link Purpose (In Context)](https://www.w3.org/TR/WCAG22/#link-purpose-in-context) | `a11ytest` |

### Testing a page

Call `a11ytest.AssertPage` on the rendered HTML of every page. Call
`a11ytest.AssertFragment` on a partial. `Check` returns the list of broken
rules for use outside tests.

```go
rec := httptest.NewRecorder()
handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
a11ytest.AssertPage(t, rec.Body.String())
```

## Coverage

`ui`, `ui/theme`, `ui/fonts`, `ui/brand`, and `ui/a11ytest` hold 100 percent statement
coverage. `ui/components` holds at least 95 percent. `make cover` enforces
the floor of ADR-004. The e2e suite runs axe against every page as a second
gate.

## Reference

- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [WAI-ARIA 1.2](https://www.w3.org/TR/wai-aria-1.2/)
- [html/template](https://pkg.go.dev/html/template)
- [htmx](https://htmx.org/)
- [CSS Fonts Level 4, font-display](https://www.w3.org/TR/css-fonts-4/#font-display-desc)
- ADR-032: the theme file, its rules, and the theme commands.
- Third-party notices: `ui/NOTICE`. The architecture derives from
  [adamndegwa](https://github.com/adammwaniki/adamndegwa) by Adam Ndegwa,
  Apache-2.0.
