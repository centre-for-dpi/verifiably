# vca UI kit

`vca/ui` is the shared user interface kit for every portal page. It gives
each service one theme, one font pack, and one asset handler. It also gives
a set of `html/template` components that meet WCAG 2.2 Level AA.

This document covers ADR-027 decisions 3 to 9.

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
| `ui` | `Assets` handler, embedded templates and static files, `HTMXVersion`, `Prefix`. |
| `ui/theme` | `Theme` type, `DefaultLight`, `DefaultDark`, `Validate`, `CSS`, `ContrastRatio`. |
| `ui/fonts` | `Pack` type with three roles, `Default`, `Shipped`, `Validate`, `CSS`, `Files`. |
| `ui/components` | `Kit` with one template and one data struct per component. |
| `ui/a11ytest` | `AssertPage`, `AssertFragment`, and `Check` for tests. |
| `ui/example` | Demo page that uses every component. `cmd/demo` serves it. |

## How to use the kit

1. Build the asset handler once at start. It checks the themes and the font
   pack and generates `/static/vca.css`.
2. Parse the templates once with `components.New`.
3. Mount the assets under `ui.Prefix`, which is `/static/`.
4. In each page handler, compose the body with `Kit.HTML` and `components.Join`.
5. Call `Kit.RenderPage`. It writes the full layout, or only the page partial
   for an htmx request, and sets the `HX-Title` header.

```go
assets, err := ui.Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
if err != nil {
	return err
}
kit, err := components.New()
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
| `/static/vca.css` | Font faces, light tokens, dark tokens, then the base stylesheet. |
| `/static/htmx.min.js` | htmx, version in `ui.HTMXVersion`. |
| `/static/fonts/<file>.woff2` | One file per font role that has a file: the heading and the body font. |

## How to add a theme

A theme is one Go value of type `theme.Theme`. The tokens are the single
source of truth. `theme.CSS` writes them as CSS custom properties, so CSS
and Go can never disagree on a colour.

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

A font pack is one Go value of type `fonts.Pack` with three roles.

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
| `layout` | `Page` | Full document with head, skip link, header, nav, theme toggle, `main`, toast region, footer. | `Title` |
| `page` | `Page` | The `h1` and `Content`, for htmx requests. | `Title` |
| `card` | `Card` | `section` labelled by its `h2`. | `ID` |
| `field` | `Field` | `label` plus `input`, `textarea`, or `select`, with hint and error text. | `ID`, `Label` |
| `table` | `Table` | Table with `caption`, `th scope="col"`, and an empty row text. | `Caption`, `Columns` |
| `badge` | `Badge` | Status label. The text carries the meaning. | `Status`, `Text` |
| `toast` | `Toast` | One message for the `aria-live` region. `OOB` adds an htmx out-of-band swap. | `Level`, `Text` |
| `dialog` | `Dialog` | Native `dialog` labelled by its `h2`, with a `method="dialog"` form. | `ID`, `Title` |
| `qr` | `QR` | QR image with `alt`, `width`, and `height`. | `Src`, `Alt` |
| `json` | `JSON` | `details` disclosure with a labelled `pre` region of indented JSON. | `ID`, `Summary` |
| `button` | `Button` | `button`, or `a.btn` when `Href` has a value. | `Text` or `AriaLabel` |

### Data structs

`Page`: `Lang` (default `en`), `Title`, `Heading` (default `Title`),
`Label`, `Lead`, `Description`, `Nav`, `Content`, `Toasts`, `Footer`, `Text`.
The page header shows `Label` in the accent colour above the `h1`, and
`Lead` under it.

`Nav`: `Label` (default `Main`), `Brand`, `Links`. `Link`: `Href`, `Text`,
`Current`.

`Text`: `SkipLink`, `ThemeToggle`, `ThemeSystem`, `ThemeLight`, `ThemeDark`.
A message catalogue fills these for each language.

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

`ui`, `ui/theme`, `ui/fonts`, and `ui/a11ytest` hold 100 percent statement
coverage. `ui/components` holds at least 95 percent. `make cover` enforces
the floor of ADR-004. The e2e suite runs axe against every page as a second
gate.

## Reference

- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [WAI-ARIA 1.2](https://www.w3.org/TR/wai-aria-1.2/)
- [html/template](https://pkg.go.dev/html/template)
- [htmx](https://htmx.org/)
- [CSS Fonts Level 4, font-display](https://www.w3.org/TR/css-fonts-4/#font-display-desc)
- Third-party notices: `ui/NOTICE`. The architecture derives from
  [adamndegwa](https://github.com/adammwaniki/adamndegwa) by Adam Ndegwa,
  Apache-2.0.
