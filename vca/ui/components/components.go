// SPDX-License-Identifier: Apache-2.0

// Package components renders the vca UI kit partials with html/template.
//
// Each component is one named template and one data struct. Render writes
// one component. RenderPage writes a full page, or only the page partial when
// the request comes from htmx.
package components

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/brand"
)

// Names lists every template a Kit can render.
var Names = []string{"layout", "page", "card", "field", "table", "badge", "toast", "dialog", "qr", "json", "button",
	"hero", "tiles", "steps", "checklist", "stat", "stepper", "choice", "code", "empty",
	"block", "figure", "stacks", "cta", "note", "signin", "tabs", "fieldset"}

// safeAttrNames is the whitelist for the safeAttr template function.
// Only these attribute names can be added through an Attrs map.
var safeAttrNames = map[string]bool{
	"hx-get": true, "hx-post": true, "hx-put": true, "hx-patch": true, "hx-delete": true,
	"hx-target": true, "hx-swap": true, "hx-trigger": true, "hx-push-url": true,
	"hx-confirm": true, "hx-include": true, "hx-indicator": true, "hx-select": true,
	"hx-vals": true, "hx-boost": true,
	"autocomplete": true, "inputmode": true, "placeholder": true, "pattern": true,
	"minlength": true, "maxlength": true, "min": true, "max": true, "step": true,
	"rows": true, "readonly": true, "disabled": true, "formaction": true, "form": true,
	"enterkeyhint": true, "spellcheck": true, "accept": true,
}

var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// SafeAttr renders one attribute when its name is on the whitelist.
// The value is HTML-escaped. Unknown names render nothing.
// It is the only template function that returns pre-approved markup.
func SafeAttr(name, value string) template.HTMLAttr {
	if !safeAttrNames[name] {
		return ""
	}
	//nolint:gosec // G203: the name is on a whitelist and the value is escaped.
	return template.HTMLAttr(name + `="` + html.EscapeString(value) + `"`)
}

// Kit holds the parsed templates and the brand mark the layout draws.
type Kit struct {
	tpl  *template.Template
	mark Mark
}

// Mark is the brand mark of the layout: the wordmark, its emphasis, and
// the logo. LogoSrc is empty when the brand has no logo.
type Mark struct {
	Text     string
	Emphasis string
	LogoSrc  string // path under ui.Prefix, for example "/static/logo.svg"
	LogoAlt  string
}

// options collects the settings of New.
type options struct {
	brand brand.Brand
}

// KitOption changes one setting of New. The name Option belongs to the
// choices of a select field.
type KitOption func(*options)

// WithBrand sets the brand the layout draws. The default is brand.Default.
// Serve the same brand with ui.AssetsFor, so the logo path resolves.
func WithBrand(b brand.Brand) KitOption {
	return func(o *options) { o.brand = b }
}

// New parses the embedded templates. It fails when the brand logo cannot
// be decoded.
func New(opts ...KitOption) (*Kit, error) {
	o := options{brand: brand.Default()}
	for _, opt := range opts {
		opt(&o)
	}
	logo, err := o.brand.Logo.File()
	if err != nil {
		return nil, fmt.Errorf("components: brand logo: %w", err)
	}
	mark := Mark{Text: o.brand.Wordmark, Emphasis: o.brand.Emphasis}
	if logo.Name != "" {
		mark.LogoSrc, mark.LogoAlt = ui.Prefix+logo.Name, o.brand.Logo.Alt
	}
	funcs := template.FuncMap{"safeAttr": SafeAttr, "mark": func() Mark { return mark }, "inc": func(i int) int { return i + 1 }, "external": External}
	tpl, err := template.New("kit").Funcs(funcs).ParseFS(ui.Templates, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("components: %w", err)
	}
	return &Kit{tpl: tpl, mark: mark}, nil
}

// Mark returns the brand mark the layout draws.
func (k *Kit) Mark() Mark {
	return k.mark
}

// normalizer is implemented by every data struct. It fills defaults and
// returns an error when the data cannot render an accessible component.
type normalizer interface {
	normalize() (any, error)
}

// ErrNoTemplates is returned by a Kit that New did not create.
var ErrNoTemplates = errors.New("components: kit has no templates, use New")

// Render writes the named component with data to w.
func (k *Kit) Render(w io.Writer, name string, data any) error {
	if k == nil || k.tpl == nil {
		return ErrNoTemplates
	}
	if n, ok := data.(normalizer); ok {
		var err error
		if data, err = n.normalize(); err != nil {
			return fmt.Errorf("components: %s: %w", name, err)
		}
	}
	var buf bytes.Buffer
	if err := k.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		return fmt.Errorf("components: %s: %w", name, err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// HTML renders the named component and returns it as trusted HTML.
// Use it to compose a page body from components.
func (k *Kit) HTML(name string, data any) (template.HTML, error) {
	var buf bytes.Buffer
	if err := k.Render(&buf, name, data); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil //nolint:gosec // output of html/template
}

// Join concatenates trusted HTML fragments, for example the output of HTML.
func Join(parts ...template.HTML) template.HTML {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(string(p))
		b.WriteString("\n")
	}
	return template.HTML(b.String()) //nolint:gosec // inputs are already trusted
}

// IsHTMX reports whether the request comes from htmx and is not a history restore.
func IsHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

// RenderPage writes the page. An htmx request receives only the page partial
// and the title in the HX-Title header. Every other request receives the
// full layout.
func (k *Kit) RenderPage(w http.ResponseWriter, r *http.Request, page Page) error {
	if k == nil || k.tpl == nil {
		return ErrNoTemplates
	}
	data, err := page.normalize()
	if err != nil {
		return fmt.Errorf("components: page: %w", err)
	}
	p := anyval.As[Page](data)
	name := "layout"
	if IsHTMX(r) {
		name = "page"
		w.Header().Set("HX-Title", p.Title)
	}
	var buf bytes.Buffer
	if tplErr := k.tpl.ExecuteTemplate(&buf, name, p); tplErr != nil {
		return fmt.Errorf("components: %s: %w", name, tplErr)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write(buf.Bytes())
	return err
}

// Text holds the user-facing strings of the layout and the shell, so a
// message catalogue can translate them.
type Text struct {
	SkipLink    string
	ThemeToggle string
	ThemeSystem string
	ThemeLight  string
	ThemeDark   string
	SignOut     string // the sign out button of the shell user menu
	Menu        string // the side nav disclosure on narrow screens
	StackNav    string // aria-label of the stack switcher
	SideNav     string // aria-label of the side navigation
	Starting    string // badge text of a stack that is not live yet
}

// DefaultText returns the English layout strings.
func DefaultText() Text {
	return Text{SkipLink: "Skip to content", ThemeToggle: "Theme", ThemeSystem: "System", ThemeLight: "Light", ThemeDark: "Dark",
		SignOut: "Sign out", Menu: "Menu", StackNav: "Stack", SideNav: "Portal", Starting: "Starting"}
}

// fillText completes t from the English defaults.
func fillText(t Text) Text {
	d := DefaultText()
	fill(&t.SkipLink, d.SkipLink)
	fill(&t.ThemeToggle, d.ThemeToggle)
	fill(&t.ThemeSystem, d.ThemeSystem)
	fill(&t.ThemeLight, d.ThemeLight)
	fill(&t.ThemeDark, d.ThemeDark)
	fill(&t.SignOut, d.SignOut)
	fill(&t.Menu, d.Menu)
	fill(&t.StackNav, d.StackNav)
	fill(&t.SideNav, d.SideNav)
	fill(&t.Starting, d.Starting)
	return t
}

// CSRFField is the default name of the hidden field in the sign out form.
// It matches the synchronizer token field of the auth services.
const CSRFField = "csrf_token"

// StackStates lists the values StackLink.State accepts. An empty state is
// a live stack with a link. A starting stack renders as text with a badge.
var StackStates = []string{"", "starting"}

// StackLink is one stack in the switcher of the shell.
type StackLink struct {
	Name    string // required
	Href    string // required unless State is "starting"
	Current bool   // the stack this page runs on; at most one
	State   string // one of StackStates
}

// User is the signed in user of the shell. An empty Name hides the menu.
type User struct {
	Name      string
	SignOut   string // action of the sign out form, required with Name
	CSRF      string // synchronizer token, required with Name
	CSRFField string // name of the hidden field, default CSRFField
}

// NavSection is one group of links in the side navigation.
type NavSection struct {
	Label string // optional heading of the group
	Links []Link // at least one
}

// Shell is the portal frame around a page: the role chip beside the
// wordmark, the stack switcher, the user menu, and the side navigation.
// The body carries data-role, so the role accent of the brand applies.
type Shell struct {
	Role      string // one of brand.Roles, required
	RoleLabel string // chip text, default the role with a capital
	Stacks    []StackLink
	User      User
	Sections  []NavSection
}

// ID returns the id of the label of section i, counted from 1.
func (NavSection) ID(i int) string { return fmt.Sprintf("side-%d-label", i+1) }

func (s Shell) normalize() (any, error) {
	if !contains(brand.Roles(), s.Role) {
		return nil, fmt.Errorf("shell: unknown role %q", s.Role)
	}
	if s.RoleLabel == "" {
		s.RoleLabel = strings.ToUpper(s.Role[:1]) + s.Role[1:]
	}
	current := 0
	for _, st := range s.Stacks {
		if st.Name == "" {
			return nil, errors.New("shell: stack name is required")
		}
		if !contains(StackStates, st.State) {
			return nil, fmt.Errorf("shell: stack %q: unknown state %q", st.Name, st.State)
		}
		if st.State == "" && st.Href == "" {
			return nil, fmt.Errorf("shell: stack %q: href is required", st.Name)
		}
		if st.Current {
			current++
		}
	}
	if current > 1 {
		return nil, errors.New("shell: at most one stack is current")
	}
	if s.User.Name != "" {
		if s.User.SignOut == "" || s.User.CSRF == "" {
			return nil, errors.New("shell: user needs a sign out action and a CSRF token")
		}
		fill(&s.User.CSRFField, CSRFField)
	}
	for _, sec := range s.Sections {
		if len(sec.Links) == 0 {
			return nil, fmt.Errorf("shell: section %q has no links", sec.Label)
		}
		for _, l := range sec.Links {
			if l.Href == "" || l.Text == "" {
				return nil, fmt.Errorf("shell: section %q: every link needs href and text", sec.Label)
			}
		}
	}
	return s, nil
}

// Link is one navigation link. Current marks the active page.
type Link struct {
	Href    string
	Text    string
	Current bool
}

// Local reports a link to a path of this site. Only such a link swaps
// the main region through htmx; an anchor and an external address open
// as plain links.
func (l Link) Local() bool {
	return strings.HasPrefix(l.Href, "/") && !strings.HasPrefix(l.Href, "//")
}

// External reports a link that leaves this site: an absolute address or
// a protocol relative one. Such a link carries rel="noopener".
func External(href string) bool {
	return strings.Contains(href, "://") || strings.HasPrefix(href, "//")
}

// Nav is the labelled navigation landmark.
type Nav struct {
	Label string // aria-label of the nav, default "Main"
	Brand Link   // Href is the target of the wordmark, default "/"; Text names the service beside it
	Links []Link
}

// Page is the data of the layout and the page partial.
type Page struct {
	Lang        string        // BCP 47 tag for <html lang>, default "en"
	Title       string        // document title, required
	Heading     string        // the one h1, default Title
	Label       string        // optional accent label above the h1, for example the role
	Lead        string        // optional sentence under the h1
	Actions     template.HTML // optional buttons under the lead, from Kit.HTML
	Description string
	Nav         Nav
	Shell       *Shell        // the portal frame; nil renders a plain page
	Hero        *Hero         // replaces the page header and carries the h1
	SignIn      *SignIn       // the sign in chooser; it replaces the page header and carries the h1
	Content     template.HTML // composed from Kit.HTML
	Toasts      []Toast
	Footer      string
	Text        Text
}

func (p Page) normalize() (any, error) {
	if p.Title == "" {
		return nil, errors.New("title is required")
	}
	if p.Lang == "" {
		p.Lang = "en"
	}
	if p.Heading == "" {
		p.Heading = p.Title
	}
	fill(&p.Nav.Label, "Main")
	fill(&p.Nav.Brand.Href, "/")
	p.Text = fillText(p.Text)
	if p.Shell != nil {
		s, err := p.Shell.normalize()
		if err != nil {
			return nil, err
		}
		sh := anyval.As[Shell](s)
		p.Shell = &sh
	}
	if p.Hero != nil {
		h, err := p.Hero.normalize()
		if err != nil {
			return nil, err
		}
		hero := anyval.As[Hero](h)
		p.Hero = &hero
	}
	if p.SignIn != nil {
		s, err := p.SignIn.normalize()
		if err != nil {
			return nil, err
		}
		block := anyval.As[SignIn](s)
		p.SignIn = &block
	}
	for i := range p.Toasts {
		t, err := p.Toasts[i].normalize()
		if err != nil {
			return nil, err
		}
		p.Toasts[i] = anyval.As[Toast](t)
	}
	return p, nil
}

func fill(s *string, def string) {
	if *s == "" {
		*s = def
	}
}

// Card is a titled section.
type Card struct {
	ID     string // required, used for aria-labelledby
	Title  string
	Text   string
	Body   template.HTML
	Footer string
}

func (c Card) normalize() (any, error) {
	if err := checkID(c.ID); err != nil {
		return nil, err
	}
	return c, nil
}

// Option is one choice of a select field.
type Option struct {
	Value    string
	Text     string
	Selected bool
}

// Field is one labelled form control with hint and error text.
type Field struct {
	ID           string // required
	Name         string // default ID
	Label        string // required
	Type         string // input type, "textarea", or "select"; default "text"
	Value        string
	Hint         string
	Error        string
	Required     bool
	Options      []Option          // for Type "select"
	Attrs        map[string]string // extra attributes, whitelisted by safeAttr
	Autocomplete string            // shortcut for Attrs["autocomplete"]
}

// DescribedBy returns the aria-describedby value: hint then error ids.
func (f Field) DescribedBy() string {
	var ids []string
	if f.Hint != "" {
		ids = append(ids, f.ID+"-hint")
	}
	if f.Error != "" {
		ids = append(ids, f.ID+"-error")
	}
	return strings.Join(ids, " ")
}

func (f Field) normalize() (any, error) {
	if err := checkID(f.ID); err != nil {
		return nil, err
	}
	if f.Label == "" {
		return nil, fmt.Errorf("field %q: label is required", f.ID)
	}
	fill(&f.Name, f.ID)
	fill(&f.Type, "text")
	if f.Autocomplete != "" {
		f.Attrs = withAttr(f.Attrs, "autocomplete", f.Autocomplete)
	}
	if err := checkAttrs(f.Attrs); err != nil {
		return nil, err
	}
	return f, nil
}

// Cell is one table cell: plain text, or trusted HTML from Kit.HTML.
type Cell struct {
	Text string
	HTML template.HTML
}

// Row is one table row.
type Row []Cell

// Table is a data table with a caption and column headers.
type Table struct {
	ID      string
	Caption string // required
	Columns []string
	Rows    []Row
	Empty   string // shown when Rows is empty, default "No rows"
}

func (t Table) normalize() (any, error) {
	if t.Caption == "" {
		return nil, errors.New("table: caption is required")
	}
	if len(t.Columns) == 0 {
		return nil, errors.New("table: at least one column is required")
	}
	fill(&t.Empty, "No rows")
	return t, nil
}

// Statuses lists the values Badge.Status and Toast.Level accept.
var Statuses = []string{"ok", "warn", "bad", "info"}

// Badge is a status label. The text carries the meaning, not the colour.
type Badge struct {
	Status string // one of Statuses
	Text   string // required
}

func (b Badge) normalize() (any, error) {
	if err := checkStatus(b.Status); err != nil {
		return nil, fmt.Errorf("badge: %w", err)
	}
	if b.Text == "" {
		return nil, errors.New("badge: text is required")
	}
	return b, nil
}

// Toast is one message for the aria-live region.
// OOB adds hx-swap-oob so an htmx response can append it to the region.
type Toast struct {
	ID    string
	Level string // one of Statuses
	Text  string // required
	OOB   bool
}

func (t Toast) normalize() (any, error) {
	if err := checkStatus(t.Level); err != nil {
		return nil, fmt.Errorf("toast: %w", err)
	}
	if t.Text == "" {
		return nil, errors.New("toast: text is required")
	}
	return t, nil
}

// Dialog is a native <dialog>. Open renders it visible without JavaScript.
type Dialog struct {
	ID        string // required
	Title     string // required
	Text      string
	Body      template.HTML
	Actions   []Button // rendered inside the method="dialog" form
	CloseText string   // default "Close"
	Open      bool
}

func (d Dialog) normalize() (any, error) {
	if err := checkID(d.ID); err != nil {
		return nil, err
	}
	if d.Title == "" {
		return nil, fmt.Errorf("dialog %q: title is required", d.ID)
	}
	fill(&d.CloseText, "Close")
	for i := range d.Actions {
		b, err := d.Actions[i].normalize()
		if err != nil {
			return nil, err
		}
		d.Actions[i] = anyval.As[Button](b)
	}
	return d, nil
}

// QR is a QR code image. Alt is required and must say what the code opens.
type QR struct {
	Src  template.URL // data:image/... URL, or a path starting with "/"
	Alt  string
	Size int // CSS pixels, default 256
}

func (q QR) normalize() (any, error) {
	src := string(q.Src)
	if !strings.HasPrefix(src, "data:image/") && !strings.HasPrefix(src, "/") {
		return nil, errors.New("qr: src must be a data:image/ URL or a path")
	}
	if strings.TrimSpace(q.Alt) == "" {
		return nil, errors.New("qr: alt text is required")
	}
	if q.Size <= 0 {
		q.Size = 256
	}
	return q, nil
}

// JSON shows a value as indented JSON inside a disclosure.
type JSON struct {
	ID      string // required, id of the labelled region
	Summary string // required, the disclosure text and region label
	Data    any
	Open    bool
}

// Text returns Data as indented JSON.
func (j JSON) Text() (string, error) {
	b, err := json.MarshalIndent(j.Data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (j JSON) normalize() (any, error) {
	if err := checkID(j.ID); err != nil {
		return nil, err
	}
	if j.Summary == "" {
		return nil, fmt.Errorf("json %q: summary is required", j.ID)
	}
	if _, err := j.Text(); err != nil {
		return nil, fmt.Errorf("json %q: %w", j.ID, err)
	}
	return j, nil
}

// Variants lists the values Button.Variant accepts.
var Variants = []string{"primary", "secondary", "danger", "ghost"}

// Button is a <button>, or an <a class="btn"> when Href is set.
// Controls makes it a disclosure button with aria-expanded.
// Opens makes it open the dialog with that id.
type Button struct {
	Text      string // required unless AriaLabel is set
	Type      string // "button" or "submit", default "button"
	Variant   string // one of Variants, default "secondary"
	Href      string
	Name      string
	Value     string
	Controls  string // id of the region this button expands
	Expanded  bool
	Opens     string // id of the dialog this button opens
	Disabled  bool
	AriaLabel string
	Attrs     map[string]string // extra attributes, whitelisted by safeAttr
}

func (b Button) normalize() (any, error) {
	if strings.TrimSpace(b.Text) == "" && b.AriaLabel == "" {
		return nil, errors.New("button: text or aria-label is required")
	}
	fill(&b.Type, "button")
	fill(&b.Variant, "secondary")
	if b.Type != "button" && b.Type != "submit" {
		return nil, fmt.Errorf("button: unknown type %q", b.Type)
	}
	if !contains(Variants, b.Variant) {
		return nil, fmt.Errorf("button: unknown variant %q", b.Variant)
	}
	if err := checkAttrs(b.Attrs); err != nil {
		return nil, err
	}
	return b, nil
}

// Hero is the opening block of a landing or intro page. It carries the one
// h1 of the page, so set Page.Hero and the page header steps aside.
type Hero struct {
	Label    string // tracked label above the title, for example the product name
	Title    string // required, the h1
	Emphasis string // second line of the title in the primary colour
	Lead     string
	Actions  []Button
	Aside    template.HTML // optional block under the actions, after a rule
}

func (h Hero) normalize() (any, error) {
	if h.Title == "" {
		return nil, errors.New("hero: title is required")
	}
	for i := range h.Actions {
		b, err := h.Actions[i].normalize()
		if err != nil {
			return nil, fmt.Errorf("hero: %w", err)
		}
		h.Actions[i] = anyval.As[Button](b)
	}
	return h, nil
}

// Tile is one inverting link card of a Tiles grid.
type Tile struct {
	Num    string // small tracked label in the top left, for example "01" or a role
	Title  string // required, the h2 of the tile
	Text   string
	Figure template.HTML // optional diagram between the text and the meta line, from the figure component
	Meta   string        // small text under the description, for example the stacks or the link name
	Href   string        // required
}

// External reports whether the tile leaves the site.
func (t Tile) External() bool { return External(t.Href) }

// Tiles is a grid of link tiles. Under 56.25rem the grid has two columns,
// under 30rem one.
type Tiles struct {
	Items   []Tile // at least one
	Columns int    // 4 (default) or 3 on a wide screen
}

func (t Tiles) normalize() (any, error) {
	if len(t.Items) == 0 {
		return nil, errors.New("tiles: at least one tile is required")
	}
	if t.Columns == 0 {
		t.Columns = 4
	}
	if t.Columns != 3 && t.Columns != 4 {
		return nil, fmt.Errorf("tiles: %d columns; use 3 or 4", t.Columns)
	}
	for _, it := range t.Items {
		if it.Title == "" || it.Href == "" {
			return nil, fmt.Errorf("tiles: tile %q needs a title and an href", it.Title)
		}
	}
	return t, nil
}

// StepStates lists the values Step.State accepts. An empty state is a plain
// step with no state text.
var StepStates = []string{"", "done", "current", "locked"}

// StepText holds the words that name a step state, so the state never
// depends on colour alone.
type StepText struct {
	Done    string // default "Done"
	Current string // default "Current"
	Locked  string // default "Locked"
}

func (t StepText) fill() StepText {
	fill(&t.Done, "Done")
	fill(&t.Current, "Current")
	fill(&t.Locked, "Locked")
	return t
}

// For returns the word of one state.
func (t StepText) For(state string) string {
	switch state {
	case "done":
		return t.Done
	case "current":
		return t.Current
	}
	return t.Locked
}

// Step is one numbered card of a Steps list.
type Step struct {
	Title    string // required
	Text     string
	State    string // one of StepStates
	Href     string // optional link at the foot of the card
	LinkText string // default "Open"
}

// Steps is an ordered list of step cards, as on a role intro page or a
// portal overview where the steps unlock in order.
type Steps struct {
	Items []Step // at least one
	Text  StepText
}

func (s Steps) normalize() (any, error) {
	if len(s.Items) == 0 {
		return nil, errors.New("steps: at least one step is required")
	}
	current := 0
	for i := range s.Items {
		st := &s.Items[i]
		if st.Title == "" {
			return nil, fmt.Errorf("steps: step %d has no title", i+1)
		}
		if !contains(StepStates, st.State) {
			return nil, fmt.Errorf("steps: step %q: unknown state %q", st.Title, st.State)
		}
		if st.State == "current" {
			current++
		}
		fill(&st.LinkText, "Open")
	}
	if current > 1 {
		return nil, errors.New("steps: at most one step is current")
	}
	s.Text = s.Text.fill()
	return s, nil
}

// CheckText holds the words that name a checklist item state.
type CheckText struct {
	Done string // default "Done"
	Todo string // default "To do"
}

// Check is one item of a Checklist.
type Check struct {
	Text   string // required
	Detail string
	Done   bool
}

// Checklist is a titled list of items that stay until done, as the first
// run checklist of the admin portal.
type Checklist struct {
	ID    string // required, used for aria-labelledby
	Title string // required
	Note  string // small text beside the title
	Items []Check
	Text  CheckText
}

func (c Checklist) normalize() (any, error) {
	if err := checkID(c.ID); err != nil {
		return nil, fmt.Errorf("checklist: %w", err)
	}
	if c.Title == "" {
		return nil, fmt.Errorf("checklist %q: title is required", c.ID)
	}
	if len(c.Items) == 0 {
		return nil, fmt.Errorf("checklist %q: at least one item is required", c.ID)
	}
	for i, it := range c.Items {
		if it.Text == "" {
			return nil, fmt.Errorf("checklist %q: item %d has no text", c.ID, i+1)
		}
	}
	fill(&c.Text.Done, "Done")
	fill(&c.Text.Todo, "To do")
	return c, nil
}

// Stat is one summary card: a label, a value, a sentence, and a link.
// Put several in a div with the class stats for a grid.
type Stat struct {
	Label    string // required
	Value    string // required, a count or a short phrase
	Text     string
	Href     string
	LinkText string // default "Open"
}

func (s Stat) normalize() (any, error) {
	if s.Label == "" || s.Value == "" {
		return nil, errors.New("stat: label and value are required")
	}
	fill(&s.LinkText, "Open")
	return s, nil
}

// Tabs is a row of links between the views of one page group, for
// example the trust list and the registries. The current view carries
// aria-current="page".
type Tabs struct {
	Label string // required, aria-label of the nav landmark
	Links []Link // two or more, each with Href and Text; at most one current
}

func (t Tabs) normalize() (any, error) {
	if t.Label == "" {
		return nil, errors.New("tabs: label is required")
	}
	if len(t.Links) < 2 {
		return nil, errors.New("tabs: two or more links are required")
	}
	current := 0
	for i, l := range t.Links {
		if l.Href == "" || l.Text == "" {
			return nil, fmt.Errorf("tabs: link %d needs href and text", i)
		}
		if l.Current {
			current++
		}
	}
	if current > 1 {
		return nil, errors.New("tabs: at most one link is current")
	}
	return t, nil
}

// Stepper shows where a multi step form stands. Current counts from 1.
type Stepper struct {
	Label   string   // required, aria-label of the list, for example "Progress"
	Steps   []string // at least two names
	Current int      // 1 to len(Steps)
	Text    StepText // Done names the steps before Current for screen readers
}

func (s Stepper) normalize() (any, error) {
	if s.Label == "" {
		return nil, errors.New("stepper: label is required")
	}
	if len(s.Steps) < 2 {
		return nil, errors.New("stepper: at least two steps are required")
	}
	for i, name := range s.Steps {
		if name == "" {
			return nil, fmt.Errorf("stepper: step %d has no name", i+1)
		}
	}
	if s.Current < 1 || s.Current > len(s.Steps) {
		return nil, fmt.Errorf("stepper: current %d is not between 1 and %d", s.Current, len(s.Steps))
	}
	s.Text = s.Text.fill()
	return s, nil
}

// ChoiceOption is one card of a Choice.
type ChoiceOption struct {
	Value    string // required
	Title    string // required
	Text     string
	Meta     string // small text at the end of the card, for example the stacks
	Checked  bool
	Disabled bool
}

// Choice is a group of radio cards, or of checkbox cards with Multiple,
// inside a fieldset with a legend.
type Choice struct {
	ID       string // required, also the default Name
	Name     string
	Legend   string // required
	Hint     string
	Options  []ChoiceOption // at least one
	Multiple bool           // checkboxes instead of radios
}

// OptionID returns the id of option i, counted from 0.
func (c Choice) OptionID(i int) string { return fmt.Sprintf("%s-%d", c.ID, i+1) }

// InputType returns the input type of the options.
func (c Choice) InputType() string {
	if c.Multiple {
		return "checkbox"
	}
	return "radio"
}

func (c Choice) normalize() (any, error) {
	if err := checkID(c.ID); err != nil {
		return nil, fmt.Errorf("choice: %w", err)
	}
	if c.Legend == "" {
		return nil, fmt.Errorf("choice %q: legend is required", c.ID)
	}
	if len(c.Options) == 0 {
		return nil, fmt.Errorf("choice %q: at least one option is required", c.ID)
	}
	for i, o := range c.Options {
		if o.Value == "" || o.Title == "" {
			return nil, fmt.Errorf("choice %q: option %d needs a value and a title", c.ID, i+1)
		}
	}
	fill(&c.Name, c.ID)
	return c, nil
}

// Code is a labelled block of code or of a long value, for example an
// offer URL or a DID document.
type Code struct {
	ID    string // required
	Label string // required, the figcaption and the region name
	Text  string // required
}

func (c Code) normalize() (any, error) {
	if err := checkID(c.ID); err != nil {
		return nil, fmt.Errorf("code: %w", err)
	}
	if c.Label == "" || c.Text == "" {
		return nil, fmt.Errorf("code %q: label and text are required", c.ID)
	}
	return c, nil
}

// Fieldset groups related fields under a legend, for example the parts
// of an address. Body holds the fields from Kit.HTML.
type Fieldset struct {
	ID     string // required
	Legend string // required, names the group
	Hint   string
	Body   template.HTML
}

func (f Fieldset) normalize() (any, error) {
	if err := checkID(f.ID); err != nil {
		return nil, fmt.Errorf("fieldset: %w", err)
	}
	if f.Legend == "" {
		return nil, fmt.Errorf("fieldset %q: legend is required", f.ID)
	}
	return f, nil
}

// Empty is an empty state: what is missing and the one action that fills it.
type Empty struct {
	Title  string // required
	Text   string
	Action Button // required
}

func (e Empty) normalize() (any, error) {
	if e.Title == "" {
		return nil, errors.New("empty: title is required")
	}
	b, err := e.Action.normalize()
	if err != nil {
		return nil, fmt.Errorf("empty: %w", err)
	}
	e.Action = anyval.As[Button](b)
	return e, nil
}

// Block is one section of a long page: an h2 that names it, a lead, a
// meta line at the right of the heading, and a body. Attrs takes the
// whitelisted htmx attributes, so a block can refresh itself.
type Block struct {
	ID    string // required, used for aria-labelledby
	Title string // required, the h2
	Lead  string
	Meta  string
	Body  template.HTML
	Attrs map[string]string
}

func (b Block) normalize() (any, error) {
	if err := checkID(b.ID); err != nil {
		return nil, fmt.Errorf("block: %w", err)
	}
	if b.Title == "" {
		return nil, fmt.Errorf("block %q: title is required", b.ID)
	}
	if err := checkAttrs(b.Attrs); err != nil {
		return nil, fmt.Errorf("block %q: %w", b.ID, err)
	}
	return b, nil
}

// viewBox matches an SVG viewBox of four numbers.
var viewBox = regexp.MustCompile(`^-?[0-9.]+ -?[0-9.]+ [0-9.]+ [0-9.]+$`)

// svgForbidden matches what an inline diagram never holds: a script, an
// event handler, or a foreign object.
var svgForbidden = regexp.MustCompile(`(?i)<script|\son[a-z]+\s*=|<foreignObject|javascript:`)

// Figure is an inline SVG diagram with a text equivalent. The SVG is an
// image named by Title, and Caption carries the words a screen reader
// gets instead of the drawing. The SVG body uses the classes fig-node,
// fig-edge, fig-label and fig-text, which the stylesheet colours with
// the theme tokens.
type Figure struct {
	ID      string        // required
	Title   string        // required, the accessible name
	Caption string        // required, the text equivalent
	ViewBox string        // required, four numbers
	SVG     template.HTML // required, the body of the svg element
}

func (f Figure) normalize() (any, error) {
	if err := checkID(f.ID); err != nil {
		return nil, fmt.Errorf("figure: %w", err)
	}
	if f.Title == "" || f.Caption == "" || f.SVG == "" {
		return nil, fmt.Errorf("figure %q: title, caption and svg are required", f.ID)
	}
	if !viewBox.MatchString(f.ViewBox) {
		return nil, fmt.Errorf("figure %q: viewBox %q is not four numbers", f.ID, f.ViewBox)
	}
	if svgForbidden.MatchString(string(f.SVG)) {
		return nil, fmt.Errorf("figure %q: the svg holds a script, a handler, or a foreign object", f.ID)
	}
	return f, nil
}

// RoleStates lists the values RoleRow.State accepts.
var RoleStates = []string{"live", "starting"}

// RoleRow is one role of a stack card with its state.
type RoleRow struct {
	Label string // required, for example Issuer
	State string // one of RoleStates
	Text  string // required, the word of the state, for example Live
}

// Badge returns the badge status of the state.
func (r RoleRow) Badge() string {
	if r.State == "live" {
		return "ok"
	}
	return "warn"
}

// Component is one deployed part of a stack, with its version and links.
type Component struct {
	Name     string // required
	Version  string // for example "pinned 1.2.3"
	RepoHref string
	RepoText string // required with RepoHref
	DocsHref string
	DocsText string // required with DocsHref
}

// StackCard is one stack of a deployment: its name, its version, its
// components, and one row per role with the state of that role.
type StackCard struct {
	ID         string // required
	Name       string // required
	Version    string // for example "Pinned 1.2.3"
	Components []Component
	Roles      []RoleRow // at least one
}

// Stacks is the list of stack cards of the landing.
type Stacks struct {
	Items           []StackCard // at least one
	ComponentsLabel string      // default "Components"
	RolesLabel      string      // default "Roles"
}

func (s Stacks) normalize() (any, error) {
	if len(s.Items) == 0 {
		return nil, errors.New("stacks: at least one stack is required")
	}
	fill(&s.ComponentsLabel, "Components")
	fill(&s.RolesLabel, "Roles")
	for _, it := range s.Items {
		if err := checkID(it.ID); err != nil {
			return nil, fmt.Errorf("stacks: %w", err)
		}
		if it.Name == "" {
			return nil, fmt.Errorf("stacks: stack %q has no name", it.ID)
		}
		if len(it.Roles) == 0 {
			return nil, fmt.Errorf("stacks: stack %q has no role", it.ID)
		}
		for _, r := range it.Roles {
			if r.Label == "" || r.Text == "" {
				return nil, fmt.Errorf("stacks: stack %q: every role needs a label and a state word", it.ID)
			}
			if !contains(RoleStates, r.State) {
				return nil, fmt.Errorf("stacks: stack %q: unknown state %q", it.ID, r.State)
			}
		}
		for _, c := range it.Components {
			if c.Name == "" {
				return nil, fmt.Errorf("stacks: stack %q: every component needs a name", it.ID)
			}
			if (c.RepoHref != "" && c.RepoText == "") || (c.DocsHref != "" && c.DocsText == "") {
				return nil, fmt.Errorf("stacks: stack %q: component %q: every link needs text", it.ID, c.Name)
			}
		}
	}
	return s, nil
}

// CTA is the call to action band: a heading, a sentence, and one button.
// More takes further buttons from Kit.HTML, after the first, when the
// reader has a choice, for example one stack per button.
type CTA struct {
	ID     string // required
	Title  string // required
	Text   string
	Action Button // required
	More   template.HTML
}

func (c CTA) normalize() (any, error) {
	if err := checkID(c.ID); err != nil {
		return nil, fmt.Errorf("cta: %w", err)
	}
	if c.Title == "" {
		return nil, fmt.Errorf("cta %q: title is required", c.ID)
	}
	b, err := c.Action.normalize()
	if err != nil {
		return nil, fmt.Errorf("cta %q: %w", c.ID, err)
	}
	c.Action = anyval.As[Button](b)
	return c, nil
}

// Note is the small aside of a hero: a tracked label, a sentence, and
// the accent line. Set it as Hero.Aside through Kit.HTML.
type Note struct {
	Label string
	Text  string // required
}

func (n Note) normalize() (any, error) {
	if n.Text == "" {
		return nil, errors.New("note: text is required")
	}
	return n, nil
}

// SignInProvider is one provider button of a SignIn block.
type SignInProvider struct {
	Text string // required, the display name of the provider
	Href string // required, the login start of the provider
	Meta string // optional realm or tenant label, drawn in the monospace stack
}

// SignIn is the sign in chooser of a role (ADR-035). The left column
// holds the role, the h1, the lead, and a link back to the role picker.
// The right panel holds one button per provider, an optional callout, an
// optional block from Kit.HTML, the register actions after a rule, and a
// note. It carries the one h1 of the page, so set Page.SignIn and the
// page header steps aside.
type SignIn struct {
	Role         string // role label above the title
	Title        string // required, the h1
	Lead         string
	Back         Link   // optional link back to the role picker
	Label        string // heading of the panel, for example "Continue with"
	Providers    []SignInProvider
	Empty        string        // sentence shown when Providers is empty
	CalloutLabel string        // bold lead of the callout
	Callout      string        // optional callout, for example for the first admin
	Extra        template.HTML // optional block from Kit.HTML, for example a form
	Or           string        // word on the rule before the register actions, default "or"
	Register     []Button      // register actions; empty hides the rule
	Note         string        // one line under the panel
}

func (s SignIn) normalize() (any, error) {
	if s.Title == "" {
		return nil, errors.New("signin: title is required")
	}
	for i, p := range s.Providers {
		if strings.TrimSpace(p.Text) == "" || p.Href == "" {
			return nil, fmt.Errorf("signin: provider %d needs text and href", i)
		}
	}
	fill(&s.Or, "or")
	for i := range s.Register {
		b, err := s.Register[i].normalize()
		if err != nil {
			return nil, fmt.Errorf("signin: %w", err)
		}
		s.Register[i] = anyval.As[Button](b)
	}
	return s, nil
}

func checkID(id string) error {
	if !identifier.MatchString(id) {
		return fmt.Errorf("id %q is not a valid identifier", id)
	}
	return nil
}

func checkStatus(s string) error {
	if !contains(Statuses, s) {
		return fmt.Errorf("unknown status %q", s)
	}
	return nil
}

func checkAttrs(attrs map[string]string) error {
	var bad []string
	for name := range attrs {
		if !safeAttrNames[name] {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("attributes not allowed: %s", strings.Join(bad, ", "))
	}
	return nil
}

func withAttr(attrs map[string]string, name, value string) map[string]string {
	out := make(map[string]string, len(attrs)+1)
	for k, v := range attrs {
		out[k] = v
	}
	out[name] = value
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
