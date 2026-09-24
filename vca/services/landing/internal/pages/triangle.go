// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"fmt"
	"html"
	"html/template"

	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// triangleViewBox is the drawing area of the triangle of trust.
const triangleViewBox = "0 0 320 210"

// triangle returns the figure of the triangle of trust: the three roles
// at the corners, the three exchanges along the edges, and the trust
// registry in the middle. Every word comes from the catalogue, and the
// caption is the text equivalent.
func triangle() components.Figure {
	node := func(x, y int, label string) string {
		return fmt.Sprintf(`<circle class="fig-node" cx="%d" cy="%d" r="34"/><text class="fig-text" font-size="13" x="%d" y="%d">%s</text>`,
			x, y, x, y+4, html.EscapeString(label))
	}
	edge := func(x, y int, anchor, label string) string {
		return fmt.Sprintf(`<text class="fig-label" font-size="10" x="%d" y="%d" text-anchor="%s">%s</text>`, x, y, anchor, html.EscapeString(label))
	}
	svg := `<path class="fig-edge" d="M60 165 L160 40 L260 165 Z"/>` +
		edge(92, 96, "end", msg.T("landing.triangle.issues.label")) +
		edge(228, 96, "start", msg.T("landing.triangle.presents.label")) +
		edge(160, 196, "middle", msg.T("landing.triangle.trusts.label")) +
		`<circle class="fig-node" cx="160" cy="118" r="12"/>` +
		edge(160, 148, "middle", msg.T("landing.triangle.registry.label")) +
		node(60, 165, msg.T("role.issuer.label")) +
		node(160, 40, msg.T("role.holder.label")) +
		node(260, 165, msg.T("role.verifier.label"))
	return components.Figure{
		ID:      "triangle",
		Title:   msg.T("landing.how.triangle.label"),
		Caption: msg.T("landing.how.triangle.alt"),
		ViewBox: triangleViewBox,
		SVG:     template.HTML(svg), //nolint:gosec // built from escaped catalogue words and fixed shapes
	}
}
