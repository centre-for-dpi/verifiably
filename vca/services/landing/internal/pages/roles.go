// SPDX-License-Identifier: Apache-2.0

package pages

import "net/http"

// roles serves the role picker. The next unit fills it.
func (p *Pages) roles(w http.ResponseWriter, r *http.Request) { p.notFound(w, r) }

// intro serves one role intro page. The next unit fills it.
func (p *Pages) intro(w http.ResponseWriter, r *http.Request) { p.notFound(w, r) }
