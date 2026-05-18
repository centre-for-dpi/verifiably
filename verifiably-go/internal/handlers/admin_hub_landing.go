package handlers

import "net/http"

// ShowAdminHub handles GET /admin — hub admin landing page.
// Shows cards for every admin section available in hub mode.
func (h *H) ShowAdminHub(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if !sess.IsAdmin {
		h.redirect(w, r, "/admin/login")
		return
	}
	h.render(w, r, "admin_hub_landing", h.pageData(sess, map[string]any{
		"HasAPIKeyStore": h.IssuerAPIKeyStore != nil,
		"GrafanaURL":     h.GrafanaURL,
	}))
}
