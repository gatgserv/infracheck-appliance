package agent

import (
	"encoding/json"
	"net/http"
	"strings"
)

type updateAdminTokenRequest struct {
	NewToken string `json:"new_token"`
}

func (a *Agent) updateAdminToken(w http.ResponseWriter, r *http.Request) {
	var req updateAdminTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	token := strings.TrimSpace(req.NewToken)
	if len(token) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "admin token must have at least 12 characters"})
		return
	}
	if err := a.db.SetSetting(adminTokenSetting, token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "saved"})
}
