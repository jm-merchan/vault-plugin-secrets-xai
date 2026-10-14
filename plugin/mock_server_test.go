// SPDX-License-Identifier: MPL-2.0

package xaisecrets

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type mockXAI struct {
	mu             sync.Mutex
	managementKey  string
	teamID         string
	keys           map[string]map[string]any
	deleted        []string
	createBodies   []map[string]any
	propagated     map[string]bool
	validationTeam string
	validationID   string
}

func newMockXAI(managementKey, teamID string) *mockXAI {
	return &mockXAI{
		managementKey:  managementKey,
		teamID:         teamID,
		keys:           make(map[string]map[string]any),
		propagated:     make(map[string]bool),
		validationTeam: teamID,
		validationID:   "mgmt-key-1",
	}
}

func (m *mockXAI) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/management-keys/validation", m.handleValidation)
	mux.HandleFunc("POST /auth/teams/{teamId}/api-keys", m.handleCreate)
	mux.HandleFunc("GET /auth/api-keys/{apiKeyId}/propagation", m.handlePropagation)
	mux.HandleFunc("DELETE /auth/api-keys/{apiKeyId}", m.handleDelete)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (m *mockXAI) authorized(w http.ResponseWriter, r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got != m.managementKey {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func (m *mockXAI) handleValidation(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"apiKeyId": m.validationID,
		"teamId":   m.validationTeam,
		"scope":    "SCOPE_TEAM",
		"scopeId":  m.validationTeam,
	})
}

func (m *mockXAI) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	teamID := r.PathValue("teamId")
	if teamID != m.teamID {
		http.Error(w, `{"error":"unknown team"}`, http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	parsed := map[string]any{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.createBodies = append(m.createBodies, parsed)
	id := "key-" + itoa(len(m.keys)+1)
	secret := "xai-secret-" + id
	name, _ := parsed["name"].(string)
	record := map[string]any{
		"apiKey":         secret,
		"apiKeyId":       id,
		"name":           name,
		"redactedApiKey": "xai-...redacted",
		"teamId":         m.teamID,
		"disabled":       false,
		"aclStrings":     parsed["aclStrings"],
	}
	m.keys[id] = record
	m.propagated[id] = true
	writeJSON(w, http.StatusOK, record)
}

func (m *mockXAI) handlePropagation(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	id := r.PathValue("apiKeyId")
	m.mu.Lock()
	defer m.mu.Unlock()
	ok := m.propagated[id]
	writeJSON(w, http.StatusOK, map[string]any{
		"icPropagation": map[string]bool{"cluster-a": ok},
	})
}

func (m *mockXAI) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(w, r) {
		return
	}
	id := r.PathValue("apiKeyId")
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.keys[id]; !exists {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	delete(m.keys, id)
	m.deleted = append(m.deleted, id)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
