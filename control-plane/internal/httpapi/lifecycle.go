package httpapi

import (
	"kordex.local/api/lifecycle"
	"net/http"
)

// lifecycleDrivers is read-only compatibility metadata. It cannot enable an
// executor, issue a permit, or replace a local operator's safety decision.
func (s *Server) lifecycleDrivers(w http.ResponseWriter, r *http.Request) {
	write(w, http.StatusOK, map[string]any{"items": lifecycle.BuiltinRegistry().Drivers()})
}

// kubernetesCompatibility is an organization-authenticated, read-only registry.
// Its unverified entries are descriptive and cannot enable maintenance.
func (s *Server) kubernetesCompatibility(w http.ResponseWriter, r *http.Request) {
	write(w, http.StatusOK, lifecycle.BuiltinKubernetesCompatibilityRegistry().Catalog())
}
