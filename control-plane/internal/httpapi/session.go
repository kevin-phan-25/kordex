package httpapi

import (
	"net/http"
	"time"
)

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	identity := principal(r)
	if identity.Bootstrap || identity.Subject == "" || identity.expiresAt.IsZero() || !identity.expiresAt.After(time.Now()) {
		problem(w, http.StatusForbidden, "token_revocation_unavailable")
		return
	}
	repository, ok := s.repo.(TokenRevocationRepository)
	if !ok {
		problem(w, http.StatusServiceUnavailable, "token_revocation_unavailable")
		return
	}
	if err := repository.RevokeToken(r.Context(), identity.tokenHash[:], identity.expiresAt, identity.Subject, requestID(r)); err != nil {
		s.failure(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
