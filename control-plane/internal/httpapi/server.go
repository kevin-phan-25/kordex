package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"kordex.local/control-plane/internal/store"
)

type Repository interface {
	Ready(context.Context) error
	CreateOrganization(context.Context, string, string, string) (store.Organization, error)
	ListOrganizations(context.Context, int, int) ([]store.Organization, error)
	CreateSite(context.Context, string, string, string, string, string) (store.Site, error)
	ListSites(context.Context, string, int, int) ([]store.Site, error)
}
type Server struct {
	repo      Repository
	tokenHash [32]byte
	logger    *slog.Logger
	product   string
}

func New(repo Repository, token, product string, logger *slog.Logger) http.Handler {
	s := &Server{repo: repo, tokenHash: sha256.Sum256([]byte(token)), logger: logger, product: product}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := repo.Ready(ctx); err != nil {
			problem(w, 503, "not_ready")
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
	})
	mux.Handle("GET /v1/organizations", s.auth(http.HandlerFunc(s.organizations)))
	mux.Handle("POST /v1/organizations", s.auth(http.HandlerFunc(s.organizations)))
	mux.Handle("GET /v1/organizations/{organizationID}/sites", s.auth(http.HandlerFunc(s.sites)))
	mux.Handle("POST /v1/organizations/{organizationID}/sites", s.auth(http.HandlerFunc(s.sites)))
	return s.observe(mux)
}

type requestKey struct{}

func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := store.NewID()
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer("kordex.http").Start(ctx, "http.request")
		defer span.End()
		ctx, cancel := context.WithTimeout(context.WithValue(ctx, requestKey{}, request), 10*time.Second)
		defer cancel()
		w.Header().Set("X-Request-ID", request)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		started := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		requestWithContext := r.WithContext(ctx)
		defer func() {
			if v := recover(); v != nil {
				s.logger.ErrorContext(ctx, "request panic", "request_id", request)
				if !sw.written {
					problem(sw, 500, "internal_error")
				}
			}
			s.logger.InfoContext(ctx, "http request", "request_id", request, "method", r.Method, "route", requestWithContext.Pattern, "status", sw.status, "duration_ms", time.Since(started).Milliseconds(), "trace_id", span.SpanContext().TraceID().String())
		}()
		next.ServeHTTP(sw, requestWithContext)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(value, "Bearer ")
		hash := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(hash[:], s.tokenHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			problem(w, 401, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		problem(w, 415, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		problem(w, 400, "invalid_json")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		problem(w, 400, "invalid_json")
		return false
	}
	return true
}
func validName(s string) bool {
	if len(s) < 1 || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func validID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil
}
func page(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	limit, offset := 100, 0
	for key, values := range r.URL.Query() {
		if (key != "limit" && key != "offset") || len(values) != 1 {
			problem(w, 400, "invalid_pagination")
			return 0, 0, false
		}
		n, err := strconv.Atoi(values[0])
		if err != nil {
			problem(w, 400, "invalid_pagination")
			return 0, 0, false
		}
		if key == "limit" {
			limit = n
		} else {
			offset = n
		}
	}
	if limit < 1 || limit > 500 || offset < 0 || offset > 100000 {
		problem(w, 400, "invalid_pagination")
		return 0, 0, false
	}
	return limit, offset, true
}
func (s *Server) organizations(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		items, err := s.repo.ListOrganizations(r.Context(), limit, offset)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !validName(input.Name) {
		problem(w, 400, "invalid_name")
		return
	}
	item, err := s.repo.CreateOrganization(r.Context(), input.Name, "bootstrap-admin", r.Context().Value(requestKey{}).(string))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 201, item)
}
func (s *Server) sites(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("organizationID")
	if !validID(org) {
		problem(w, 400, "invalid_organization_id")
		return
	}
	if r.Method == http.MethodGet {
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		items, err := s.repo.ListSites(r.Context(), org, limit, offset)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
		return
	}
	var input struct {
		Name   string `json:"name"`
		Region string `json:"region"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !validName(input.Name) || !validName(input.Region) {
		problem(w, 400, "invalid_site")
		return
	}
	item, err := s.repo.CreateSite(r.Context(), org, input.Name, input.Region, "bootstrap-admin", r.Context().Value(requestKey{}).(string))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 201, item)
}
func (s *Server) failure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrConflict) {
		problem(w, 409, "already_exists")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		problem(w, 404, "not_found")
		return
	}
	// Database errors can contain customer input; log no raw error or credentials.
	s.logger.ErrorContext(r.Context(), "repository request failed", "request_id", r.Context().Value(requestKey{}))
	problem(w, 503, "storage_unavailable")
}
func problem(w http.ResponseWriter, status int, code string) {
	write(w, status, map[string]string{"error": code})
}
func write(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		panic("response serialization failed")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err = w.Write(append(data, '\n')); err != nil {
		panic("response write failed")
	}
}
