package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"kordex.local/api/protocol"
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
	repo           Repository
	tokenHash      [32]byte
	logger         *slog.Logger
	product        string
	verifier       SubjectVerifier
	allowBootstrap bool
	Role           string
	maintenanceKey ed25519.PrivateKey
	metrics        *httpMetrics
	limiter        *subjectLimiter
}

type SubjectVerifier interface {
	Verify(context.Context, string) (string, error)
}
type Options struct {
	MaintenanceKey ed25519.PrivateKey
	Verifier       SubjectVerifier
	AllowBootstrap bool
	Role           string
	RateLimitRPS   float64
	RateLimitBurst int
}
type Principal struct {
	Subject   string
	Bootstrap bool
	Role      string
}
type principalKey struct{}

func principal(r *http.Request) Principal {
	p, _ := r.Context().Value(principalKey{}).(Principal)
	return p
}
func actor(r *http.Request) string {
	p := principal(r)
	if p.Bootstrap {
		return p.Subject
	}
	return "oidc:" + p.Subject
}
func New(repo Repository, token, product string, logger *slog.Logger) http.Handler {
	return NewWithOptions(repo, token, product, logger, Options{AllowBootstrap: true})
}
func NewWithOptions(repo Repository, token, product string, logger *slog.Logger, options Options) http.Handler {
	if options.RateLimitRPS <= 0 {
		options.RateLimitRPS = 20
	}
	if options.RateLimitBurst <= 0 {
		options.RateLimitBurst = 600
	}
	s := &Server{repo: repo, tokenHash: sha256.Sum256([]byte(token)), logger: logger, product: product, maintenanceKey: options.MaintenanceKey, verifier: options.Verifier, allowBootstrap: options.Verifier == nil && options.AllowBootstrap && len(token) >= 32, metrics: newHTTPMetrics(), limiter: newSubjectLimiter(options.RateLimitRPS, options.RateLimitBurst)}
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
	mux.Handle("GET /v1/organizations/{organizationID}", s.auth(http.HandlerFunc(s.organizationRoot)))
	s.registerFleetRoutes(mux)
	s.registerCampaignRoutes(mux)
	s.registerDashboardRoutes(mux)
	mux.Handle("GET /v1/organizations/{organizationID}/lifecycle-drivers", s.auth(http.HandlerFunc(s.lifecycleDrivers)))
	return &handlerWithMetrics{Handler: s.observe(mux), metrics: s.metrics}
}

func (s *Server) organizationRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		return
	}
	if p := principal(r); !p.Bootstrap {
		repo, ok := s.repo.(FleetRepository)
		if !ok {
			problem(w, 503, "identity_unavailable")
			return
		}
		items, err := repo.OrganizationsForSubject(r.Context(), p.Subject, 500, 0)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		for _, item := range items {
			if item.ID == r.PathValue("organizationID") {
				write(w, 200, item)
				return
			}
		}
		problem(w, 404, "not_found")
		return
	}
	items, err := s.repo.ListOrganizations(r.Context(), 500, 0)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	for _, item := range items {
		if item.ID == r.PathValue("organizationID") {
			write(w, 200, item)
			return
		}
	}
	problem(w, 404, "not_found")
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
			route := requestWithContext.Pattern
			if route == "" {
				route = "unmatched"
			}
			s.metrics.record(r.Method, route, sw.status, time.Since(started))
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
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			problem(w, 401, "unauthorized")
			return
		}
		hash := sha256.Sum256([]byte(token))
		p := Principal{}
		if s.allowBootstrap && subtle.ConstantTimeCompare(hash[:], s.tokenHash[:]) == 1 {
			p = Principal{Subject: "bootstrap-admin", Bootstrap: true, Role: "administrator"}
		} else {
			if s.verifier == nil {
				problem(w, 401, "unauthorized")
				return
			}
			subject, err := s.verifier.Verify(r.Context(), token)
			if err != nil || subject == "" {
				problem(w, 401, "unauthorized")
				return
			}
			p.Subject = subject
		}
		if !s.limiter.allow(p.Subject) {
			w.Header().Set("Retry-After", "1")
			problem(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
		org := r.PathValue("organizationID")
		if org != "" && !validID(org) {
			problem(w, 400, "invalid_organization_id")
			return
		}
		if !p.Bootstrap && org != "" {
			repo, ok := s.repo.(FleetRepository)
			if !ok {
				problem(w, 503, "identity_unavailable")
				return
			}
			role, err := repo.Membership(r.Context(), org, p.Subject)
			if errors.Is(err, store.ErrUnauthorized) {
				problem(w, 403, "forbidden")
				return
			}
			if err != nil {
				s.failure(w, r, err)
				return
			}
			p.Role = role
			if !authorizedRoute(r, role) {
				problem(w, 403, "forbidden")
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
		next.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool { return decodeSize(w, r, v, 16<<10) }
func decodeSize(w http.ResponseWriter, r *http.Request, v any, size int64) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		problem(w, 415, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, size)
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
func validID(s string) bool { return protocol.ValidUUID(s) }

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
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		var items []store.Organization
		var err error
		if p := principal(r); !p.Bootstrap {
			repo, ok := s.repo.(FleetRepository)
			if !ok {
				problem(w, 503, "identity_unavailable")
				return
			}
			items, err = repo.OrganizationsForSubject(r.Context(), p.Subject, limit, offset)
		} else {
			items, err = s.repo.ListOrganizations(r.Context(), limit, offset)
		}
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
		return
	}
	if !principal(r).Bootstrap {
		problem(w, 403, "platform_admin_required")
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
	item, err := s.repo.CreateOrganization(r.Context(), input.Name, actor(r), r.Context().Value(requestKey{}).(string))
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
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
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
	item, err := s.repo.CreateSite(r.Context(), org, input.Name, input.Region, actor(r), r.Context().Value(requestKey{}).(string))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 201, item)
}
func (s *Server) failure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrInvalid) {
		problem(w, 400, "invalid_campaign")
		return
	}
	if errors.Is(err, store.ErrForbidden) {
		problem(w, 403, "forbidden")
		return
	}
	if errors.Is(err, store.ErrSnapshotChanged) || errors.Is(err, store.ErrSiteHealth) || errors.Is(err, store.ErrUpgradeAdmission) {
		problem(w, 409, "safety_evidence_unavailable")
		return
	}
	if errors.Is(err, store.ErrUnauthorized) {
		problem(w, 401, "unauthorized")
		return
	}
	if errors.Is(err, store.ErrStale) {
		problem(w, 409, "stale_report")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		problem(w, 409, "already_exists")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		problem(w, 404, "not_found")
		return
	}
	// Database errors can contain customer input; log no raw error or credentials.
	category := "repository_failure"
	var pe *pgconn.PgError
	code := ""
	if errors.As(err, &pe) {
		code = pe.Code
		category = "postgres_error"
	} else if errors.Is(err, context.DeadlineExceeded) {
		category = "deadline_exceeded"
	}
	s.logger.ErrorContext(r.Context(), "repository request failed", "request_id", r.Context().Value(requestKey{}), "category", category, "sqlstate", code, "route", r.Pattern)
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
