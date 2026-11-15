package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrConflict = errors.New("resource already exists")
var ErrNotFound = errors.New("resource not found")

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}
type Site struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Name           string    `json:"name"`
	Region         string    `json:"region"`
	CreatedAt      time.Time `json:"createdAt"`
}
type Store struct{ Pool *pgxpool.Pool }

func NewID() string {
	b := make([]byte, 16)
	// Failure to acquire secure randomness cannot safely produce an identity.
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("secure ID generation: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	// Bound queries even for callers that fail to supply a deadline.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return &Store{Pool: p}, nil
}
func (s *Store) Close() { s.Pool.Close() }

func classify(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		if pe.Code == "23505" {
			return ErrConflict
		}
		if pe.Code == "23503" {
			return ErrNotFound
		}
	}
	return err
}
func audit(ctx context.Context, tx pgx.Tx, org, actor, action, resource, request string) error {
	_, err := tx.Exec(ctx, "INSERT INTO audit_events (organization_id, actor, action, resource_id, request_id) VALUES ($1,$2,$3,$4,$5)", org, actor, action, resource, request)
	return err
}
func (s *Store) CreateOrganization(ctx context.Context, name, actor, request string) (Organization, error) {
	o := Organization{ID: NewID(), Name: name}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return o, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, "INSERT INTO organizations (id,name) VALUES ($1,$2) RETURNING created_at", o.ID, o.Name).Scan(&o.CreatedAt)
	if err != nil {
		return o, classify(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO organization_limits(organization_id) VALUES ($1)", o.ID); err != nil {
		return o, err
	}
	if err = audit(ctx, tx, o.ID, actor, "organization.created", o.ID, request); err != nil {
		return o, err
	}
	return o, tx.Commit(ctx)
}
func (s *Store) ListOrganizations(ctx context.Context, limit, offset int) ([]Organization, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,name,created_at FROM organizations ORDER BY created_at,id LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Organization{}
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}
func (s *Store) CreateSite(ctx context.Context, org, name, region, actor, request string) (Site, error) {
	site := Site{ID: NewID(), OrganizationID: org, Name: name, Region: region}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return site, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, "INSERT INTO sites (id,organization_id,name,region) VALUES ($1,$2,$3,$4) RETURNING created_at", site.ID, org, name, region).Scan(&site.CreatedAt)
	if err != nil {
		return site, classify(err)
	}
	if err = audit(ctx, tx, org, actor, "site.created", site.ID, request); err != nil {
		return site, err
	}
	return site, tx.Commit(ctx)
}
func (s *Store) ListSites(ctx context.Context, org string, limit, offset int) ([]Site, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)", org).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,organization_id,name,region,created_at FROM sites WHERE organization_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3", org, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Site{}
	for rows.Next() {
		var v Site
		if err := rows.Scan(&v.ID, &v.OrganizationID, &v.Name, &v.Region, &v.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
