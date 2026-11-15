package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"kordex.local/control-plane/internal/auditchain"
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
func audit(ctx context.Context, tx pgx.Tx, org, actor, action, resource, request string, details ...json.RawMessage) error {
	metadata := json.RawMessage(`{}`)
	if len(details) > 1 {
		return errors.New("at most one audit metadata value is allowed")
	}
	if len(details) == 1 {
		metadata = details[0]
	}
	if !json.Valid(metadata) {
		return errors.New("invalid audit metadata")
	}
	if _, err := tx.Exec(ctx, "INSERT INTO audit_chain_heads(organization_id) VALUES ($1) ON CONFLICT DO NOTHING", org); err != nil {
		return err
	}
	var previous []byte
	var lastEventID int64
	if err := tx.QueryRow(ctx, "SELECT last_event_id,last_hash FROM audit_chain_heads WHERE organization_id=$1 FOR UPDATE", org).Scan(&lastEventID, &previous); err != nil {
		return err
	}
	var id int64
	if err := tx.QueryRow(ctx, "SELECT nextval(pg_get_serial_sequence('audit_events','id'))").Scan(&id); err != nil {
		return err
	}
	if lastEventID == 0 {
		var priorHash bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM audit_events WHERE organization_id=$1 AND event_hash IS NOT NULL)", org).Scan(&priorHash); err != nil {
			return err
		}
		if priorHash {
			return errors.New("existing chained audit rows lack a chain head")
		}
	} else if id <= lastEventID {
		return errors.New("audit event sequence moved backwards; refusing to extend chain")
	}
	var occurred time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&occurred); err != nil {
		return err
	}
	event := auditchain.Event{ID: id, OrganizationID: org, Actor: actor, Action: action, ResourceID: resource, RequestID: request, OccurredAt: occurred, Metadata: metadata}
	hash, err := auditchain.Hash(previous, event)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,organization_id,actor,action,resource_id,request_id,occurred_at,metadata,previous_hash,event_hash)
OVERRIDING SYSTEM VALUE VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, org, actor, action, resource, request, occurred, string(metadata), previous, hash); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE audit_chain_heads SET last_event_id=$2,last_hash=$3 WHERE organization_id=$1", org, id, hash)
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
