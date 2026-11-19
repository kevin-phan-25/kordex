package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
)

const securityAuditOrganization = "kordex-security"

type SecurityDenial struct {
	OrganizationID string
	Actor          string
	Reason         string
	Route          string
	Method         string
	Role           string
	RequestID      string
}

type securityDenialMetadata struct {
	Reason string `json:"reason"`
	Method string `json:"method"`
	Route  string `json:"route"`
	Role   string `json:"role,omitempty"`
}

func validSecurityDenial(v SecurityDenial) bool {
	if v.Actor == "" || len(v.Actor) > 512 || len(v.Route) == 0 || len(v.Route) > 512 || strings.ContainsAny(v.Route, "?#\r\n") || !protocol.ValidUUID(v.RequestID) || len(v.Role) > 64 {
		return false
	}
	if v.OrganizationID != "" && !protocol.ValidUUID(v.OrganizationID) {
		return false
	}
	switch v.Reason {
	case "membership_denied", "role_denied":
	default:
		return false
	}
	switch v.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return false
	}
	return true
}

// RecordSecurityDenial persists authorization failures for already-authenticated
// principals. Anonymous credential failures stay in bounded-credential-safe
// application logs to avoid unauthenticated database write amplification.
func (s *Store) RecordSecurityDenial(ctx context.Context, denial SecurityDenial) error {
	if !validSecurityDenial(denial) {
		return errors.New("invalid security audit denial")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var lastID int64
	var previous []byte
	if err = tx.QueryRow(ctx, `SELECT last_event_id,last_hash FROM security_audit_chain_head WHERE singleton=true FOR UPDATE`).Scan(&lastID, &previous); err != nil {
		return err
	}
	var id int64
	if err = tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('security_audit_events','id'))`).Scan(&id); err != nil {
		return err
	}
	if len(previous) != sha256.Size || (lastID == 0 && !equalHash(previous, make([]byte, sha256.Size))) || (lastID > 0 && id <= lastID) {
		return errors.New("security audit chain head is invalid; refusing to append")
	}
	if lastID > 0 {
		var persistedHead []byte
		if err = tx.QueryRow(ctx, `SELECT event_hash FROM security_audit_events WHERE id=$1`, lastID).Scan(&persistedHead); err != nil {
			return errors.New("security audit chain head references a missing event; refusing to append")
		}
		if !equalHash(previous, persistedHead) {
			return errors.New("security audit chain head does not match its last event; refusing to append")
		}
	}
	var occurred time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&occurred); err != nil {
		return err
	}
	metadata, err := json.Marshal(securityDenialMetadata{Reason: denial.Reason, Method: denial.Method, Route: denial.Route, Role: denial.Role})
	if err != nil {
		return err
	}
	event := auditchain.Event{
		ID: id, OrganizationID: securityAuditOrganization, Actor: denial.Actor,
		Action: "authorization.denied", ResourceID: denial.OrganizationID,
		RequestID: denial.RequestID, OccurredAt: occurred, Metadata: metadata,
	}
	hash, err := auditchain.Hash(previous, event)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO security_audit_events
 (id,organization_id,actor,reason,route,method,role,request_id,occurred_at,previous_hash,event_hash)
 OVERRIDING SYSTEM VALUE VALUES ($1,NULLIF($2,'')::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		id, denial.OrganizationID, denial.Actor, denial.Reason, denial.Route, denial.Method, denial.Role,
		denial.RequestID, occurred, previous, hash)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE security_audit_chain_head SET last_event_id=$1,last_hash=$2 WHERE singleton=true`, id, hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SecurityAuditHighWater(ctx context.Context) (int64, error) {
	id, _, err := s.SecurityAuditCheckpoint(ctx)
	return id, err
}

func (s *Store) SecurityAuditCheckpoint(ctx context.Context) (int64, []byte, error) {
	var id int64
	var hash []byte
	err := s.Pool.QueryRow(ctx, `SELECT last_event_id,last_hash FROM security_audit_chain_head WHERE singleton=true`).Scan(&id, &hash)
	if err != nil {
		return 0, nil, err
	}
	if len(hash) != sha256.Size {
		return 0, nil, errors.New("security audit checkpoint hash has invalid size")
	}
	return id, hash, nil
}

// ListSecurityAudit returns a bounded ascending page from a fixed high-water
// snapshot. IDs can have gaps because PostgreSQL sequences are not transactional.
func (s *Store) ListSecurityAudit(ctx context.Context, afterID, throughID int64, limit int) ([]auditchain.Record, error) {
	if afterID < 0 || throughID < 1 || afterID >= throughID || limit < 1 || limit > 1000 {
		return nil, errors.New("invalid security audit page")
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,COALESCE(organization_id::text,''),actor,reason,route,method,role,request_id::text,occurred_at,previous_hash,event_hash
 FROM security_audit_events WHERE id>$1 AND id<=$2 ORDER BY id ASC LIMIT $3`, afterID, throughID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]auditchain.Record, 0, limit)
	for rows.Next() {
		var id int64
		var targetOrg, actor, reason, route, method, role, request string
		var occurred time.Time
		var previous, hash []byte
		if err = rows.Scan(&id, &targetOrg, &actor, &reason, &route, &method, &role, &request, &occurred, &previous, &hash); err != nil {
			return nil, err
		}
		metadata, marshalErr := json.Marshal(securityDenialMetadata{Reason: reason, Method: method, Route: route, Role: role})
		if marshalErr != nil {
			return nil, marshalErr
		}
		result = append(result, auditchain.Record{
			Event:        auditchain.Event{ID: id, OrganizationID: securityAuditOrganization, Actor: actor, Action: "authorization.denied", ResourceID: targetOrg, RequestID: request, OccurredAt: occurred, Metadata: metadata},
			PreviousHash: hex.EncodeToString(previous), EventHash: hex.EncodeToString(hash),
		})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) VerifySecurityAudit(ctx context.Context) error {
	throughID, expectedHead, err := s.SecurityAuditCheckpoint(ctx)
	if err != nil {
		return err
	}
	if throughID == 0 {
		if !equalHash(expectedHead, make([]byte, sha256.Size)) {
			return errors.New("empty security audit stream has a nonempty chain head")
		}
		return nil
	}
	var lastID int64
	var previous = make([]byte, sha256.Size)
	for lastID < throughID {
		items, pageErr := s.ListSecurityAudit(ctx, lastID, throughID, 1000)
		if pageErr != nil {
			return pageErr
		}
		if len(items) == 0 {
			return fmt.Errorf("security audit chain has a gap before checkpoint %d", throughID)
		}
		for _, item := range items {
			if item.OrganizationID != securityAuditOrganization || item.Action != "authorization.denied" || !protocol.ValidUUID(item.RequestID) {
				return errors.New("security audit chain scope is invalid")
			}
			verified, verifyErr := auditchain.Verify(item, previous)
			if verifyErr != nil {
				return verifyErr
			}
			previous = verified
			lastID = item.ID
		}
	}
	if !equalHash(expectedHead, previous) {
		return errors.New("security audit chain head does not match records")
	}
	return nil
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for i := range a {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}
