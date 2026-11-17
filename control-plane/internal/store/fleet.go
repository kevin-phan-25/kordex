package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"kordex.local/api/protocol"
)

var ErrUnauthorized = errors.New("unauthorized identity")
var ErrStale = errors.New("stale inventory version")

type Fleet struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
}
type Cluster struct {
	ID                string     `json:"id"`
	OrganizationID    string     `json:"organizationId"`
	FleetID           string     `json:"fleetId"`
	SiteID            string     `json:"siteId"`
	Name              string     `json:"name"`
	Provider          string     `json:"provider"`
	ClusterUID        *string    `json:"clusterUid"`
	KubernetesVersion string     `json:"kubernetesVersion"`
	SnapshotVersion   int64      `json:"snapshotVersion"`
	ObservedAt        *time.Time `json:"observedAt"`
	LastHeartbeatAt   *time.Time `json:"lastHeartbeatAt"`
	CreatedAt         time.Time  `json:"createdAt"`
	Connected         bool       `json:"connected"`
}
type EnrollmentToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	ClusterID string    `json:"clusterId"`
}
type AgentKey struct {
	PublicKey ed25519.PublicKey
	KeyID     string
	ExpiresAt time.Time
}

type PolicyCatalogSnapshot struct {
	ObservedAt   *time.Time                               `json:"observedAt"`
	Fresh        bool                                     `json:"fresh"`
	Capabilities *protocol.OperatorCapabilities           `json:"operatorCapabilities,omitempty"`
	Items        []protocol.MaintenancePolicyCatalogEntry `json:"items"`
}

func (s *Store) CreateFleet(ctx context.Context, org, name, actor, request string) (Fleet, error) {
	v := Fleet{ID: NewID(), OrganizationID: org, Name: name}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return v, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, "INSERT INTO fleets(id,organization_id,name) VALUES ($1,$2,$3) RETURNING created_at", v.ID, org, name).Scan(&v.CreatedAt)
	if err != nil {
		return v, classify(err)
	}
	if err = audit(ctx, tx, org, actor, "fleet.created", v.ID, request); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}
func (s *Store) ListFleets(ctx context.Context, org string, limit, offset int) ([]Fleet, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,organization_id,name,created_at FROM fleets WHERE organization_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3", org, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Fleet{}
	for rows.Next() {
		var v Fleet
		if err = rows.Scan(&v.ID, &v.OrganizationID, &v.Name, &v.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func (s *Store) CreateCluster(ctx context.Context, v Cluster, actor, request string) (Cluster, error) {
	v.ID = NewID()
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return v, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, "INSERT INTO clusters(id,organization_id,fleet_id,site_id,name,provider) VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at", v.ID, v.OrganizationID, v.FleetID, v.SiteID, v.Name, v.Provider).Scan(&v.CreatedAt)
	if err != nil {
		return v, classify(err)
	}
	if err = audit(ctx, tx, v.OrganizationID, actor, "cluster.created", v.ID, request); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}
func (s *Store) ListClusters(ctx context.Context, org string, limit, offset int) ([]Cluster, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.id,c.organization_id,c.fleet_id,c.site_id,c.name,c.provider,c.cluster_uid,c.kubernetes_version,c.snapshot_version,c.observed_at,c.last_heartbeat_at,c.created_at,
 coalesce(c.last_heartbeat_at > now()-interval '90 seconds' AND a.revoked_at IS NULL AND a.expires_at > now(),false)
 FROM clusters c LEFT JOIN agent_identities a ON a.cluster_id=c.id WHERE c.organization_id=$1 ORDER BY c.created_at,c.id LIMIT $2 OFFSET $3`, org, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Cluster{}
	for rows.Next() {
		var v Cluster
		if err = rows.Scan(&v.ID, &v.OrganizationID, &v.FleetID, &v.SiteID, &v.Name, &v.Provider, &v.ClusterUID, &v.KubernetesVersion, &v.SnapshotVersion, &v.ObservedAt, &v.LastHeartbeatAt, &v.CreatedAt, &v.Connected); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func (s *Store) ClusterOrganization(ctx context.Context, cluster string) (string, error) {
	var org string
	err := s.Pool.QueryRow(ctx, "SELECT organization_id FROM clusters WHERE id=$1", cluster).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return org, err
}
func (s *Store) IssueEnrollment(ctx context.Context, org, cluster, actor, request string) (EnrollmentToken, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return EnrollmentToken{}, err
	}
	v := EnrollmentToken{Token: base64.RawURLEncoding.EncodeToString(secret), ClusterID: cluster}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return v, err
	}
	defer tx.Rollback(ctx)
	var actual string
	err = tx.QueryRow(ctx, "SELECT organization_id FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&actual)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if actual != org {
		return v, ErrNotFound
	}
	var active bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agent_identities WHERE cluster_id=$1 AND revoked_at IS NULL)", cluster).Scan(&active); err != nil {
		return v, err
	}
	if active {
		return v, ErrConflict
	}
	if _, err = tx.Exec(ctx, "UPDATE enrollment_tokens SET consumed_at=now() WHERE cluster_id=$1 AND consumed_at IS NULL", cluster); err != nil {
		return v, err
	}
	err = tx.QueryRow(ctx, "INSERT INTO enrollment_tokens(token_hash,cluster_id,expires_at) VALUES ($1,$2,now()+interval '10 minutes') RETURNING expires_at", protocol.TokenHash(v.Token), cluster).Scan(&v.ExpiresAt)
	if err != nil {
		return v, err
	}
	if err = audit(ctx, tx, org, actor, "agent.enrollment_issued", cluster, request); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}
func (s *Store) EnrollAgent(ctx context.Context, e protocol.Enrollment, request string) (protocol.Identity, error) {
	result := protocol.Identity{ClusterID: e.ClusterID}
	public, err := protocol.DecodeKey(e.PublicKey)
	if err != nil || !protocol.VerifyProof(public, protocol.EnrollmentMessage(e), e.Proof) {
		return result, ErrUnauthorized
	}
	result.KeyID = protocol.KeyID(public)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	var org string
	var uid *string
	err = tx.QueryRow(ctx, "SELECT organization_id,cluster_uid FROM clusters WHERE id=$1 FOR UPDATE", e.ClusterID).Scan(&org, &uid)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrUnauthorized
	}
	if err != nil {
		return result, err
	}
	if uid != nil && *uid != e.ClusterUID {
		return result, ErrUnauthorized
	}
	var tokenCluster string
	err = tx.QueryRow(ctx, "UPDATE enrollment_tokens SET consumed_at=now() WHERE token_hash=$1 AND cluster_id=$2 AND consumed_at IS NULL AND expires_at>now() RETURNING cluster_id", protocol.TokenHash(e.Token), e.ClusterID).Scan(&tokenCluster)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrUnauthorized
	}
	if err != nil {
		return result, err
	}
	var active bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agent_identities WHERE cluster_id=$1 AND revoked_at IS NULL)", e.ClusterID).Scan(&active); err != nil {
		return result, err
	}
	if active {
		return result, ErrConflict
	}
	err = tx.QueryRow(ctx, `INSERT INTO agent_identities(cluster_id,key_id,public_key,expires_at) VALUES ($1,$2,$3,now()+interval '24 hours') ON CONFLICT(cluster_id) DO UPDATE SET key_id=excluded.key_id,public_key=excluded.public_key,expires_at=excluded.expires_at,revoked_at=NULL RETURNING expires_at`, e.ClusterID, result.KeyID, []byte(public)).Scan(&result.ExpiresAt)
	if err != nil {
		return result, classify(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE clusters SET cluster_uid=$2,snapshot_version=0,observed_at=NULL,last_heartbeat_at=NULL WHERE id=$1", e.ClusterID, e.ClusterUID); err != nil {
		return result, classify(err)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM nodes WHERE cluster_id=$1", e.ClusterID); err != nil {
		return result, err
	}
	if err = audit(ctx, tx, org, "agent:"+result.KeyID, "agent.enrolled", e.ClusterID, request); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
func (s *Store) AgentIdentity(ctx context.Context, cluster string) (AgentKey, error) {
	var v AgentKey
	var public []byte
	err := s.Pool.QueryRow(ctx, "SELECT public_key,key_id,expires_at FROM agent_identities WHERE cluster_id=$1 AND revoked_at IS NULL AND expires_at>now()", cluster).Scan(&public, &v.KeyID, &v.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrUnauthorized
	}
	v.PublicKey = ed25519.PublicKey(public)
	return v, err
}

// Every mutation rechecks the authenticated key under the same lock used by revocation.
func (s *Store) beginAgent(ctx context.Context, cluster, key, nonce string) (pgx.Tx, string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	fail := func(err error) (pgx.Tx, string, error) { _ = tx.Rollback(ctx); return nil, "", err }
	var org string
	err = tx.QueryRow(ctx, "SELECT organization_id FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(ErrUnauthorized)
	}
	if err != nil {
		return fail(err)
	}
	var valid bool
	err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agent_identities WHERE cluster_id=$1 AND key_id=$2 AND revoked_at IS NULL AND expires_at>now())", cluster, key).Scan(&valid)
	if err != nil {
		return fail(err)
	}
	if !valid {
		return fail(ErrUnauthorized)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM agent_nonces WHERE cluster_id=$1 AND expires_at<now()", cluster); err != nil {
		return fail(err)
	}
	_, err = tx.Exec(ctx, "INSERT INTO agent_nonces(cluster_id,nonce,expires_at) VALUES ($1,$2,now()+interval '5 minutes')", cluster, nonce)
	if err != nil {
		if errors.Is(classify(err), ErrConflict) {
			return fail(ErrUnauthorized)
		}
		return fail(err)
	}
	return tx, org, nil
}
func (s *Store) CheckAgent(ctx context.Context, cluster, key, nonce string) (protocol.Identity, error) {
	tx, _, err := s.beginAgent(ctx, cluster, key, nonce)
	if err != nil {
		return protocol.Identity{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "UPDATE clusters SET last_heartbeat_at=now() WHERE id=$1", cluster); err != nil {
		return protocol.Identity{}, err
	}
	v := protocol.Identity{ClusterID: cluster, KeyID: key}
	if err = tx.QueryRow(ctx, "SELECT expires_at FROM agent_identities WHERE cluster_id=$1", cluster).Scan(&v.ExpiresAt); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}
func (s *Store) AcceptReport(ctx context.Context, cluster, key, nonce string, v protocol.Report) error {
	tx, _, err := s.beginAgent(ctx, cluster, key, nonce)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// observed_at must be nondecreasing even if a buggy agent increments its version.
	var catalog any
	var catalogObserved any
	if v.PolicyCatalog != nil {
		data, marshalErr := json.Marshal(v.PolicyCatalog)
		if marshalErr != nil {
			return marshalErr
		}
		catalog = string(data)
		catalogObserved = v.PolicyCatalog.ObservedAt
	}
	tag, err := tx.Exec(ctx, `UPDATE clusters SET snapshot_version=$2,observed_at=$3,last_heartbeat_at=now(),kubernetes_version=$4,
 maintenance_policy_catalog=coalesce($6::jsonb,maintenance_policy_catalog),
 maintenance_policy_catalog_observed_at=CASE WHEN $6::jsonb IS NULL THEN maintenance_policy_catalog_observed_at ELSE $7 END
 WHERE id=$1 AND cluster_uid=$5 AND snapshot_version<$2 AND (observed_at IS NULL OR observed_at<=$3)`, cluster, v.Version, v.ObservedAt, v.KubernetesVersion, v.ClusterUID, catalog, catalogObserved)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStale
	}
	if _, err = tx.Exec(ctx, "DELETE FROM nodes WHERE cluster_id=$1", cluster); err != nil {
		return err
	}
	rows := make([][]any, 0, len(v.Nodes))
	for _, node := range v.Nodes {
		data, err := json.Marshal(node)
		if err != nil {
			return err
		}
		rows = append(rows, []any{cluster, node.UID, node.Name, string(data)})
	}
	if len(rows) > 0 {
		if _, err = tx.CopyFrom(ctx, pgx.Identifier{"nodes"}, []string{"cluster_id", "uid", "name", "inventory"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) RotateAgent(ctx context.Context, cluster, key, nonce string, rotation protocol.Rotation, request string) (protocol.Identity, error) {
	v := protocol.Identity{ClusterID: cluster}
	public, err := protocol.DecodeKey(rotation.PublicKey)
	if err != nil || !protocol.VerifyProof(public, protocol.RotationMessage(cluster, key, rotation.PublicKey), rotation.Proof) {
		return v, ErrUnauthorized
	}
	v.KeyID = protocol.KeyID(public)
	if v.KeyID == key {
		return v, ErrConflict
	}
	tx, org, err := s.beginAgent(ctx, cluster, key, nonce)
	if err != nil {
		return v, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, "UPDATE agent_identities SET public_key=$2,key_id=$3,expires_at=now()+interval '24 hours' WHERE cluster_id=$1 RETURNING expires_at", cluster, []byte(public), v.KeyID).Scan(&v.ExpiresAt)
	if err != nil {
		return v, err
	}
	if err = audit(ctx, tx, org, "agent:"+key, "agent.key_rotated", cluster, request); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}
func (s *Store) RevokeAgent(ctx context.Context, org, cluster, actor, request string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actual string
	err = tx.QueryRow(ctx, "SELECT organization_id FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&actual)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if actual != org {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, "UPDATE agent_identities SET revoked_at=now() WHERE cluster_id=$1", cluster); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE enrollment_tokens SET consumed_at=now() WHERE cluster_id=$1 AND consumed_at IS NULL", cluster); err != nil {
		return err
	}
	if err = audit(ctx, tx, org, actor, "agent.revoked", cluster, request); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) ListNodes(ctx context.Context, org, cluster string, limit, offset int) ([]protocol.Node, error) {
	actual, err := s.ClusterOrganization(ctx, cluster)
	if err != nil {
		return nil, err
	}
	if actual != org {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, "SELECT inventory FROM nodes WHERE cluster_id=$1 ORDER BY name,uid LIMIT $2 OFFSET $3", cluster, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []protocol.Node{}
	for rows.Next() {
		var data []byte
		var node protocol.Node
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &node); err != nil {
			return nil, err
		}
		items = append(items, node)
	}
	return items, rows.Err()
}

func (s *Store) MaintenancePolicyCatalog(ctx context.Context, org, cluster string) (PolicyCatalogSnapshot, error) {
	result := PolicyCatalogSnapshot{Items: []protocol.MaintenancePolicyCatalogEntry{}}
	var data []byte
	err := s.Pool.QueryRow(ctx, `SELECT maintenance_policy_catalog,maintenance_policy_catalog_observed_at,
 coalesce(maintenance_policy_catalog_observed_at>now()-interval '90 seconds',false)
 FROM clusters WHERE organization_id=$1 AND id=$2`, org, cluster).Scan(&data, &result.ObservedAt, &result.Fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if len(data) == 0 {
		return result, nil
	}
	var catalog protocol.MaintenancePolicyCatalog
	if err = json.Unmarshal(data, &catalog); err != nil {
		return result, err
	}
	result.Items = catalog.Items
	if catalog.Capabilities != nil && catalog.Capabilities.Fresh(time.Now().UTC()) {
		result.Capabilities = catalog.Capabilities
	}
	if result.Items == nil {
		result.Items = []protocol.MaintenancePolicyCatalogEntry{}
	}
	return result, nil
}

func (s *Store) Membership(ctx context.Context, org, subject string) (string, error) {
	var role string
	err := s.Pool.QueryRow(ctx, "SELECT role FROM memberships WHERE organization_id=$1 AND subject=$2", org, subject).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthorized
	}
	return role, err
}
func (s *Store) SetMembership(ctx context.Context, org, subject, role, actor, request string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO memberships(organization_id,subject,role) VALUES ($1,$2,$3) ON CONFLICT(organization_id,subject) DO UPDATE SET role=excluded.role", org, subject, role); err != nil {
		return classify(err)
	}
	// Subject is not a resource UUID; the audit resource is the organization.
	metadata, err := json.Marshal(map[string]string{"subject": subject, "role": role})
	if err != nil {
		return err
	}
	if err = audit(ctx, tx, org, actor, "membership.updated", org, request, json.RawMessage(metadata)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) OrganizationsForSubject(ctx context.Context, subject string, limit, offset int) ([]Organization, error) {
	rows, err := s.Pool.Query(ctx, `SELECT o.id,o.name,o.created_at FROM organizations o JOIN memberships m ON m.organization_id=o.id WHERE m.subject=$1 ORDER BY o.created_at,o.id LIMIT $2 OFFSET $3`, subject, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Organization{}
	for rows.Next() {
		var v Organization
		if err = rows.Scan(&v.ID, &v.Name, &v.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
