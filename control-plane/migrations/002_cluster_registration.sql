-- Additive schema: immutable cluster identity and tenant-scoped relationships.
ALTER TABLE sites ADD CONSTRAINT sites_org_id_unique UNIQUE (organization_id, id);
CREATE TABLE fleets (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES organizations(id),
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (organization_id, name),
 UNIQUE (organization_id, id)
);
CREATE TABLE memberships (
 organization_id uuid NOT NULL REFERENCES organizations(id),
 subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
 role text NOT NULL CHECK (role IN ('viewer','administrator')),
 PRIMARY KEY (organization_id, subject)
);
CREATE TABLE clusters (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES organizations(id),
 fleet_id uuid NOT NULL,
 site_id uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 provider text NOT NULL CHECK (provider IN ('self-managed','gke','eks','aks')),
 cluster_uid text,
 kubernetes_version text NOT NULL DEFAULT '',
 snapshot_version bigint NOT NULL DEFAULT 0,
 observed_at timestamptz,
 last_heartbeat_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (organization_id, name),
 UNIQUE (cluster_uid),
 FOREIGN KEY (organization_id, fleet_id) REFERENCES fleets(organization_id,id),
 FOREIGN KEY (organization_id, site_id) REFERENCES sites(organization_id,id)
);
CREATE INDEX clusters_org_inventory ON clusters(organization_id,created_at,id);
CREATE TABLE enrollment_tokens (
 token_hash bytea PRIMARY KEY,
 cluster_id uuid NOT NULL REFERENCES clusters(id),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_cluster ON enrollment_tokens(cluster_id);
CREATE TABLE agent_identities (
 cluster_id uuid PRIMARY KEY REFERENCES clusters(id),
 key_id text NOT NULL UNIQUE,
 public_key bytea NOT NULL CHECK (octet_length(public_key)=32),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz
);
CREATE TABLE agent_nonces (
 cluster_id uuid NOT NULL REFERENCES clusters(id),
 nonce text NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(cluster_id,nonce)
);
CREATE INDEX agent_nonce_expiry ON agent_nonces(expires_at);
CREATE TABLE nodes (
 cluster_id uuid NOT NULL REFERENCES clusters(id),
 uid text NOT NULL,
 name text NOT NULL,
 inventory jsonb NOT NULL,
 PRIMARY KEY(cluster_id,uid),
 UNIQUE(cluster_id,name)
);

ALTER TABLE audit_events ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
