ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check CHECK(role IN ('viewer','operator','approver','administrator'));
CREATE TABLE organization_limits (
 organization_id uuid PRIMARY KEY REFERENCES organizations(id),
 limits jsonb NOT NULL DEFAULT '{"organization":1,"fleet":1,"site":1,"cluster":1,"node":1,"maxUnavailablePerSite":1}',
 revision bigint NOT NULL DEFAULT 1,
 next_tick_at timestamptz NOT NULL DEFAULT now(),
 scheduler_epoch bigint NOT NULL DEFAULT 0,
 last_worker text NOT NULL DEFAULT ''
);
INSERT INTO organization_limits(organization_id) SELECT id FROM organizations;
CREATE TABLE campaigns (
 id uuid PRIMARY KEY,
 organization_id uuid NOT NULL REFERENCES organizations(id),
 spec jsonb NOT NULL,
 phase text NOT NULL DEFAULT 'Draft',
 reason text NOT NULL DEFAULT 'DraftCreated',
 revision bigint NOT NULL DEFAULT 1,
 plan_generation bigint NOT NULL DEFAULT 1,
 stage integer NOT NULL DEFAULT 0 CHECK(stage BETWEEN 0 AND 3),
 approval_epoch bigint NOT NULL DEFAULT 1,
 snapshot_digest text NOT NULL DEFAULT '',
 created_by text NOT NULL,
 failed_baseline integer NOT NULL DEFAULT 0,
 completed_baseline integer NOT NULL DEFAULT 0,
 terminal_after_stop text NOT NULL DEFAULT 'Cancelled',
 last_scheduled_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,id)
);
CREATE INDEX campaigns_scheduler ON campaigns(organization_id,last_scheduled_at,created_at) WHERE phase NOT IN ('Draft','Succeeded','Failed','Cancelled','CompletedWithFailures');
CREATE TABLE campaign_windows (
 campaign_id uuid NOT NULL REFERENCES campaigns(id),
 ordinal integer NOT NULL,
 start_at timestamptz NOT NULL,
 end_at timestamptz NOT NULL CHECK(end_at>start_at),
 time_zone text NOT NULL,
 PRIMARY KEY(campaign_id,ordinal)
);
CREATE TABLE campaign_targets (
 id uuid PRIMARY KEY,
 campaign_id uuid NOT NULL REFERENCES campaigns(id),
 organization_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 fleet_id uuid NOT NULL,
 site_id uuid NOT NULL,
 node_uid text NOT NULL,
 node_name text NOT NULL,
 snapshot jsonb NOT NULL,
 ordinal integer NOT NULL,
 stage integer NOT NULL CHECK(stage BETWEEN 0 AND 3),
 state text NOT NULL DEFAULT 'Pending',
 reason text NOT NULL DEFAULT 'SnapshotSelected',
 attempts integer NOT NULL DEFAULT 0,
 failures integer NOT NULL DEFAULT 0,
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,campaign_id) REFERENCES campaigns(organization_id,id),
 FOREIGN KEY(organization_id,cluster_id) REFERENCES clusters(organization_id,id),
 UNIQUE(campaign_id,cluster_id,node_uid),
 UNIQUE(campaign_id,ordinal)
);
CREATE INDEX campaign_targets_admission ON campaign_targets(campaign_id,stage,state,next_attempt_at,ordinal);
ALTER TABLE node_operations ADD COLUMN terminal_at timestamptz;
ALTER TABLE node_operations ADD COLUMN campaign_id uuid REFERENCES campaigns(id);
ALTER TABLE node_operations ADD COLUMN cancel_requested_at timestamptz;
ALTER TABLE node_operations ADD COLUMN cancel_reason text;
CREATE TABLE campaign_attempts (
 operation_id uuid PRIMARY KEY REFERENCES node_operations(id),
 target_id uuid NOT NULL REFERENCES campaign_targets(id),
 campaign_id uuid NOT NULL REFERENCES campaigns(id),
 attempt integer NOT NULL,
 phase text NOT NULL DEFAULT 'Pending',
 reason text NOT NULL DEFAULT 'OperationIssued',
 finished_at timestamptz,
 UNIQUE(target_id,attempt)
);
CREATE INDEX campaign_attempts_progress ON campaign_attempts(campaign_id,finished_at,operation_id);
CREATE TABLE operation_reservations (
 operation_id uuid PRIMARY KEY REFERENCES node_operations(id),
 organization_id uuid NOT NULL REFERENCES organizations(id),
 fleet_id uuid NOT NULL,
 site_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 node_uid text NOT NULL,
 campaign_id uuid REFERENCES campaigns(id),
 released_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,fleet_id) REFERENCES fleets(organization_id,id),
 FOREIGN KEY(organization_id,site_id) REFERENCES sites(organization_id,id),
 FOREIGN KEY(organization_id,cluster_id) REFERENCES clusters(organization_id,id)
);
CREATE INDEX reservation_active_scopes ON operation_reservations(organization_id,fleet_id,site_id,cluster_id) WHERE released_at IS NULL;
INSERT INTO operation_reservations(operation_id,organization_id,fleet_id,site_id,cluster_id,node_uid)
 SELECT o.id,o.organization_id,c.fleet_id,c.site_id,c.id,o.request->>'nodeUid'
 FROM node_operations o JOIN clusters c ON c.id=o.cluster_id WHERE o.phase NOT IN ('Succeeded','Failed','Cancelled');
CREATE TABLE campaign_approvals (
 id uuid PRIMARY KEY,
 campaign_id uuid NOT NULL REFERENCES campaigns(id),
 plan_generation bigint NOT NULL,
 stage integer NOT NULL,
 approval_epoch bigint NOT NULL,
 snapshot_digest text NOT NULL,
 actor text NOT NULL,
 decision text NOT NULL CHECK(decision IN ('Approved','Rejected','FailureResume')),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(campaign_id,plan_generation,stage,approval_epoch)
);
CREATE TABLE campaign_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 campaign_id uuid NOT NULL REFERENCES campaigns(id),
 organization_id uuid NOT NULL REFERENCES organizations(id),
 revision bigint NOT NULL,
 actor text NOT NULL,
 kind text NOT NULL,
 details jsonb NOT NULL,
 request_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX campaign_events_history ON campaign_events(campaign_id,id);
CREATE TABLE operation_controls (
 operation_id uuid PRIMARY KEY REFERENCES node_operations(id),
 payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
