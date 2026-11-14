CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name)
);
CREATE TABLE sites (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    region text NOT NULL CHECK (length(region) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE INDEX sites_inventory ON sites (organization_id, created_at, id);
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    actor text NOT NULL,
    action text NOT NULL,
    resource_id uuid NOT NULL,
    request_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_organization_time ON audit_events (organization_id, occurred_at, id);
