-- A second kind of destination: a PSA, reached through its API.
--
-- The webhook is one address per organization given a signed POST per change.
-- A PSA (ConnectWise) has no such inbox: it is reached through its own REST
-- API and gets a ticket per finding, with a note when the finding repeats.
-- Both are destinations on the same channel - the same pending events, the
-- same ledger of what went where, the same secret store - so the table gains
-- a kind, and an organization may have one destination of each kind. See
-- docs/CONNECTWISE.md.
--
-- A rebuild rather than ALTER TABLE, because "one per organization" was a
-- UNIQUE on tenant_id and SQLite cannot loosen a constraint in place. The
-- order is the whole of the safety: the new tables are filled first; the OLD
-- child table is dropped before the old parent, so the parent's implicit
-- DELETE has nothing left to cascade into (foreign keys are enforced on the
-- connection this runs on - see MigratingNeverLosesRowsInATableItDoesNotName);
-- and the renames come last, which SQLite follows into the new child's
-- foreign key.

CREATE TABLE webhooks_new (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL DEFAULT 'webhook'
                        CHECK (kind IN ('webhook','connectwise')),
    destination         TEXT NOT NULL,
    credential_ref      TEXT NOT NULL,
    min_severity        TEXT NOT NULL DEFAULT 'warning'
                        CHECK (min_severity IN ('info','warning','critical')),
    link_base           TEXT,
    config_json         TEXT,
    created_at          TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    last_delivered_at   TEXT,
    last_error          TEXT,
    last_error_at       TEXT,
    UNIQUE (tenant_id, kind)
);

INSERT INTO webhooks_new
    (id, tenant_id, kind, destination, credential_ref, min_severity, link_base, config_json,
     created_at, created_by, updated_at, last_delivered_at, last_error, last_error_at)
SELECT id, tenant_id, 'webhook', destination, credential_ref, min_severity, link_base, NULL,
       created_at, created_by, updated_at, last_delivered_at, last_error, last_error_at
FROM webhooks;

CREATE TABLE webhook_deliveries_new (
    webhook_id          TEXT NOT NULL REFERENCES webhooks_new(id) ON DELETE CASCADE,
    event_id            TEXT NOT NULL,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    attempts            INTEGER NOT NULL DEFAULT 0,
    delivered_at        TEXT,
    last_attempt_at     TEXT,
    last_status         INTEGER,
    last_error          TEXT,
    -- What the event was about, as the PSA files it: one ticket per finding.
    -- A later event with the same key is a note on that ticket while it is
    -- open. The ticket's number is remote_id.
    remote_key          TEXT,
    remote_id           TEXT,
    PRIMARY KEY (webhook_id, event_id)
);

INSERT INTO webhook_deliveries_new
    (webhook_id, event_id, client_id, attempts, delivered_at, last_attempt_at, last_status, last_error)
SELECT webhook_id, event_id, client_id, attempts, delivered_at, last_attempt_at, last_status, last_error
FROM webhook_deliveries;

DROP TABLE webhook_deliveries;
DROP TABLE webhooks;

ALTER TABLE webhooks_new RENAME TO webhooks;
ALTER TABLE webhook_deliveries_new RENAME TO webhook_deliveries;

CREATE INDEX ix_webhook_deliveries_client ON webhook_deliveries(client_id);
CREATE INDEX ix_webhook_deliveries_remote ON webhook_deliveries(webhook_id, remote_key, delivered_at);
