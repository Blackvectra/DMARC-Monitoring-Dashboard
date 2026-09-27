-- Somewhere to send what the product finds, and a record of what was sent.
--
-- Until now every finding was learned about by opening the app. DNS drift is
-- detected on every scan and written to each client's file, and nothing told
-- anybody. A webhook is one delivery path that reaches everything else: a
-- triage console, a chat channel, a SIEM. See docs/WEBHOOKS.md.
--
-- Both tables live here, in the organization's database, not in the client
-- files. They hold which events went where, never what the events said: the
-- payload is built from the client's own file at the moment it is sent, so
-- erasing a client's file leaves nothing of its mail behind in this one.

-- One per organization. The address and the signing secret are both in the
-- secret store; this holds the pointer, the same way dns_provider_configs
-- does. The address counts as a secret because for Slack, Teams and most chat
-- tools it is one: the token is in the path, and whoever reads it can post.
-- destination is the scheme and host only, for a person to recognize.
CREATE TABLE webhooks (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    destination         TEXT NOT NULL,
    credential_ref      TEXT NOT NULL,
    min_severity        TEXT NOT NULL DEFAULT 'warning'
                        CHECK (min_severity IN ('info','warning','critical')),
    -- The dashboard's own address, so an event can link to its evidence. Null
    -- sends no link rather than a guessed one.
    link_base           TEXT,
    -- Events detected before this are never sent. Setting a webhook up is not
    -- a request for every change the product has ever seen.
    created_at          TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    last_delivered_at   TEXT,
    last_error          TEXT,
    last_error_at       TEXT
);

-- One row per event per webhook once a delivery has been tried. An event with
-- no row has never been tried; one with delivered_at set is done.
CREATE TABLE webhook_deliveries (
    webhook_id          TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_id            TEXT NOT NULL,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    attempts            INTEGER NOT NULL DEFAULT 0,
    delivered_at        TEXT,
    last_attempt_at     TEXT,
    last_status         INTEGER,
    last_error          TEXT,
    PRIMARY KEY (webhook_id, event_id)
);

CREATE INDEX ix_webhook_deliveries_client ON webhook_deliveries(client_id);
