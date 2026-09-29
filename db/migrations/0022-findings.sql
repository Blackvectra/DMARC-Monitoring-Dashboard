-- One lifecycle for what the product finds.
--
-- Until now a thing that was wrong lived in one of three half-lifecycles: a
-- DNS drift event in the client's file with three acknowledgement columns, an
-- alerts table in the client's file that nothing wrote, and a PSA ticket keyed
-- by a remote key the notifier made up per event. This adds the one table
-- they were each reaching for, in the organization's database, with its
-- history, its exceptions and the health of the engines that feed it. See
-- docs/FINDINGS.md and issue 12b in docs/OPEN-ISSUES.md.
--
-- Here rather than in the client files because a finding is operational
-- state about a client - like the audit log and the delivery ledger already
-- here - and the queue over it must not be a union of every client's file.
-- What a finding carries is metadata and a pointer; the evidence stays in the
-- client's file, and dmarc client erase covers these tables because they
-- carry client_id.

-- One row per thing that is wrong, however many nights see it. The row is
-- the finding's current state; finding_events below is what happened to it.
-- Identity is (tenant, source, client, dedup_key): a source that sees the
-- same condition again updates last_observed_at and observation_count and
-- never inserts a second row, and a condition that comes back after being
-- resolved reopens this row rather than starting a new one.
--
-- Two states, kept apart on purpose. source_state is what the source last
-- saw: active (seen), resolved (a successful observation no longer shows
-- it, for as long as the type requires), unknown (the last observation for
-- this scope failed, so nothing is known - a failed collector never clears
-- a finding). analyst_state is what a person decided, and a decision never
-- moves source_state: closing a finding is not evidence it went away.
--
-- What is kept here is metadata about a client, not the client's data: the
-- title is a derived line and evidence_ref points at the row in the client's
-- own file that holds the record text or the report. Nothing here carries a
-- DNS record's value or a report body, so a copy of this database says what
-- was found and not what the client publishes. See docs/FINDINGS.md.
CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT REFERENCES domains(id) ON DELETE CASCADE,  -- NULL for a finding about the client as a whole

    source_id           TEXT NOT NULL,                 -- which engine raised it: dns-scan, reports, remediation, anomaly
    type                TEXT NOT NULL,                 -- DMARC_POLICY_WEAKENED, SPF_INVALID, REPORTING_STOPPED, ... (FindingTypes)
    rule                TEXT,                          -- the source's finer rule, where it has one
    severity            TEXT NOT NULL
                        CHECK (severity IN ('info','warning','critical')),
    title               TEXT NOT NULL,                 -- one derived line; never the record text
    dedup_key           TEXT NOT NULL,                 -- the source's identity for the condition, stable across observations
    evidence_ref        TEXT,                          -- where the evidence is, in the client's file: kind:id
    expected_ref        TEXT,                          -- what a resolving observation has to match, for types that verify against a known-good state
    related_finding_id  TEXT REFERENCES findings(id) ON DELETE SET NULL,  -- the finding this one answers (a remediation's drift)

    source_state        TEXT NOT NULL DEFAULT 'active'
                        CHECK (source_state IN ('active','resolved','unknown')),
    analyst_state       TEXT NOT NULL DEFAULT 'unreviewed'
                        CHECK (analyst_state IN ('unreviewed','investigating','action_required','benign','accepted_risk','closed')),
    remediation_stage   TEXT
                        CHECK (remediation_stage IN ('planned','applied','dns_pending','dns_verified','effectiveness_pending')),

    first_observed_at   TEXT NOT NULL,
    last_observed_at    TEXT NOT NULL,
    observation_count   INTEGER NOT NULL DEFAULT 1,
    absent_count        INTEGER NOT NULL DEFAULT 0,    -- consecutive successful observations that did not show it
    reopened_count      INTEGER NOT NULL DEFAULT 0,
    source_resolved_at  TEXT,
    payload_json        TEXT,                          -- what the source adds beyond the title: numbers, windows, a model version; never evidence

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    UNIQUE (tenant_id, source_id, client_id, dedup_key)
);

CREATE INDEX ix_findings_tenant_state ON findings(tenant_id, source_state, analyst_state);
CREATE INDEX ix_findings_client       ON findings(client_id);
CREATE INDEX ix_findings_domain       ON findings(domain_id);
CREATE INDEX ix_findings_related      ON findings(related_finding_id);

-- What happened to a finding, appended and never updated: observed for the
-- first time, seen with a different severity, marked unknown, resolved by
-- its source, reopened, acknowledged, given an analyst state, excepted, a
-- ticket filed. A plain re-observation that changes nothing writes no row;
-- the finding's own counters carry that. This is the audit trail and the
-- material for reconstructing a finding's history, not an event log the
-- current state is rebuilt from.
CREATE TABLE finding_events (
    id                  TEXT PRIMARY KEY,
    finding_id          TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id           TEXT NOT NULL,                 -- denormalized, so erasure and isolation are checkable on this table alone
    client_id           TEXT NOT NULL,
    at                  TEXT NOT NULL,
    kind                TEXT NOT NULL,                 -- Observed, SeverityChanged, TypeChanged, SourceUnknown, ObservationAbsent, SourceResolved, Reopened, Acknowledged, AnalystStateChanged, ExceptionApplied, ExceptionExpired, ExceptionEnded, RemediationStaged, TicketCreated, TicketUpdated
    actor               TEXT NOT NULL,                 -- a person, or the source id
    from_value          TEXT,
    to_value            TEXT,
    note                TEXT,
    payload_json        TEXT
);

CREATE INDEX ix_finding_events_finding ON finding_events(finding_id, at);
CREATE INDEX ix_finding_events_tenant  ON finding_events(tenant_id, at);

-- A decision to live with a finding for a while. It hides the finding from
-- the queue and changes nothing about observation: the source keeps
-- updating the finding, and when the exception ends the finding is back in
-- the queue if it is still seen. A review date is required, because an
-- exception nobody is due to look at again is a finding that was deleted.
CREATE TABLE finding_exceptions (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    finding_id          TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    reason              TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    approver            TEXT NOT NULL CHECK (length(trim(approver)) > 0),
    compensating_control TEXT NOT NULL CHECK (length(trim(compensating_control)) > 0),
    approved_at         TEXT NOT NULL,
    review_at           TEXT NOT NULL,
    expires_at          TEXT,
    ended_at            TEXT,
    ended_reason        TEXT
                        CHECK (ended_reason IN ('expired','withdrawn','resolved')),
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_finding_exceptions_open ON finding_exceptions(finding_id) WHERE ended_at IS NULL;
CREATE INDEX ix_finding_exceptions_client ON finding_exceptions(client_id);

-- Every engine that raises findings, per client, and when it last ran: the
-- facts data-source health is judged from. Health is computed when read, from
-- these timestamps against the cadence, so silence shows as stale rather than
-- as healthy - a row that has never been attempted is unknown, not fine.
CREATE TABLE finding_sources (
    id                  TEXT PRIMARY KEY,              -- kind:client_id, or kind:tenant_id for an organization-wide source
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           TEXT REFERENCES clients(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL,                 -- dns-scan, reports, remediation, anomaly
    expected_every_hours INTEGER NOT NULL,
    last_attempt_at     TEXT,
    last_success_at     TEXT,
    last_failure_at     TEXT,
    last_error          TEXT,
    updated_at          TEXT NOT NULL
);

CREATE INDEX ix_finding_sources_tenant ON finding_sources(tenant_id, kind);

-- Which contract a destination receives. Destinations set up before this
-- keep event.v1, the DNS-drift POST with the record text in it, until an
-- operator switches them: the receiver they were set up with reads that
-- shape. New destinations get finding.v1, which carries a finding and a
-- pointer to its evidence and never the evidence itself. See docs/WEBHOOKS.md.
ALTER TABLE webhooks ADD COLUMN payload_version TEXT NOT NULL DEFAULT 'event.v1'
    CHECK (payload_version IN ('event.v1','finding.v1'));
