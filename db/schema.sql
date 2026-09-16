-- ============================================================================
--  DMARC Monitoring Platform — Core Schema  (v1)
--  Target: SQLite now, PostgreSQL later. Written to migrate without redesign.
--
--  DESIGN RULES (these are the expensive-to-change decisions)
--
--  1. client_id on EVERY tenant-scoped table, including denormalized onto the
--     high-volume child tables. Never reach a tenant's data through a join.
--     This is what makes row-level isolation enforceable and cheap, and what
--     makes "5 clients" -> "5,000 clients" a non-event.
--
--  2. TEXT UUID primary keys on entity tables (clients, domains, senders...)
--     because those IDs leak into URLs, report filenames, and API responses,
--     and must survive a database migration or a merge of two deployments.
--
--  3. INTEGER PRIMARY KEY (rowid alias) on the two hot append-only tables
--     (aggregate_records, forensic_reports). At 20M+ rows a random TEXT UUID
--     destroys insert locality and bloats every index. Postgres equivalent is
--     BIGINT GENERATED ALWAYS AS IDENTITY. These rows are never referenced
--     externally, so they don't need a stable public identifier.
--
--  4. collection_method is a column, not an assumption. Central-mailbox
--     (MSP model, RFC 7489 s7.1 external destination verification) ships
--     first; per-tenant Graph app is the enterprise-customer path. The ingest
--     pipeline must not hardcode either.
--
--  5. UTC everywhere, ISO-8601 TEXT in SQLite (sorts lexicographically,
--     maps to timestamptz in Postgres). No local time in the database ever.
--
--  6. Soft delete (deleted_at) on client-owned entities. An MSP that loses a
--     client still needs their history for the final invoice and for the
--     "we told you so" conversation.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;


-- ============================================================================
--  TENANCY
-- ============================================================================

-- The MSP's customers. One row per billable organization.
CREATE TABLE clients (
    id                  TEXT PRIMARY KEY,              -- UUID
    name                TEXT NOT NULL,                 -- "Acme Corp"
    slug                TEXT NOT NULL UNIQUE,          -- "acme-corp", used in report filenames + future URLs
    status              TEXT NOT NULL DEFAULT 'onboarding'
                        CHECK (status IN ('onboarding','active','suspended','offboarded')),

    -- How this client's reports reach us. Ships with 'central_mailbox'.
    collection_method   TEXT NOT NULL DEFAULT 'central_mailbox'
                        CHECK (collection_method IN ('central_mailbox','tenant_graph','imap')),

    -- Populated only when collection_method = 'tenant_graph'
    tenant_id           TEXT,                          -- Entra tenant GUID
    client_app_id       TEXT,                          -- app registration in THEIR tenant
    cert_thumbprint     TEXT,
    mailbox_address     TEXT,

    -- White-label report branding
    brand_logo_path     TEXT,
    brand_primary_color TEXT DEFAULT '#3FB950',
    brand_contact_block TEXT,                          -- markdown, rendered into report footer

    -- Commercial
    billing_reference   TEXT,                          -- your invoicing system's ID
    contract_start      TEXT,                          -- ISO-8601 date
    notes               TEXT,

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);

CREATE INDEX ix_clients_status ON clients(status) WHERE deleted_at IS NULL;


-- Who receives reports and alerts for a client.
CREATE TABLE client_contacts (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    email               TEXT NOT NULL,
    display_name        TEXT,
    role                TEXT,                          -- "IT Director", "Security"
    receives_digest     INTEGER NOT NULL DEFAULT 1,    -- monthly report
    receives_alerts     INTEGER NOT NULL DEFAULT 0,    -- real-time failures
    created_at          TEXT NOT NULL,
    deleted_at          TEXT,
    UNIQUE(client_id, email)
);

CREATE INDEX ix_client_contacts_client ON client_contacts(client_id) WHERE deleted_at IS NULL;


-- Per-client overrides of global settings. Anything absent falls back to the
-- platform default. Kept as key/value rather than columns so adding a knob
-- doesn't require a migration.
CREATE TABLE client_settings (
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    key                 TEXT NOT NULL,                 -- 'alert_threshold_pct', 'digest_day_of_month'
    value               TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    PRIMARY KEY (client_id, key)
);


-- ============================================================================
--  DOMAINS
-- ============================================================================

-- Domains under management. `name` is globally unique because report routing
-- resolves a policy domain -> client with no other context available. Two
-- clients claiming the same domain is a real-world misconfiguration that must
-- fail loudly at onboarding rather than silently misroute someone's mail data.
CREATE TABLE domains (
    id                      TEXT PRIMARY KEY,          -- UUID
    client_id               TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL UNIQUE,      -- "acme.com"
    is_active               INTEGER NOT NULL DEFAULT 1,

    -- RFC 7489 s7.1 external destination verification. For central_mailbox
    -- collection we must publish  <domain>._report._dmarc.<our-domain>  TXT
    -- "v=DMARC1"  or receivers will refuse to send us their reports.
    report_verification_published    INTEGER NOT NULL DEFAULT 0,
    report_verification_checked_at   TEXT,
    report_verification_error        TEXT,

    -- Where we're driving them. Drives the enforcement roadmap + the invoice
    -- narrative ("we moved you from none to quarantine this quarter").
    policy_target           TEXT NOT NULL DEFAULT 'reject'
                            CHECK (policy_target IN ('none','quarantine','reject')),

    -- Denormalized current state, refreshed on each DNS snapshot. Lets the
    -- client list render without touching dns_snapshots.
    current_policy          TEXT,
    current_pct             INTEGER,
    last_report_at          TEXT,

    onboarded_at            TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    deleted_at              TEXT
);

CREATE INDEX ix_domains_client ON domains(client_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_domains_active ON domains(is_active, client_id);


-- ============================================================================
--  AGGREGATE REPORTS (RUA — RFC 7489)
-- ============================================================================

-- One row per received report file. The envelope/metadata.
CREATE TABLE aggregate_reports (
    id                  TEXT PRIMARY KEY,              -- UUID
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    -- Reporter identity + their report id. Dedup key.
    org_name            TEXT NOT NULL,                 -- "google.com"
    org_email           TEXT,
    external_report_id  TEXT NOT NULL,                 -- reporter's <report_id>

    date_begin          TEXT NOT NULL,                 -- ISO-8601 UTC
    date_end            TEXT NOT NULL,

    -- <policy_published> as the reporter saw it. Historical value: this is how
    -- you prove a policy was live on a given date.
    policy_p            TEXT,
    policy_sp           TEXT,
    policy_pct          INTEGER DEFAULT 100,
    policy_adkim        TEXT DEFAULT 'r',
    policy_aspf         TEXT DEFAULT 'r',

    -- Provenance
    source_message_id   TEXT,                          -- Graph message id
    raw_hash            TEXT NOT NULL,                 -- SHA-256 of decompressed XML
    received_at         TEXT NOT NULL,
    ingested_at         TEXT NOT NULL,

    -- Dedup: a reporter resending the same report, or the same message being
    -- reprocessed after a parse failure, must not double-count.
    UNIQUE(org_name, external_report_id, domain_id)
);

CREATE INDEX ix_agg_reports_client_date ON aggregate_reports(client_id, date_begin DESC);
CREATE INDEX ix_agg_reports_domain_date ON aggregate_reports(domain_id, date_begin DESC);
CREATE INDEX ix_agg_reports_hash        ON aggregate_reports(raw_hash);


-- The <record> rows. THE hot table — expect this to dominate storage.
-- Rough sizing: 50 clients x 10 domains x ~500 rows/day = 250k rows/day,
-- ~22M rows at 90-day retention. SQLite is comfortable here with these
-- indexes; Postgres is comfortable an order of magnitude past it.
CREATE TABLE aggregate_records (
    id                  INTEGER PRIMARY KEY,           -- rowid alias, see design rule 3
    report_id           TEXT NOT NULL REFERENCES aggregate_reports(id) ON DELETE CASCADE,

    -- Denormalized for tenant-isolated queries without a join (design rule 1)
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,
    date_begin          TEXT NOT NULL,                 -- denormalized: time-range scans skip the join

    source_ip           TEXT NOT NULL,
    source_ip_version   INTEGER NOT NULL DEFAULT 4 CHECK (source_ip_version IN (4,6)),
    message_count       INTEGER NOT NULL DEFAULT 0,

    -- <policy_evaluated>
    disposition         TEXT CHECK (disposition IN ('none','quarantine','reject')),
    dkim_result         TEXT,                          -- pass/fail
    spf_result          TEXT,
    dmarc_result        TEXT NOT NULL,                 -- derived: pass if either aligned
    fail_reason         TEXT,                          -- dkim-only-fail / spf-only-fail / both-fail
    override_reason     TEXT,                          -- forwarded, mailing_list, trusted_forwarder...
    override_comment    TEXT,

    -- <identifiers>
    header_from         TEXT,
    envelope_from       TEXT,
    envelope_to         TEXT,
    is_subdomain        INTEGER NOT NULL DEFAULT 0,

    -- <auth_results>
    dkim_domain         TEXT,
    dkim_selector       TEXT,
    spf_domain          TEXT,

    -- Resolved at ingest, denormalized so sender rollups don't need a join
    sender_id           TEXT REFERENCES senders(id) ON DELETE SET NULL
);

-- The four access patterns that matter, in order of frequency:
CREATE INDEX ix_agg_rec_client_date   ON aggregate_records(client_id, date_begin DESC);
CREATE INDEX ix_agg_rec_domain_date   ON aggregate_records(domain_id, date_begin DESC);
CREATE INDEX ix_agg_rec_client_ip     ON aggregate_records(client_id, source_ip);
CREATE INDEX ix_agg_rec_report        ON aggregate_records(report_id);
CREATE INDEX ix_agg_rec_sender        ON aggregate_records(sender_id) WHERE sender_id IS NOT NULL;
-- Partial index for the "what's failing" query, which is most of the product:
CREATE INDEX ix_agg_rec_failures      ON aggregate_records(client_id, date_begin DESC)
                                      WHERE dmarc_result = 'fail';


-- ============================================================================
--  SENDERS
-- ============================================================================

-- One row per (client, source IP). This is the sender inventory — the thing
-- the Authorization Wizard operates on and the thing that gates p=reject.
CREATE TABLE senders (
    id                  TEXT PRIMARY KEY,              -- UUID
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    source_ip           TEXT NOT NULL,

    -- Catalog classification (sender-catalog.json)
    service_id          TEXT,                          -- 'sendgrid', 'm365', NULL if unknown
    service_confidence  TEXT CHECK (service_confidence IN ('high','medium','none')),

    -- Enrichment
    ptr_hostname        TEXT,
    asn                 INTEGER,
    asn_org             TEXT,
    geo_country         TEXT,
    geo_city            TEXT,

    -- Operator decisions. This is billable work product — who approved what,
    -- when, and why. Needed for the audit trail AND the invoice narrative.
    is_approved         INTEGER NOT NULL DEFAULT 0,
    approved_by         TEXT,
    approved_at         TEXT,
    approval_notes      TEXT,

    -- Remediation tracking (the differentiator: closing the loop)
    remediation_status  TEXT DEFAULT 'none'
                        CHECK (remediation_status IN ('none','identified','dns_pending','dns_published','verified','wont_fix')),
    remediation_notes   TEXT,

    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,

    UNIQUE(client_id, source_ip)
);

CREATE INDEX ix_senders_client        ON senders(client_id);
CREATE INDEX ix_senders_service       ON senders(client_id, service_id);
CREATE INDEX ix_senders_unapproved    ON senders(client_id) WHERE is_approved = 0;


-- ============================================================================
--  FORENSIC REPORTS (RUF — RFC 6591 ARF)
-- ============================================================================

-- Low volume relative to aggregate, but privacy-sensitive: contains real
-- message headers. Retention is deliberately separate from aggregate data.
CREATE TABLE forensic_reports (
    id                  INTEGER PRIMARY KEY,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

    arrival_date        TEXT,
    source_ip           TEXT,
    return_path         TEXT,
    header_from         TEXT,
    subject             TEXT,
    message_id          TEXT,

    dkim_result         TEXT,
    spf_result          TEXT,
    dkim_domain         TEXT,
    auth_failure_type   TEXT,                          -- dmarc / spf / dkim

    raw_headers         TEXT,                          -- full rfc822 part, redactable
    source_message_id   TEXT,
    received_at         TEXT NOT NULL,
    ingested_at         TEXT NOT NULL
);

CREATE INDEX ix_forensic_client_date ON forensic_reports(client_id, received_at DESC);
CREATE INDEX ix_forensic_domain      ON forensic_reports(domain_id, received_at DESC);
CREATE INDEX ix_forensic_ip          ON forensic_reports(client_id, source_ip);


-- ============================================================================
--  TLS-RPT (RFC 8460)
-- ============================================================================

CREATE TABLE tls_reports (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    org_name            TEXT,
    external_report_id  TEXT NOT NULL,
    date_begin          TEXT NOT NULL,
    date_end            TEXT NOT NULL,

    policy_type         TEXT,                          -- sts / tlsa / no-policy-found
    policy_domain       TEXT,
    total_success       INTEGER NOT NULL DEFAULT 0,
    total_failure       INTEGER NOT NULL DEFAULT 0,

    raw_hash            TEXT NOT NULL,
    received_at         TEXT NOT NULL,
    ingested_at         TEXT NOT NULL,

    UNIQUE(org_name, external_report_id, domain_id)
);

CREATE INDEX ix_tls_client_date ON tls_reports(client_id, date_begin DESC);


CREATE TABLE tls_failure_details (
    id                      INTEGER PRIMARY KEY,
    tls_report_id           TEXT NOT NULL REFERENCES tls_reports(id) ON DELETE CASCADE,
    client_id               TEXT NOT NULL,
    result_type             TEXT,                      -- starttls-not-supported, certificate-expired...
    sending_mta_ip          TEXT,
    receiving_mx_hostname   TEXT,
    receiving_ip            TEXT,
    failed_session_count    INTEGER NOT NULL DEFAULT 0,
    additional_info         TEXT
);

CREATE INDEX ix_tls_fail_report ON tls_failure_details(tls_report_id);


-- ============================================================================
--  DNS STATE + DRIFT
-- ============================================================================

-- Point-in-time capture of a domain's published DNS. One row per CHANGE, not
-- per poll — content_hash gates the insert. That makes this table a change
-- log you can replay, not a firehose.
CREATE TABLE dns_snapshots (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    captured_at         TEXT NOT NULL,

    spf_record          TEXT,
    dmarc_record        TEXT,
    mta_sts_record      TEXT,
    bimi_record         TEXT,
    tls_rpt_record      TEXT,
    mx_records          TEXT,                          -- JSON array, ordered by preference

    -- Parsed convenience fields so queries don't regex TEXT columns
    spf_lookup_count    INTEGER,
    spf_all_mechanism   TEXT,                          -- -all / ~all / ?all / missing
    dmarc_p             TEXT,
    dmarc_sp            TEXT,
    dmarc_pct           INTEGER,
    dmarc_adkim         TEXT,
    dmarc_aspf          TEXT,
    dmarc_rua           TEXT,
    dmarc_ruf           TEXT,

    content_hash        TEXT NOT NULL                  -- SHA-256 of all record values
);

CREATE INDEX ix_dns_snap_domain ON dns_snapshots(domain_id, captured_at DESC);
CREATE UNIQUE INDEX ux_dns_snap_dedup ON dns_snapshots(domain_id, content_hash);


-- Computed diffs between consecutive snapshots. This is the feature most
-- competitors do badly and the one that catches a client silently breaking
-- their own SPF at 2am.
CREATE TABLE dns_drift_events (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    detected_at         TEXT NOT NULL,
    record_type         TEXT NOT NULL CHECK (record_type IN ('spf','dmarc','mta-sts','bimi','tls-rpt','mx','dkim')),
    old_value           TEXT,
    new_value           TEXT,
    summary             TEXT NOT NULL,                 -- "SPF: -include:mailchimp.com"
    severity            TEXT NOT NULL DEFAULT 'info'
                        CHECK (severity IN ('info','warning','critical')),

    -- An MSP needs to distinguish "change I made" from "change the client made
    -- without telling me". That distinction is the whole value of this table.
    was_expected        INTEGER NOT NULL DEFAULT 0,
    acknowledged_at     TEXT,
    acknowledged_by     TEXT,
    acknowledgement_note TEXT
);

CREATE INDEX ix_drift_client_date ON dns_drift_events(client_id, detected_at DESC);
CREATE INDEX ix_drift_unack       ON dns_drift_events(client_id, detected_at DESC) WHERE acknowledged_at IS NULL;


-- Discovered DKIM keys per domain.
CREATE TABLE dkim_selectors (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    selector            TEXT NOT NULL,
    algorithm           TEXT,
    key_length          INTEGER,
    key_status          TEXT,                          -- strong / acceptable / WEAK / REVOKED
    flags               TEXT,
    raw_record          TEXT,                          -- key material truncated
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    UNIQUE(domain_id, selector)
);

CREATE INDEX ix_dkim_client ON dkim_selectors(client_id);


-- ============================================================================
--  ANALYSIS OUTPUT
-- ============================================================================

-- Daily compliance snapshot. Precomputed so the dashboard and the monthly
-- report never recompute 90 days of aggregate on demand, and so month-over-
-- month deltas are a two-row lookup.
CREATE TABLE compliance_scores (
    id                      TEXT PRIMARY KEY,
    client_id               TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id               TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    score_date              TEXT NOT NULL,             -- ISO-8601 date

    score                   INTEGER NOT NULL,          -- 0-100
    policy                  TEXT,
    pass_rate               REAL,
    total_messages          INTEGER NOT NULL DEFAULT 0,
    passing_messages        INTEGER NOT NULL DEFAULT 0,
    failing_messages        INTEGER NOT NULL DEFAULT 0,
    unknown_sender_failures INTEGER NOT NULL DEFAULT 0,
    details_json            TEXT,                      -- score component breakdown

    computed_at             TEXT NOT NULL,
    UNIQUE(domain_id, score_date)
);

CREATE INDEX ix_scores_client_date ON compliance_scores(client_id, score_date DESC);


-- "Can this domain move to the next policy level, and if not, what's blocking?"
-- This is the client-facing roadmap that justifies the retainer.
CREATE TABLE enforcement_assessments (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    assessed_at         TEXT NOT NULL,

    current_policy      TEXT,
    target_policy       TEXT,
    recommendation      TEXT,                          -- advance-to-X / not-ready / fully-optimized
    ready_to_advance    INTEGER NOT NULL DEFAULT 0,
    pass_rate           REAL,
    total_messages      INTEGER,
    blockers_json       TEXT,                          -- JSON array of blocker strings
    reasons_json        TEXT
);

CREATE INDEX ix_enforce_domain ON enforcement_assessments(domain_id, assessed_at DESC);


-- Lookalike domains observed in the wild.
CREATE TABLE cousin_domains (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    cousin_domain       TEXT NOT NULL,
    edit_distance       INTEGER,
    detection_method    TEXT,                          -- levenshtein / homoglyph / tld-swap
    message_count       INTEGER NOT NULL DEFAULT 0,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    is_dismissed        INTEGER NOT NULL DEFAULT 0,
    dismissed_reason    TEXT,
    UNIQUE(domain_id, cousin_domain)
);

CREATE INDEX ix_cousin_client ON cousin_domains(client_id) WHERE is_dismissed = 0;


-- ============================================================================
--  OPERATIONS
-- ============================================================================

-- Fired alerts. Exists for dedup (don't page twice for the same thing in an
-- hour) and for the SLA conversation ("we alerted you at 14:22").
CREATE TABLE alerts (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT REFERENCES domains(id) ON DELETE CASCADE,

    alert_type          TEXT NOT NULL,                 -- failure_rate / new_sender / dns_drift / volume_anomaly / cert_expiry
    severity            TEXT NOT NULL DEFAULT 'warning'
                        CHECK (severity IN ('info','warning','critical')),
    title               TEXT NOT NULL,
    payload_json        TEXT,

    fired_at            TEXT NOT NULL,
    resolved_at         TEXT,
    notified_channels   TEXT,                          -- JSON array: ["email","teams"]
    dedup_key           TEXT NOT NULL                  -- type + domain + bucket, for suppression
);

CREATE INDEX ix_alerts_client_date ON alerts(client_id, fired_at DESC);
CREATE INDEX ix_alerts_dedup       ON alerts(dedup_key, fired_at DESC);
CREATE INDEX ix_alerts_open        ON alerts(client_id) WHERE resolved_at IS NULL;


-- Every message we touched. Replaces the processed-reports.json ledger.
-- Gives idempotent reprocessing and a "why is this client's data missing"
-- answer that doesn't require reading log files.
CREATE TABLE ingest_log (
    id                  INTEGER PRIMARY KEY,
    client_id           TEXT,                          -- NULL until domain->client resolves
    source_message_id   TEXT NOT NULL,
    report_type         TEXT,                          -- rua / ruf / tlsrpt / unknown
    status              TEXT NOT NULL
                        CHECK (status IN ('parsed','duplicate','unmapped_domain','parse_error','extract_error')),
    error_message       TEXT,
    file_hash           TEXT,
    attachment_name     TEXT,
    processed_at        TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_ingest_message ON ingest_log(source_message_id, file_hash);
CREATE INDEX ix_ingest_status         ON ingest_log(status, processed_at DESC);
CREATE INDEX ix_ingest_unmapped       ON ingest_log(processed_at DESC) WHERE status = 'unmapped_domain';


-- ============================================================================
--  IDENTITY  (defined now, unused until there's a web tier — costs nothing
--             to have, painful to retrofit once data exists)
-- ============================================================================

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    display_name        TEXT,
    is_platform_admin   INTEGER NOT NULL DEFAULT 0,    -- MSP staff, sees all clients
    auth_provider       TEXT,                          -- entra / local
    external_subject_id TEXT,                          -- oid claim from Entra
    created_at          TEXT NOT NULL,
    last_login_at       TEXT,
    deleted_at          TEXT
);

-- Client-scoped access. A client's own IT staff can be granted read access to
-- exactly their org without seeing the rest of the book of business.
CREATE TABLE user_client_access (
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    role                TEXT NOT NULL DEFAULT 'viewer'
                        CHECK (role IN ('viewer','operator','admin')),
    granted_at          TEXT NOT NULL,
    granted_by          TEXT,
    PRIMARY KEY (user_id, client_id)
);


-- ============================================================================
--  SCHEMA VERSIONING
-- ============================================================================

CREATE TABLE schema_migrations (
    version             TEXT PRIMARY KEY,
    applied_at          TEXT NOT NULL,
    description         TEXT
);

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0001', datetime('now'), 'Initial multi-tenant schema');


-- ============================================================================
--  CONVENIENCE VIEWS
-- ============================================================================

-- Current posture per domain, for the client list / sidebar.
CREATE VIEW v_domain_posture AS
SELECT
    d.id                AS domain_id,
    d.client_id,
    c.name              AS client_name,
    d.name              AS domain_name,
    d.current_policy,
    d.current_pct,
    d.policy_target,
    d.last_report_at,
    s.score             AS latest_score,
    s.pass_rate         AS latest_pass_rate,
    s.score_date        AS score_as_of,
    (SELECT COUNT(*) FROM senders sn
       WHERE sn.client_id = d.client_id AND sn.is_approved = 0)      AS unapproved_senders,
    (SELECT COUNT(*) FROM dns_drift_events de
       WHERE de.domain_id = d.id AND de.acknowledged_at IS NULL)     AS unacked_drift
FROM domains d
JOIN clients c ON c.id = d.client_id
LEFT JOIN compliance_scores s
       ON s.domain_id = d.id
      AND s.score_date = (SELECT MAX(score_date) FROM compliance_scores WHERE domain_id = d.id)
WHERE d.deleted_at IS NULL AND c.deleted_at IS NULL;


-- Daily pass-rate rollup. Backs the trend chart without scanning raw records.
CREATE VIEW v_daily_rollup AS
SELECT
    client_id,
    domain_id,
    substr(date_begin, 1, 10)                                           AS day,
    SUM(message_count)                                                  AS total_messages,
    SUM(CASE WHEN dmarc_result = 'pass' THEN message_count ELSE 0 END)  AS passing,
    SUM(CASE WHEN dmarc_result = 'fail' THEN message_count ELSE 0 END)  AS failing,
    COUNT(DISTINCT source_ip)                                           AS distinct_sources
FROM aggregate_records
GROUP BY client_id, domain_id, substr(date_begin, 1, 10);
