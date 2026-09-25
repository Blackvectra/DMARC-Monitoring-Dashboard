-- ============================================================================
--  DMARC Monitoring Platform — One Client's File  (client schema 0001)
--
--  Every client has a database file of its own, holding what the platform has
--  learned about that client's mail: the reports receivers sent about its
--  domains, its DNS history and drift, and the changes made on its behalf.
--  The organization's database (schema.sql) holds who the clients are, who
--  may sign in and what was done, and nothing about anybody's mail.
--
--  Why a file each. A client's data can be backed up, handed over, restored
--  or erased as a unit. And a page scoped to one client opens that client's
--  file and no other, so a query that forgets a WHERE clause still cannot
--  show one customer another customer's mail. See docs/CLIENT-FILES.md.
--
--  The columns are the ones the single database had, tenant_id and client_id
--  included, so every query written against one database reads these
--  unchanged - and a union of several files, which is how the cross-client
--  pages read them, still says whose each row is.
--
--  No foreign key reaches outside the file. SQLite cannot enforce one across
--  databases, and a client file has to open on its own. Whose a row is, is
--  enforced by which file it is in; the keys between this file's own tables
--  are kept.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;


-- ============================================================================
--  WHOSE FILE THIS IS
-- ============================================================================

-- Written once, when the file is created, and checked every time the file is
-- opened for a client: a file copied or renamed into another client's place
-- is refused rather than read as theirs.
CREATE TABLE client_file (
    client_id           TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL
);


-- ============================================================================
--  AGGREGATE REPORTS (RUA — RFC 7489)
-- ============================================================================

-- One row per received report file. The envelope/metadata.
CREATE TABLE aggregate_reports (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

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

    -- When the message carrying this report actually arrived, or NULL when
    -- nobody knows. Nullable on purpose: a report imported from a folder or a
    -- zip has no arrival to record, and a file's timestamp is when it was
    -- copied rather than when the mail came. This used to be NOT NULL and was
    -- filled with date_end - the value already in the column beside it - so
    -- "when we got this" was a second copy of "what period this covers", and
    -- a tie-break that ordered by it separated nothing.
    received_at         TEXT,
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

    -- Denormalized for isolated queries without a join (design rules 1 and 7)
    tenant_id           TEXT NOT NULL,
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
    --
    -- The RESULT is stored alongside the domain, not just the domain. A source
    -- forging a signature as its victim produces <dkim><domain>victim.com
    -- </domain><result>fail</result></dkim>, so keeping only the domain makes a
    -- forgery attempt indistinguishable from the victim's own misconfigured
    -- service. That inverts the advice an operator is given.
    dkim_domain         TEXT,
    dkim_selector       TEXT,
    dkim_auth_result    TEXT,                          -- pass/fail/none/policy...
    spf_domain          TEXT,
    spf_auth_result     TEXT,

    -- Resolved at ingest, denormalized so sender rollups don't need a join
    sender_id           TEXT REFERENCES senders(id) ON DELETE SET NULL
);

-- The four access patterns that matter, in order of frequency:
CREATE INDEX ix_agg_rec_tenant_date   ON aggregate_records(tenant_id, date_begin DESC);
CREATE INDEX ix_agg_rec_client_date   ON aggregate_records(client_id, date_begin DESC);
CREATE INDEX ix_agg_rec_domain_date   ON aggregate_records(domain_id, date_begin DESC);
CREATE INDEX ix_agg_rec_client_ip     ON aggregate_records(client_id, source_ip);
CREATE INDEX ix_agg_rec_report        ON aggregate_records(report_id);
CREATE INDEX ix_agg_rec_sender        ON aggregate_records(sender_id) WHERE sender_id IS NOT NULL;
-- Partial index for the "what's failing" query, which is most of the product:
CREATE INDEX ix_agg_rec_failures      ON aggregate_records(tenant_id, client_id, date_begin DESC)
                                      WHERE dmarc_result = 'fail';


-- ============================================================================
--  SENDERS
-- ============================================================================

-- One row per (client, source IP). This is the sender inventory — the thing
-- the Authorization Wizard operates on and the thing that gates p=reject.
CREATE TABLE senders (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
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

CREATE INDEX ix_senders_tenant        ON senders(tenant_id);
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
    tenant_id           TEXT NOT NULL,
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

    -- What the receiver did with it: reject / quarantine / delivered / none.
    -- A report of a message that was DELIVERED anyway is a domain at p=none
    -- watching a forgery reach somebody; the same report with 'reject' is the
    -- policy working. Without this the two are indistinguishable.
    delivery_result     TEXT,

    -- Which receiver sent it, from the feedback part's User-Agent. So few
    -- receivers send these that knowing which ones do is most of what an
    -- operator needs to read the silence from the rest.
    reported_by         TEXT,

    -- The reported message's HEADERS, never its body. RFC 6591 allows a
    -- receiver to attach the whole original mail; the parser stops at the
    -- blank line that ends the headers, so a customer's correspondence is not
    -- kept on an MSP's server because somebody published a ruf address.
    raw_headers         TEXT,
    source_message_id   TEXT,
    received_at         TEXT NOT NULL,
    ingested_at         TEXT NOT NULL,

    -- SHA-256 of the report as it arrived, so importing the same mailbox
    -- twice is a no-op rather than a second copy of everybody's mail.
    raw_hash            TEXT
);

CREATE UNIQUE INDEX ux_forensic_hash ON forensic_reports(raw_hash);
CREATE INDEX ix_forensic_tenant_date ON forensic_reports(tenant_id, received_at DESC);
CREATE INDEX ix_forensic_client_date ON forensic_reports(client_id, received_at DESC);
CREATE INDEX ix_forensic_domain      ON forensic_reports(domain_id, received_at DESC);
CREATE INDEX ix_forensic_ip          ON forensic_reports(client_id, source_ip);


-- ============================================================================
--  TLS-RPT (RFC 8460)
-- ============================================================================

CREATE TABLE tls_reports (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

    org_name            TEXT,
    external_report_id  TEXT NOT NULL,
    date_begin          TEXT NOT NULL,
    date_end            TEXT NOT NULL,

    policy_type         TEXT,                          -- sts / tlsa / no-policy-found
    policy_domain       TEXT,

    -- MTA-STS mode AS THE RECEIVER FETCHED IT, not whatever DNS says today.
    -- This is the field that decides whether TLS was actually enforced during
    -- the window: 'testing' means the receiver reported failures and then
    -- delivered over plaintext anyway. A domain can sit in testing for years,
    -- generate perfectly clean reports, and be no better protected than one
    -- with no policy at all. Without this column that distinction is lost and
    -- every report looks like success.
    policy_mode         TEXT CHECK (policy_mode IN ('unknown','none','testing','enforce')),

    total_success       INTEGER NOT NULL DEFAULT 0,
    total_failure       INTEGER NOT NULL DEFAULT 0,

    source_message_id   TEXT,                          -- Graph message id, for provenance
    raw_hash            TEXT NOT NULL,

    -- Nullable for the same reason as aggregate_reports: NULL means nobody
    -- knows when this arrived, which is the truth for a file import.
    received_at         TEXT,
    ingested_at         TEXT NOT NULL,

    UNIQUE(org_name, external_report_id, domain_id)
);

CREATE INDEX ix_tls_client_date ON tls_reports(client_id, date_begin DESC);


CREATE TABLE tls_failure_details (
    id                      INTEGER PRIMARY KEY,
    tls_report_id           TEXT NOT NULL REFERENCES tls_reports(id) ON DELETE CASCADE,
    tenant_id               TEXT NOT NULL,
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
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

    -- captured_at is when this state was FIRST seen; last_seen_at is when it
    -- was last observed. Both are needed because the rows are deduplicated by
    -- content: a domain that goes A -> B -> A inserts no third row, and A
    -- keeps its original captured_at, so ordering by captured_at would name B
    -- as the current state of a domain publishing A.
    --
    -- last_seen_seq, not last_seen_at, is what "current" is picked by. No
    -- timestamp can do that job: two readings stored in the same tick tie, and
    -- the tie falls to insertion order, which is backwards for a revert - the
    -- current row is the older one. Whatever resolution the clock has, a
    -- machine fast enough to beat it exists. The counter is bumped on every
    -- observation of a domain, whether it inserts a row or touches one.
    captured_at         TEXT NOT NULL,
    last_seen_at        TEXT,
    last_seen_seq       INTEGER,

    spf_record          TEXT,
    dmarc_record        TEXT,
    mta_sts_record      TEXT,
    bimi_record         TEXT,
    tls_rpt_record      TEXT,
    mx_records          TEXT,                          -- JSON array, ordered by preference

    -- Parsed convenience fields so queries don't regex TEXT columns
    --
    -- spf_record_count exists because more than one v=spf1 record at an apex
    -- is a fault on its own - RFC 7208 section 4.5 has the receiver return
    -- permerror, so every SPF check fails however correct either record is -
    -- and spf_record above holds one of them.
    --
    -- DKIM has no column here: dkim_selectors below records each observed
    -- selector with its own key_status and last_seen, and a count in this row
    -- would be a second copy of that, free to disagree with it.
    spf_record_count    INTEGER,
    spf_lookup_count    INTEGER,
    spf_all_mechanism   TEXT,                          -- -all / ~all / ?all / missing
    dmarc_p             TEXT,
    dmarc_sp            TEXT,
    dmarc_pct           INTEGER,
    dmarc_adkim         TEXT,
    dmarc_aspf          TEXT,
    dmarc_rua           TEXT,
    dmarc_ruf           TEXT,

    -- The mode of the MTA-STS policy really being served, which is the one
    -- thing about MTA-STS that DNS cannot answer: mta_sts_record above carries
    -- an id and nothing else, and the mode lives in a file fetched over HTTPS
    -- from mta-sts.<domain>. Without this a snapshot can say a domain
    -- announces a policy and cannot say whether that policy requires anything,
    -- and a policy in testing requires nothing at all.
    --
    -- One of 'enforce', 'testing', 'none', 'unreachable' (announced, and the
    -- file could not be fetched or did not parse), or NULL for nobody asked.
    -- Deliberately outside content_hash: the file is not a DNS record, it is
    -- an HTTPS fetch that can time out on its own schedule, and hashing it
    -- would let a flaky minute of network announce that the zone was edited.
    -- It is written onto whichever row is current when it is observed, and
    -- left alone when it is not.
    mta_sts_mode        TEXT,

    content_hash        TEXT NOT NULL                  -- SHA-256 of all record values
);

CREATE INDEX ix_dns_snap_domain ON dns_snapshots(domain_id, captured_at DESC);
CREATE INDEX ix_dns_snap_latest ON dns_snapshots(domain_id, last_seen_seq DESC);
CREATE UNIQUE INDEX ux_dns_snap_dedup ON dns_snapshots(domain_id, content_hash);


-- Computed diffs between consecutive snapshots. This is the feature most
-- competitors do badly and the one that catches a client silently breaking
-- their own SPF at 2am.
CREATE TABLE dns_drift_events (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

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

CREATE INDEX ix_drift_tenant_date ON dns_drift_events(tenant_id, detected_at DESC);
CREATE INDEX ix_drift_client_date ON dns_drift_events(client_id, detected_at DESC);
CREATE INDEX ix_drift_unack       ON dns_drift_events(client_id, detected_at DESC) WHERE acknowledged_at IS NULL;


-- Discovered DKIM keys per domain.
CREATE TABLE dkim_selectors (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,
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
    tenant_id           TEXT NOT NULL,
    client_id               TEXT NOT NULL,
    domain_id               TEXT NOT NULL,
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
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,
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
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,
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
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT,

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


-- ============================================================================
--  REMEDIATION  (DNS changes this tool planned and published for this client)
-- ============================================================================

-- A planned change, whether or not it was ever applied. Plans are kept even
-- when refused: "we could not authorize this sender because the SPF record is
-- at the lookup cap" is itself the finding an operator needs to act on.
CREATE TABLE dns_change_plans (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,
    sender_id           TEXT REFERENCES senders(id) ON DELETE SET NULL,

    change_type         TEXT NOT NULL
                        CHECK (change_type IN ('spf-include-add','spf-include-remove','spf-flatten',
                                               'dkim-publish','dmarc-policy','mta-sts','bimi','tls-rpt')),
    record_name         TEXT NOT NULL,
    record_type         TEXT NOT NULL,
    current_value       TEXT,
    proposed_value      TEXT,

    -- Why the plan is or is not safe. Blockers are hard refusals, warnings
    -- are things the operator should read before confirming.
    is_safe             INTEGER NOT NULL DEFAULT 0,
    is_noop             INTEGER NOT NULL DEFAULT 0,
    blockers_json       TEXT,
    warnings_json       TEXT,
    lookups_before      INTEGER,
    lookups_after       INTEGER,
    summary             TEXT,

    status              TEXT NOT NULL DEFAULT 'proposed'
                        CHECK (status IN ('proposed','refused','applied','rolled_back','superseded','canceled')),

    created_at          TEXT NOT NULL,
    created_by          TEXT
);

CREATE INDEX ix_plan_client_date ON dns_change_plans(client_id, created_at DESC);
CREATE INDEX ix_plan_domain      ON dns_change_plans(domain_id, created_at DESC);
CREATE INDEX ix_plan_open        ON dns_change_plans(client_id) WHERE status = 'proposed';


-- What was actually written. Separate from the plan because a plan can be
-- applied, rolled back and re-applied, and because this table is the billing
-- and compliance evidence: who changed a client's DNS, when, and why.
--
-- previous_value is captured from the live zone immediately before the write,
-- not copied from the plan, so it is a trustworthy rollback target even if
-- the plan had gone stale.
CREATE TABLE dns_changes (
    id                  TEXT PRIMARY KEY,
    plan_id             TEXT REFERENCES dns_change_plans(id) ON DELETE SET NULL,
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

    record_name         TEXT NOT NULL,
    record_type         TEXT NOT NULL,
    previous_value      TEXT,
    new_value           TEXT,

    provider            TEXT NOT NULL,
    provider_record_id  TEXT,

    applied_at          TEXT NOT NULL,
    applied_by          TEXT,
    reason              TEXT,

    -- A successful API call means accepted, not visible. Until this is 1 the
    -- client's mail is still behaving as it did before the change.
    is_propagated       INTEGER NOT NULL DEFAULT 0,
    propagated_at       TEXT,
    propagation_error   TEXT,

    rolled_back_at      TEXT,
    rolled_back_by      TEXT,
    rollback_reason     TEXT
);

CREATE INDEX ix_change_tenant_date ON dns_changes(tenant_id, applied_at DESC);
CREATE INDEX ix_change_client_date ON dns_changes(client_id, applied_at DESC);
CREATE INDEX ix_change_domain      ON dns_changes(domain_id, applied_at DESC);
CREATE INDEX ix_change_unpropagated ON dns_changes(client_id) WHERE is_propagated = 0 AND rolled_back_at IS NULL;


-- Flattened SPF records go stale when a provider changes its sending ranges,
-- and stale means legitimate mail starts failing with no obvious cause. This
-- tracks what was flattened from what, and when it must be refreshed.
CREATE TABLE spf_flatten_state (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    domain_id           TEXT NOT NULL,

    flattened_includes  TEXT NOT NULL,   -- JSON array of the include domains inlined
    resolved_ips        TEXT NOT NULL,   -- JSON array of the ip4/ip6 mechanisms produced
    preserved_terms     TEXT,            -- JSON array of a/mx/ptr kept as-is
    flattened_value     TEXT NOT NULL,

    lookups_before      INTEGER,
    lookups_after       INTEGER,

    flattened_at        TEXT NOT NULL,
    refresh_by          TEXT NOT NULL,
    last_refreshed_at   TEXT,
    is_stale            INTEGER NOT NULL DEFAULT 0,

    UNIQUE(domain_id)
);

CREATE INDEX ix_flatten_due ON spf_flatten_state(refresh_by) WHERE is_stale = 0;


-- ============================================================================
--  CONVENIENCE VIEWS
-- ============================================================================

-- Daily pass-rate rollup. Backs the trend chart without scanning raw records.
CREATE VIEW v_daily_rollup AS
SELECT
    tenant_id,
    client_id,
    domain_id,
    substr(date_begin, 1, 10)                                           AS day,
    SUM(message_count)                                                  AS total_messages,
    SUM(CASE WHEN dmarc_result = 'pass' THEN message_count ELSE 0 END)  AS passing,
    SUM(CASE WHEN dmarc_result = 'fail' THEN message_count ELSE 0 END)  AS failing,
    COUNT(DISTINCT source_ip)                                           AS distinct_sources
FROM aggregate_records
GROUP BY tenant_id, client_id, domain_id, substr(date_begin, 1, 10);


-- ============================================================================
--  SCHEMA VERSIONING
-- ============================================================================

-- Client files are versioned apart from the organization's database: a
-- change to one does not touch the other, and each file records what it has.
-- Later changes land in db/client-migrations and are applied to every file.
CREATE TABLE schema_migrations (
    version             TEXT PRIMARY KEY,
    applied_at          TEXT NOT NULL,
    description         TEXT
);

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0001', datetime('now'), 'One file per client: the tables the single database held about each client''s mail as of 0018');
