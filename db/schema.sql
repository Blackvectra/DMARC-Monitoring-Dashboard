-- ============================================================================
--  DMARC Monitoring Platform — The Organization's Database
--  Target: SQLite now, PostgreSQL later. Written to migrate without redesign.
--
--  ONE FILE FOR THE ORGANIZATION, ONE FILE PER CLIENT
--
--  This file is the organization's own: who its clients are, which domains
--  belong to whom, who may sign in, what was done and by whom, and what the
--  organization has learned across its clients. Nothing in it is anybody's
--  mail.
--
--  What was learned about one client's mail - the reports receivers sent
--  about its domains, its DNS history, the changes made for it - is in that
--  client's own file, built from client-schema.sql, beside this one in a
--  folder named after it (dmarc.db keeps its clients in dmarc-clients/).
--  A client can then be backed up, handed over or erased as a file, and a
--  page scoped to one client opens that client's file and no other.
--  Migration 0019 did the split for databases that predate it; see
--  docs/CLIENT-FILES.md.
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
--
--  7. TWO TENANCY LEVELS, because the product ships both hosted and
--     self-hosted from ONE codebase:
--
--         tenants  -> the MSP (or, self-hosted, the single operator)
--         clients  -> that MSP's customers
--         domains  -> that customer's domains
--
--     Self-hosted is simply hosted with exactly one row in `tenants`. There
--     is no second schema, no second query path and no build flag: the only
--     difference is how many tenant rows exist. The moment those diverge you
--     are maintaining two products.
--
--     tenant_id is denormalized alongside client_id onto every tenant-scoped
--     table, hot ones included, for the same reason client_id is (rule 1) —
--     and for a stronger one. Self-hosted, client_id scoping is organizational
--     hygiene. Hosted, tenant_id scoping is the security boundary that stops
--     MSP A reading MSP B's book of business. A boundary enforced by
--     remembering to write a JOIN is not a boundary. Every read filters
--     tenant_id directly, and in PostgreSQL these columns are what Row Level
--     Security policies attach to.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;


-- ============================================================================
--  TENANCY
-- ============================================================================

-- The operator of the platform. Hosted, one row per MSP customer. Self-hosted,
-- exactly one row, seeded at install.
--
-- Everything below hangs off this. Code never branches on deployment mode for
-- data access; it resolves the current tenant and filters by it, which in the
-- self-hosted case happens to always be the same one.
CREATE TABLE tenants (
    id                  TEXT PRIMARY KEY,              -- UUID
    name                TEXT NOT NULL,                 -- "NextLayerSec", "Some Other MSP"
    slug                TEXT NOT NULL UNIQUE,          -- URL-safe, used in hosted routing

    -- Recorded for support and telemetry, NOT branched on for data access.
    -- If a query needs to know the deployment mode to be correct, the design
    -- has gone wrong.
    deployment_mode     TEXT NOT NULL DEFAULT 'self_hosted'
                        CHECK (deployment_mode IN ('self_hosted','hosted')),

    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('trial','active','suspended','canceled')),

    -- Where this tenant's secrets actually live. Self-hosted uses DPAPI, which
    -- is bound to a Windows user on one machine and cannot work server-side.
    -- Hosted needs envelope encryption via a KMS. The credential_ref columns
    -- elsewhere are opaque pointers so neither mode leaks into the schema.
    secret_backend      TEXT NOT NULL DEFAULT 'dpapi'
                        CHECK (secret_backend IN ('dpapi','aws_kms','azure_keyvault','gcp_kms','age')),
    secret_backend_config TEXT,                        -- JSON, non-secret coordinates only

    -- Hosted collection: each tenant needs its own inbound address, because
    -- RFC 7489 s7.1 verification records point at a specific destination
    -- domain and two MSPs cannot share one.
    collection_address  TEXT,

    -- Commercial. Deliberately NOT per-domain: the whole positioning is that
    -- a small MSP can add a client without the price moving.
    plan                TEXT,
    domain_limit        INTEGER,                       -- NULL = unlimited
    client_limit        INTEGER,                       -- NULL = unlimited
    billing_reference   TEXT,

    -- Who belongs here: the object ids of Entra security groups, matched
    -- against the groups claim of whoever signs in. Techs (entra_group_id) do
    -- the daily work: assign domains, import, run reports and checks, repair
    -- SPF and DKIM. Engineers may also move a domain up the DMARC ladder,
    -- which is the one change that can stop real mail being delivered. Admins
    -- also run the organization's settings; viewers read. NULL throughout
    -- means nobody but the master group (named in configuration) can see this
    -- organization, and a null engineer group simply means the Tech group is
    -- as far as the ladder is concerned - nobody escalates.
    entra_group_id      TEXT,
    admin_group_id      TEXT,
    viewer_group_id     TEXT,
    engineer_group_id   TEXT,

    -- White-label: the sidebar and the reports carry these.
    brand_primary_color TEXT,
    brand_logo          TEXT,                          -- data: URL, small
    provider_name       TEXT,                          -- "prepared by ..."
    brand_contact_block TEXT,                          -- report footer

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);

CREATE INDEX ix_tenants_status ON tenants(status) WHERE deleted_at IS NULL;


-- The MSP's customers. One row per billable organization.
CREATE TABLE clients (
    id                  TEXT PRIMARY KEY,              -- UUID
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,                 -- "Acme Corp"
    -- Scoped to the tenant, not global: two different MSPs may both have a
    -- customer they call "acme-corp" and neither should block the other.
    slug                TEXT NOT NULL,                 -- "acme-corp", used in report filenames + future URLs
    status              TEXT NOT NULL DEFAULT 'onboarding'
                        CHECK (status IN ('onboarding','active','suspended','offboarded')),

    -- How this client's reports reach us. Ships with 'central_mailbox'.
    collection_method   TEXT NOT NULL DEFAULT 'central_mailbox'
                        CHECK (collection_method IN ('central_mailbox','tenant_graph','imap')),

    -- Populated only when collection_method = 'tenant_graph'.
    -- Named entra_tenant_id, not tenant_id: this is Microsoft's directory GUID
    -- for the CUSTOMER's Azure AD, which has nothing to do with tenant_id
    -- above (the MSP operating this platform). Two columns called tenant_id
    -- meaning different things in one table is a bug waiting to be written.
    entra_tenant_id     TEXT,                          -- customer's Entra directory GUID
    client_app_id       TEXT,                          -- app registration in THEIR tenant
    cert_thumbprint     TEXT,
    mailbox_address     TEXT,

    -- The customer's own login: members of this group (guests in the MSP's
    -- directory, usually) see this client and nothing else, read only.
    entra_group_id      TEXT,

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
    deleted_at          TEXT,
    UNIQUE(tenant_id, slug)
);

CREATE INDEX ix_clients_tenant ON clients(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_clients_status ON clients(tenant_id, status) WHERE deleted_at IS NULL;


-- Who receives reports and alerts for a client.
CREATE TABLE client_contacts (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
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
    tenant_id               TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id               TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    -- Unique per TENANT, not globally. Report routing resolves policy-domain
    -- -> client within one tenant, so two different MSPs can each manage
    -- example.com for their own customer without colliding. Within a tenant
    -- it must still fail loudly, or reports get misrouted between that MSP's
    -- own customers.
    name                    TEXT NOT NULL,             -- "acme.com"
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

    -- The deliberate baseline window for the CURRENT stage.
    --
    -- Without these, a domain sitting at p=none looks identical whether it is
    -- on day three of an intentional two-week baseline or has been forgotten
    -- for eight months. Those need opposite responses, and a tool reporting
    -- both as "needs work" trains an operator to ignore the ones that do.
    --
    -- Set when a stage begins and again on every advance, because the question
    -- is always "how long at THIS policy", never "how long since onboarding".
    baseline_started_at     TEXT,
    baseline_days           INTEGER NOT NULL DEFAULT 14,

    -- Denormalized current state, refreshed on each DNS snapshot. Lets the
    -- client list render without touching dns_snapshots.
    current_policy          TEXT,
    current_pct             INTEGER,
    last_report_at          TEXT,

    -- When the DNS was last read, and how that attempt went. Kept here rather
    -- than in dns_snapshots because that table is content-addressed and can
    -- only hold readings that differ from the one before, and because a failed
    -- lookup must never be written as a snapshot saying the domain publishes
    -- nothing. See 0012-dns-freshness.sql.
    dns_checked_at          TEXT,
    dns_check_status        TEXT,                        -- ok / failed / nxdomain

    onboarded_at            TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    deleted_at              TEXT
);

CREATE UNIQUE INDEX ux_domains_tenant_name ON domains(tenant_id, name);
CREATE INDEX ix_domains_tenant ON domains(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_domains_client ON domains(client_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_domains_active ON domains(is_active, client_id);


-- ============================================================================
--  OPERATIONS
-- ============================================================================

-- Every message we touched. Replaces the processed-reports.json ledger.
-- Gives idempotent reprocessing and a "why is this client's data missing"
-- answer that doesn't require reading log files.
CREATE TABLE ingest_log (
    id                  INTEGER PRIMARY KEY,
    tenant_id           TEXT NOT NULL,                 -- known from the collection address
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
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Unique per tenant: the same person may legitimately hold an account
    -- with two different MSPs on a hosted deployment.
    email               TEXT NOT NULL,
    display_name        TEXT,
    is_platform_admin   INTEGER NOT NULL DEFAULT 0,    -- MSP staff, sees all clients
    auth_provider       TEXT,                          -- entra / local
    external_subject_id TEXT,                          -- oid claim from Entra
    created_at          TEXT NOT NULL,
    last_login_at       TEXT,
    deleted_at          TEXT,
    UNIQUE(tenant_id, email)
);

-- Client-scoped access. A client's own IT staff can be granted read access to
-- exactly their org without seeing the rest of the book of business.
CREATE TABLE user_client_access (
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    role                TEXT NOT NULL DEFAULT 'viewer'
                        CHECK (role IN ('viewer','operator','admin')),
    granted_at          TEXT NOT NULL,
    granted_by          TEXT,
    PRIMARY KEY (user_id, client_id)
);


-- ============================================================================
--  REMEDIATION  (where a client's DNS lives; the changes made to it are kept
--               in the client's own file, with the rest of its history)
-- ============================================================================

-- Where a client's DNS actually lives, and how we are allowed to touch it.
-- Credentials are NOT stored here. This row holds only the non-secret
-- coordinates plus an opaque pointer, and the secret itself lives in whatever
-- backend tenants.secret_backend names for the owning tenant: DPAPI under the
-- operator's profile when self-hosted, a KMS when hosted. A database file that
-- leaks must not hand over write access to a client's zone.
CREATE TABLE dns_provider_configs (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT REFERENCES domains(id) ON DELETE CASCADE,  -- NULL = all client domains

    provider            TEXT NOT NULL
                        CHECK (provider IN ('cloudflare','azuredns','route53','godaddy','manual')),
    -- Non-secret coordinates: Cloudflare zone id, Azure subscription/RG/zone.
    config_json         TEXT,
    -- Opaque pointer minted by New-CredentialRef, never the token itself.
    -- Shape: dmarc.<tenant>.<purpose>.<random>. Tenant-namespaced so two
    -- tenants cannot collide, and validated before use because it becomes a
    -- key in the backend's own namespace.
    credential_ref      TEXT,

    is_enabled          INTEGER NOT NULL DEFAULT 1,
    last_verified_at    TEXT,
    last_error          TEXT,

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    UNIQUE(client_id, domain_id, provider)
);

CREATE INDEX ix_dnsprov_client ON dns_provider_configs(client_id) WHERE is_enabled = 1;



-- ============================================================================
--  THREAT INTELLIGENCE
-- ============================================================================

-- What this operator has learned about sources impersonating their clients.
--
-- This is the asset an MSP accumulates that a single-tenant tool cannot. Every
-- client's reports contribute to it, and what is learned from one client
-- protects every other, including clients onboarded next year who were never
-- exposed to the source at all.
--
-- Derived from aggregate_records and refreshed, NOT hand-maintained: a list
-- somebody has to remember to update is a list that goes stale and then gets
-- distrusted. The one thing a human supplies is the classification, because
-- deciding that a source is a client's own marketing platform rather than an
-- attacker is a judgment, and getting it wrong in either direction is
-- expensive.
CREATE TABLE threat_indicators (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    indicator_type      TEXT NOT NULL
                        CHECK (indicator_type IN ('ip','domain','selector')),
    value               TEXT NOT NULL,

    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,

    -- Reach. client_count is the number that matters: one client is noise,
    -- several unrelated ones is somebody working through a list.
    client_count        INTEGER NOT NULL DEFAULT 0,
    domain_count        INTEGER NOT NULL DEFAULT 0,
    message_count       INTEGER NOT NULL DEFAULT 0,

    -- Whether it ever authenticated for ANY domain. A source that has never
    -- authenticated anything anywhere is behaving differently from a real
    -- service somebody set up unaligned.
    ever_authenticated  INTEGER NOT NULL DEFAULT 0,

    -- Tried to sign AS a victim domain and failed. This is the strongest
    -- single signal in the dataset: a misconfigured sender signs as itself,
    -- while a forger signs as the domain it is pretending to be.
    attempted_forgery   INTEGER NOT NULL DEFAULT 0,
    forged_selectors    TEXT,                          -- comma-separated, evidence

    -- The domains this indicator was seen against, recorded in the same pass
    -- that counts them. Held here rather than looked up when displaying,
    -- because the count is computed over a window and a separate lookup is
    -- not: the two then disagree, and a row reading "3 domain(s)" beside a
    -- list of four is the kind of contradiction that costs a report its
    -- credibility in front of a customer.
    domains             TEXT NOT NULL DEFAULT '',        -- comma-separated

    -- Supplied by a human, and the reason this table is worth keeping.
    -- Classify a source once and every client benefits, forever.
    classification      TEXT NOT NULL DEFAULT 'suspected'
                        CHECK (classification IN ('suspected','confirmed_malicious','known_good','ignored')),
    classified_by       TEXT,
    classified_at       TEXT,
    notes               TEXT,

    updated_at          TEXT NOT NULL,

    UNIQUE(tenant_id, indicator_type, value)
);

CREATE INDEX ix_indicators_reach ON threat_indicators(tenant_id, client_count DESC, message_count DESC);
CREATE INDEX ix_indicators_class ON threat_indicators(tenant_id, classification);


-- ============================================================================
--  WHAT AN ADDRESS REVERSES TO
-- ============================================================================

-- The Sources page listed addresses, and every line of it was research
-- somebody had to go and do, with the same answer every time for the same
-- address. See db/migrations/0015-source-names.sql for why this is a cache
-- rather than a column, and for what a PTR is and is not evidence of.
CREATE TABLE source_names (
    ip            TEXT PRIMARY KEY,
    reverse_name  TEXT,                              -- NULL: asked, there is none
    checked_at    TEXT NOT NULL,
    answered      INTEGER NOT NULL DEFAULT 1,        -- 0: the reverse zone did not answer
    -- Whether the name's own A/AAAA records point back at the address. Only a
    -- confirmed name may decide anything; see 0018-forward-confirmed-names.sql.
    forward_confirmed INTEGER                        -- NULL: not checked yet
);

CREATE INDEX ix_source_names_checked ON source_names(checked_at);


-- ============================================================================
--  ROW IDS THAT HOLD ACROSS CLIENT FILES
-- ============================================================================

-- aggregate_records and forensic_reports key on a rowid, and a rowid is only
-- unique inside one file: every client's file would number its rows 1, 2, 3.
-- Those ids leave the product - `dmarc export` ships each record under its id,
-- and a SIEM files documents by it, so two clients' row 7 would overwrite each
-- other - so the ids are handed out here instead, one sequence for every
-- file, and the rows are inserted with them.
--
-- Handed out inside the same transaction as the insert, on a connection that
-- has the client's file as main: SQLite commits main first, so an id becomes
-- visible here only after the row it was issued for is committed. A reader
-- that sees next_id = N can therefore rely on every row below N being in its
-- file, which is what lets an export resume from the last id it wrote.
CREATE TABLE row_ids (
    table_name          TEXT PRIMARY KEY,
    next_id             INTEGER NOT NULL
);

INSERT INTO row_ids (table_name, next_id) VALUES
  ('aggregate_records', 1),
  ('forensic_reports', 1),
  ('tls_failure_details', 1);


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
INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0002', datetime('now'), 'DNS remediation: provider configs, change plans, applied changes, SPF flatten state');
INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0003', datetime('now'), 'Tenant layer: tenants table, tenant_id on every scoped table, per-tenant uniqueness');
INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0004', datetime('now'), 'TLS reports: record the MTA-STS mode in force, so testing is distinguishable from enforce, plus source message provenance');
INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0005', datetime('now'), 'Aggregate records: keep the raw SPF and DKIM auth RESULTS, so a forged signature is distinguishable from a misconfigured sender');
INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0006', datetime('now'), 'Threat indicators: what this operator has learned about sources impersonating their clients, so knowledge from one client protects all of them');
INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0007', datetime('now'), 'Domains: record the deliberate baseline window per policy stage, so a planned rollout is distinguishable from a neglected domain');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0008', datetime('now'), 'Threat indicators: record the domain names alongside the count, so the two cannot disagree');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0009', datetime('now'), 'MTA-STS policies: what this product serves at mta-sts.<domain>, so the DNS record and the policy file cannot disagree');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0010', datetime('now'), 'Organizations: the Entra group that decides who belongs to each tenant');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0011', datetime('now'), 'Roles within an organization, customer login groups, white-label branding, and an audit log');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0012', datetime('now'), 'DNS freshness: when a domain was last read and whether that read worked, so a status chip can tell an old tick from a current one');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0013', datetime('now'), 'received_at nullable on aggregate_reports and tls_reports: it was being filled with the window end, which is a different fact and was already in the row');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0014', datetime('now'), 'engineer_group_id on tenants: splits the working role in two, so the person who repairs SPF and DKIM and the person who decides a domain may start rejecting mail can be different people');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0015', datetime('now'), 'source_names: what an address reverses to, so a report can name its senders instead of printing digits at an operator');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0016', datetime('now'), 'mta_sts_mode on dns_snapshots: the mode of the policy really being served, which DNS cannot answer, so a chip can tell enforcement from a policy in testing that requires nothing');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0017', datetime('now'), 'forensic_reports gains delivery_result, reported_by and a unique raw_hash: the table had never been written to, and storing failure reports for the first time showed what it was missing');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0018', datetime('now'), 'forward_confirmed on source_names: a reverse name decides nothing unless its own forward records point back at the address, because whoever holds an address can write any name into its PTR');

INSERT INTO schema_migrations (version, applied_at, description)
VALUES ('0019', datetime('now'), 'One file per client: each client''s reports, DNS history and changes move to a database file of its own, and this one keeps the organization, its clients, its people and its audit trail');


-- ============================================================================
--  AUDIT LOG
-- ============================================================================

-- Who did what, for the settings page and for anybody asking afterwards.
-- Not the DNS change trail, which dns_changes keeps in full; this is the
-- rest: organizations, groups, clients, providers, imports.
CREATE TABLE audit_log (
    id                  INTEGER PRIMARY KEY,
    tenant_id           TEXT,                          -- NULL for platform-wide
    at                  TEXT NOT NULL,
    actor               TEXT NOT NULL,
    action              TEXT NOT NULL,
    detail              TEXT
);

CREATE INDEX ix_audit_tenant_at ON audit_log(tenant_id, at DESC);



-- ============================================================================
--  MTA-STS POLICIES (RFC 8461)
-- ============================================================================

-- The policy this product serves for a domain, at
-- mta-sts.<domain>/.well-known/mta-sts.txt.
--
-- MTA-STS is two halves that must agree: a TXT record announcing an id, and
-- a policy file served over HTTPS with a certificate that validates. Only the
-- first is DNS. The file has to come from a web server, so the app serves it,
-- and this is what it serves - one row per domain, looked up by the Host the
-- request arrived on.
--
-- Kept rather than generated from the live MX on each request on purpose. A
-- policy that changed whenever a DNS answer changed would silently start
-- refusing mail to a server that had just been added, and senders cache it
-- for max_age either way.
CREATE TABLE mta_sts_policies (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    mode                TEXT NOT NULL DEFAULT 'testing'
                        CHECK (mode IN ('testing','enforce','none')),
    -- JSON array of mx patterns, in the order they are written to the file.
    mx_json             TEXT NOT NULL,
    max_age_seconds     INTEGER NOT NULL DEFAULT 604800,

    -- What senders see in the TXT record. Changing it is what tells them to
    -- fetch the file again, so it moves when the policy does and not before.
    policy_id           TEXT NOT NULL,

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    updated_by          TEXT
);

CREATE UNIQUE INDEX ux_mta_sts_domain ON mta_sts_policies(domain_id);
