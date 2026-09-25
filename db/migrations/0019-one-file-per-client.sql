-- One file per client.
--
-- Everything this database held about a client's mail moves to a file of the
-- client's own, in a folder beside this one: dmarc.db keeps its clients in
-- dmarc-clients/. What stays here is the organization's: its clients, their
-- domains, its people, its audit trail, and what it has learned across
-- clients. See db/client-schema.sql and docs/CLIENT-FILES.md.
--
-- The rows are copied out BEFORE this runs, by ClientFileSplit, which writes
-- each client's file, counts every table in both places and stops if they
-- disagree. This is the part that can be said in SQL: the tables go.
--
-- A copy of the database as it was is left beside it before anything moves
-- (dmarc.pre-0019.db), because this is the one migration that moves data
-- rather than adding somewhere to put it.

-- Row ids that must stay unique across files carry on from where this
-- database had got to: see row_ids in schema.sql. The rows copied out keep
-- the ids they have here, which were unique across the whole database.
CREATE TABLE row_ids (
    table_name          TEXT PRIMARY KEY,
    next_id             INTEGER NOT NULL
);

INSERT INTO row_ids (table_name, next_id)
SELECT 'aggregate_records', COALESCE(MAX(id), 0) + 1 FROM aggregate_records;
INSERT INTO row_ids (table_name, next_id)
SELECT 'forensic_reports', COALESCE(MAX(id), 0) + 1 FROM forensic_reports;
INSERT INTO row_ids (table_name, next_id)
SELECT 'tls_failure_details', COALESCE(MAX(id), 0) + 1 FROM tls_failure_details;

-- The posture view joined both halves, which no longer share a file.
DROP VIEW IF EXISTS v_domain_posture;
DROP VIEW IF EXISTS v_daily_rollup;

-- Children before parents. With foreign keys on, dropping a parent deletes its
-- rows first and cascades into the child, which is work for nothing when the
-- child is going anyway.
DROP TABLE aggregate_records;
DROP TABLE aggregate_reports;
DROP TABLE tls_failure_details;
DROP TABLE tls_reports;
DROP TABLE dns_changes;
DROP TABLE dns_change_plans;
DROP TABLE senders;
DROP TABLE forensic_reports;
DROP TABLE dns_snapshots;
DROP TABLE dns_drift_events;
DROP TABLE dkim_selectors;
DROP TABLE compliance_scores;
DROP TABLE enforcement_assessments;
DROP TABLE cousin_domains;
DROP TABLE alerts;
DROP TABLE spf_flatten_state;
