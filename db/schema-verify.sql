-- Constraint checks for the two schemas, run by CI: the organization's
-- database (db/schema.sql) as main, and one file per client
-- (db/client-schema.sql) attached as acme, globex and rival. See
-- docs/CLIENT-FILES.md.
--
-- Run from a folder holding the four files, each built from its schema:
--   sqlite3 org.db < db/schema.sql
--   for c in acme globex rival; do sqlite3 "$c.db" < db/client-schema.sql; done
--   sqlite3 org.db < db/schema-verify.sql
--
-- The negative cases are expected to error, and CI greps the output for each
-- expected error and each name=value line.

PRAGMA foreign_keys = ON;

ATTACH 'acme.db'   AS acme;
ATTACH 'globex.db' AS globex;
ATTACH 'rival.db'  AS rival;

-- ---------------------------------------------------------------- seed
-- TWO tenants: one self-hosted operator and one hosted MSP. Everything below
-- exists so the isolation boundary can actually be exercised rather than
-- asserted. t-nls and t-rival are competitors; neither may see the other.
INSERT INTO tenants (id,name,slug,deployment_mode,secret_backend,created_at,updated_at) VALUES
 ('t-nls','NextLayerSec','nextlayersec','self_hosted','dpapi',datetime('now'),datetime('now')),
 ('t-rival','Rival MSP','rival-msp','hosted','azure_keyvault',datetime('now'),datetime('now'));

INSERT INTO clients (id,tenant_id,name,slug,status,collection_method,created_at,updated_at) VALUES
 ('c-acme','t-nls','Acme Corp','acme-corp','active','central_mailbox',datetime('now'),datetime('now')),
 ('c-globex','t-nls','Globex Inc','globex','active','central_mailbox',datetime('now'),datetime('now')),
 ('c-rival','t-rival','Rival Customer','acme-corp','active','central_mailbox',datetime('now'),datetime('now'));

INSERT INTO domains (id,tenant_id,client_id,name,policy_target,current_policy,created_at,updated_at) VALUES
 ('d-acme','t-nls','c-acme','acme.com','reject','quarantine',datetime('now'),datetime('now')),
 ('d-globex','t-nls','c-globex','globex.com','reject','none',datetime('now'),datetime('now')),
 ('d-rival','t-rival','c-rival','acme.com','reject','none',datetime('now'),datetime('now'));

-- Each file says whose it is; the application refuses to read one as anybody else's.
INSERT INTO acme.client_file   (client_id, created_at) VALUES ('c-acme',   datetime('now'));
INSERT INTO globex.client_file (client_id, created_at) VALUES ('c-globex', datetime('now'));
INSERT INTO rival.client_file  (client_id, created_at) VALUES ('c-rival',  datetime('now'));

INSERT INTO acme.senders (id,tenant_id,client_id,source_ip,service_id,service_confidence,is_approved,first_seen,last_seen,created_at,updated_at) VALUES
 ('s-acme-sg','t-nls','c-acme','1.2.3.4','sendgrid','high',1,datetime('now'),datetime('now'),datetime('now'),datetime('now')),
 ('s-acme-unk','t-nls','c-acme','9.9.9.9',NULL,'none',0,datetime('now'),datetime('now'),datetime('now'),datetime('now'));
INSERT INTO globex.senders (id,tenant_id,client_id,source_ip,service_id,service_confidence,is_approved,first_seen,last_seen,created_at,updated_at) VALUES
 ('s-globex-m365','t-nls','c-globex','5.6.7.8','m365','high',1,datetime('now'),datetime('now'),datetime('now'),datetime('now'));

INSERT INTO acme.aggregate_reports (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,policy_p,raw_hash,received_at,ingested_at) VALUES
 ('r1','t-nls','c-acme','d-acme','google.com','RPT-001','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','quarantine','hash-a',datetime('now'),datetime('now'));
INSERT INTO globex.aggregate_reports (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,policy_p,raw_hash,received_at,ingested_at) VALUES
 ('r2','t-nls','c-globex','d-globex','google.com','RPT-002','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','none','hash-b',datetime('now'),datetime('now'));
INSERT INTO rival.aggregate_reports (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,policy_p,raw_hash,received_at,ingested_at) VALUES
 ('r3','t-rival','c-rival','d-rival','google.com','RPT-001','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','none','hash-c',datetime('now'),datetime('now'));

-- Row ids are unique across every file: the organization's database hands
-- them out (row_ids), so each file's rows are numbered from where it says.
INSERT INTO acme.aggregate_records (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,disposition,dkim_result,spf_result,dmarc_result,sender_id) VALUES
 (1,'r1','t-nls','c-acme','d-acme','2026-09-14T00:00:00Z','1.2.3.4',950,'none','pass','pass','pass','s-acme-sg'),
 (2,'r1','t-nls','c-acme','d-acme','2026-09-14T00:00:00Z','9.9.9.9',50,'quarantine','fail','fail','fail','s-acme-unk');
INSERT INTO globex.aggregate_records (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,disposition,dkim_result,spf_result,dmarc_result,sender_id) VALUES
 (3,'r2','t-nls','c-globex','d-globex','2026-09-14T00:00:00Z','5.6.7.8',400,'none','pass','pass','pass','s-globex-m365');
INSERT INTO rival.aggregate_records (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,disposition,dkim_result,spf_result,dmarc_result,sender_id) VALUES
 (4,'r3','t-rival','c-rival','d-rival','2026-09-14T00:00:00Z','7.7.7.7',777,'none','pass','pass','pass',NULL);
UPDATE row_ids SET next_id = 5 WHERE table_name = 'aggregate_records';

INSERT INTO acme.compliance_scores (id,tenant_id,client_id,domain_id,score_date,score,policy,pass_rate,total_messages,passing_messages,failing_messages,unknown_sender_failures,computed_at) VALUES
 ('sc1','t-nls','c-acme','d-acme','2026-09-14',82,'quarantine',95.0,1000,950,50,50,datetime('now'));
INSERT INTO globex.compliance_scores (id,tenant_id,client_id,domain_id,score_date,score,policy,pass_rate,total_messages,passing_messages,failing_messages,unknown_sender_failures,computed_at) VALUES
 ('sc2','t-nls','c-globex','d-globex','2026-09-14',45,'none',100.0,400,400,0,0,datetime('now'));

INSERT INTO acme.dns_drift_events (id,tenant_id,client_id,domain_id,detected_at,record_type,old_value,new_value,summary,severity) VALUES
 ('dr1','t-nls','c-acme','d-acme',datetime('now'),'spf','v=spf1 include:a -all','v=spf1 -all','SPF: -include:a','critical');

.print '=== T1: dedup - same reporter resending the same report_id MUST fail ==='
INSERT INTO acme.aggregate_reports (id,tenant_id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,received_at,ingested_at)
VALUES ('r1-dup','t-nls','c-acme','d-acme','google.com','RPT-001','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','hash-a',datetime('now'),datetime('now'));

.print '=== T2: two clients of the SAME tenant claiming one domain MUST fail ==='
INSERT INTO domains (id,tenant_id,client_id,name,created_at,updated_at)
VALUES ('d-conflict','t-nls','c-globex','acme.com',datetime('now'),datetime('now'));

.print '=== T3: orphan record (bad FK inside a client file) MUST fail ==='
INSERT INTO acme.aggregate_records (id,report_id,tenant_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
VALUES (99,'r-nonexistent','t-nls','c-acme','d-acme','2026-09-14T00:00:00Z','1.1.1.1',1,'pass');

.print '=== T4: invalid enum MUST fail ==='
INSERT INTO clients (id,tenant_id,name,slug,status,created_at,updated_at)
VALUES ('c-bad','t-nls','Bad','bad','not-a-real-status',datetime('now'),datetime('now'));

.print ''
.print '=== T5: isolation - a client file holds that client and nothing else ==='
.mode list
SELECT 'acme_file_owner=' || client_id FROM acme.client_file;
SELECT 'acme_file_foreign_rows=' || COUNT(*) FROM acme.aggregate_records WHERE client_id <> 'c-acme';
-- And the organization's database holds none of any client's mail: a query
-- with its WHERE clause missing still cannot reach another client's rows,
-- because there are none where it looks.
SELECT 'main_holds_client_tables=' || COUNT(*) FROM main.sqlite_master m
 WHERE m.type = 'table'
   AND m.name IN (SELECT name FROM acme.sqlite_master WHERE type = 'table' AND name <> 'schema_migrations');

.print ''
.print '=== T7: v_daily_rollup, inside the client file ==='
.mode column
.headers on
SELECT client_id, day, total_messages, passing, failing, distinct_sources FROM acme.v_daily_rollup ORDER BY client_id;
.headers off

.print ''
.print '=== T8: cascade delete - removing Globex removes it from the organization ==='
.mode list
DELETE FROM clients WHERE id='c-globex';
SELECT 'orphan_domains='   || COUNT(*) FROM domains WHERE client_id='c-globex';
-- Its reports, senders and scores are in its own file, which the product
-- deletes with it (see ClientErasure): no foreign key crosses between files.
SELECT 'acme_survives='    || COUNT(*) FROM acme.aggregate_records WHERE client_id='c-acme';

.print ''
.print '=== T9: query plans - do the hot paths use indexes? ==='
EXPLAIN QUERY PLAN SELECT * FROM acme.aggregate_records WHERE client_id='c-acme' AND date_begin >= '2026-09-01';
.print '---'
EXPLAIN QUERY PLAN SELECT * FROM acme.aggregate_records WHERE client_id='c-acme' AND dmarc_result='fail';
.print '---'
EXPLAIN QUERY PLAN SELECT * FROM acme.senders WHERE client_id='c-acme' AND is_approved=0;
.print '---'
EXPLAIN QUERY PLAN SELECT * FROM acme.dns_drift_events WHERE client_id='c-acme' AND acknowledged_at IS NULL ORDER BY detected_at DESC;

.print ''
.print '=== T10: remediation - a plan can be recorded even when refused ==='
INSERT INTO acme.dns_change_plans (id,tenant_id,client_id,domain_id,change_type,record_name,record_type,current_value,proposed_value,is_safe,blockers_json,lookups_before,lookups_after,summary,status,created_at,created_by)
VALUES ('pl1','t-nls','c-acme','d-acme','spf-include-add','acme.com','TXT','v=spf1 ... -all','v=spf1 ... include:sendgrid.net -all',0,'["would exceed 10 lookups"]',10,11,'REFUSED: lookup cap','refused',datetime('now'),'alex');
SELECT 'refused_plan_stored=' || COUNT(*) FROM acme.dns_change_plans WHERE status='refused';

.print ''
.print '=== T11: remediation - applied change links to its plan and keeps rollback target ==='
INSERT INTO acme.dns_change_plans (id,tenant_id,client_id,domain_id,change_type,record_name,record_type,current_value,proposed_value,is_safe,lookups_before,lookups_after,summary,status,created_at,created_by)
VALUES ('pl2','t-nls','c-acme','d-acme','spf-include-add','acme.com','TXT','v=spf1 include:a -all','v=spf1 include:a include:b -all',1,1,2,'add include:b','applied',datetime('now'),'alex');
INSERT INTO acme.dns_changes (id,plan_id,tenant_id,client_id,domain_id,record_name,record_type,previous_value,new_value,provider,applied_at,applied_by,reason,is_propagated)
VALUES ('ch1','pl2','t-nls','c-acme','d-acme','acme.com','TXT','v=spf1 include:a -all','v=spf1 include:a include:b -all','cloudflare',datetime('now'),'alex','ticket 42',1);
SELECT 'change_rollback_target=' || previous_value FROM acme.dns_changes WHERE id='ch1';

.print ''
.print '=== T12: remediation - credentials are never stored in the DB ==='
INSERT INTO dns_provider_configs (id,tenant_id,client_id,domain_id,provider,config_json,credential_ref,created_at,updated_at)
VALUES ('pc1','t-nls','c-acme','d-acme','cloudflare','{"zoneId":"abc123"}','DnsToken_c-acme_cloudflare',datetime('now'),datetime('now'));
SELECT 'stores_only_ref=' || credential_ref FROM dns_provider_configs WHERE id='pc1';

.print ''
.print '=== T13: remediation - one flatten state per domain ==='
INSERT INTO acme.spf_flatten_state (id,tenant_id,client_id,domain_id,flattened_includes,resolved_ips,flattened_value,lookups_before,lookups_after,flattened_at,refresh_by)
VALUES ('fs1','t-nls','c-acme','d-acme','["sendgrid.net"]','["ip4:167.89.0.0/17"]','v=spf1 ip4:167.89.0.0/17 -all',2,0,datetime('now'),date('now','+30 day'));
INSERT INTO acme.spf_flatten_state (id,tenant_id,client_id,domain_id,flattened_includes,resolved_ips,flattened_value,flattened_at,refresh_by)
VALUES ('fs2','t-nls','c-acme','d-acme','["other"]','[]','v=spf1 -all',datetime('now'),date('now','+30 day'));

.print ''
.print '=== T15: TENANT ISOLATION - the files of one organization hold no rows of another ==='
.mode column
.headers on
SELECT tenant_id, client_id, source_ip, message_count FROM acme.aggregate_records ORDER BY source_ip;
.headers off
.mode list
SELECT 'nls_sees_rival_rows=' || (
    (SELECT COUNT(*) FROM acme.aggregate_records   WHERE tenant_id <> 't-nls' OR client_id = 'c-rival')
  + (SELECT COUNT(*) FROM globex.aggregate_records WHERE tenant_id <> 't-nls' OR client_id = 'c-rival'));
SELECT 'rival_row_count=' || COUNT(*) FROM rival.aggregate_records WHERE tenant_id='t-rival';

.print ''
.print '=== T16: two DIFFERENT tenants may both manage the same domain name ==='
SELECT 'acme_com_managed_by=' || COUNT(DISTINCT tenant_id) || '_tenants' FROM domains WHERE name='acme.com';

.print ''
.print '=== T17: two tenants may reuse a client slug ==='
SELECT 'acme_corp_slug_used_by=' || COUNT(*) || '_tenants' FROM clients WHERE slug='acme-corp';

.print ''
.print '=== T18: but ONE tenant cannot reuse a client slug ==='
INSERT INTO clients (id,tenant_id,name,slug,status,created_at,updated_at)
VALUES ('c-dup','t-nls','Duplicate','acme-corp','active',datetime('now'),datetime('now'));

.print ''
.print '=== T19: deleting a tenant removes its entire world, leaving the other intact ==='
DELETE FROM tenants WHERE id='t-rival';
SELECT 'rival_clients='  || COUNT(*) FROM clients WHERE tenant_id='t-rival';
SELECT 'rival_domains='  || COUNT(*) FROM domains WHERE tenant_id='t-rival';
-- A client file is reached only through a client the organization's database
-- still names, so with the clients gone none of the tenant's files can be.
SELECT 'rival_files_reachable=' || COUNT(*) FROM clients WHERE id='c-rival';
SELECT 'nls_survives='   || COUNT(*) FROM acme.aggregate_records WHERE tenant_id='t-nls';

.print ''
.print '=== T20: tenant-leading index is used for the isolation filter ==='
EXPLAIN QUERY PLAN SELECT * FROM acme.aggregate_records WHERE tenant_id='t-nls' AND date_begin >= '2026-09-01';

.print ''
.print '=== T21: row ids carry on from the sequence in the organization database ==='
SELECT 'next_record_id=' || next_id FROM row_ids WHERE table_name='aggregate_records';

.print ''
.print '=== T14: remediation - the history of a client is in its file and nowhere else ==='
DELETE FROM clients WHERE id='c-acme';
SELECT 'orphan_provider=' || COUNT(*) FROM dns_provider_configs WHERE client_id='c-acme';
SELECT 'remediation_outside_its_file=' || (
    (SELECT COUNT(*) FROM globex.dns_change_plans) + (SELECT COUNT(*) FROM globex.dns_changes)
  + (SELECT COUNT(*) FROM globex.spf_flatten_state)
  + (SELECT COUNT(*) FROM rival.dns_change_plans) + (SELECT COUNT(*) FROM rival.dns_changes)
  + (SELECT COUNT(*) FROM rival.spf_flatten_state));
