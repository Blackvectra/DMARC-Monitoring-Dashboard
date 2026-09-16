PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- seed
INSERT INTO clients (id,name,slug,status,collection_method,created_at,updated_at) VALUES
 ('c-acme','Acme Corp','acme-corp','active','central_mailbox',datetime('now'),datetime('now')),
 ('c-globex','Globex Inc','globex','active','central_mailbox',datetime('now'),datetime('now'));

INSERT INTO domains (id,client_id,name,policy_target,current_policy,created_at,updated_at) VALUES
 ('d-acme','c-acme','acme.com','reject','quarantine',datetime('now'),datetime('now')),
 ('d-globex','c-globex','globex.com','reject','none',datetime('now'),datetime('now'));

INSERT INTO senders (id,client_id,source_ip,service_id,service_confidence,is_approved,first_seen,last_seen,created_at,updated_at) VALUES
 ('s-acme-sg','c-acme','1.2.3.4','sendgrid','high',1,datetime('now'),datetime('now'),datetime('now'),datetime('now')),
 ('s-acme-unk','c-acme','9.9.9.9',NULL,'none',0,datetime('now'),datetime('now'),datetime('now'),datetime('now')),
 ('s-globex-m365','c-globex','5.6.7.8','m365','high',1,datetime('now'),datetime('now'),datetime('now'),datetime('now'));

INSERT INTO aggregate_reports (id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,policy_p,raw_hash,received_at,ingested_at) VALUES
 ('r1','c-acme','d-acme','google.com','RPT-001','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','quarantine','hash-a',datetime('now'),datetime('now')),
 ('r2','c-globex','d-globex','google.com','RPT-002','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','none','hash-b',datetime('now'),datetime('now'));

INSERT INTO aggregate_records (report_id,client_id,domain_id,date_begin,source_ip,message_count,disposition,dkim_result,spf_result,dmarc_result,sender_id) VALUES
 ('r1','c-acme','d-acme','2026-09-14T00:00:00Z','1.2.3.4',950,'none','pass','pass','pass','s-acme-sg'),
 ('r1','c-acme','d-acme','2026-09-14T00:00:00Z','9.9.9.9',50,'quarantine','fail','fail','fail','s-acme-unk'),
 ('r2','c-globex','d-globex','2026-09-14T00:00:00Z','5.6.7.8',400,'none','pass','pass','pass','s-globex-m365');

INSERT INTO compliance_scores (id,client_id,domain_id,score_date,score,policy,pass_rate,total_messages,passing_messages,failing_messages,unknown_sender_failures,computed_at) VALUES
 ('sc1','c-acme','d-acme','2026-09-14',82,'quarantine',95.0,1000,950,50,50,datetime('now')),
 ('sc2','c-globex','d-globex','2026-09-14',45,'none',100.0,400,400,0,0,datetime('now'));

INSERT INTO dns_drift_events (id,client_id,domain_id,detected_at,record_type,old_value,new_value,summary,severity) VALUES
 ('dr1','c-acme','d-acme',datetime('now'),'spf','v=spf1 include:a -all','v=spf1 -all','SPF: -include:a','critical');

.print '=== T1: dedup — same reporter resending the same report_id MUST fail ==='
INSERT INTO aggregate_reports (id,client_id,domain_id,org_name,external_report_id,date_begin,date_end,raw_hash,received_at,ingested_at)
VALUES ('r1-dup','c-acme','d-acme','google.com','RPT-001','2026-09-14T00:00:00Z','2026-09-14T23:59:59Z','hash-a',datetime('now'),datetime('now'));

.print '=== T2: two clients claiming the same domain MUST fail ==='
INSERT INTO domains (id,client_id,name,created_at,updated_at)
VALUES ('d-conflict','c-globex','acme.com',datetime('now'),datetime('now'));

.print '=== T3: orphan record (bad FK) MUST fail ==='
INSERT INTO aggregate_records (report_id,client_id,domain_id,date_begin,source_ip,message_count,dmarc_result)
VALUES ('r-nonexistent','c-acme','d-acme','2026-09-14T00:00:00Z','1.1.1.1',1,'pass');

.print '=== T4: invalid enum MUST fail ==='
INSERT INTO clients (id,name,slug,status,created_at,updated_at)
VALUES ('c-bad','Bad','bad','not-a-real-status',datetime('now'),datetime('now'));

.print ''
.print '=== T5: tenant isolation — Acme query returns ONLY Acme rows, no join ==='
.mode column
.headers on
SELECT client_id, source_ip, message_count, dmarc_result FROM aggregate_records WHERE client_id='c-acme';

.print ''
.print '=== T6: v_domain_posture ==='
SELECT client_name, domain_name, current_policy, latest_score, latest_pass_rate, unapproved_senders, unacked_drift FROM v_domain_posture ORDER BY client_name;

.print ''
.print '=== T7: v_daily_rollup ==='
SELECT client_id, day, total_messages, passing, failing, distinct_sources FROM v_daily_rollup ORDER BY client_id;

.print ''
.print '=== T8: cascade delete — removing Globex removes all its data ==='
DELETE FROM clients WHERE id='c-globex';
SELECT 'orphan_domains='   || COUNT(*) FROM domains           WHERE client_id='c-globex';
SELECT 'orphan_reports='   || COUNT(*) FROM aggregate_reports WHERE client_id='c-globex';
SELECT 'orphan_senders='   || COUNT(*) FROM senders           WHERE client_id='c-globex';
SELECT 'orphan_scores='    || COUNT(*) FROM compliance_scores WHERE client_id='c-globex';
SELECT 'acme_survives='    || COUNT(*) FROM aggregate_records WHERE client_id='c-acme';

.print ''
.print '=== T9: query plans — do the hot paths use indexes? ==='
.mode list
EXPLAIN QUERY PLAN SELECT * FROM aggregate_records WHERE client_id='c-acme' AND date_begin >= '2026-09-01';
.print '---'
EXPLAIN QUERY PLAN SELECT * FROM aggregate_records WHERE client_id='c-acme' AND dmarc_result='fail';
.print '---'
EXPLAIN QUERY PLAN SELECT * FROM senders WHERE client_id='c-acme' AND is_approved=0;
.print '---'
EXPLAIN QUERY PLAN SELECT * FROM dns_drift_events WHERE client_id='c-acme' AND acknowledged_at IS NULL ORDER BY detected_at DESC;
