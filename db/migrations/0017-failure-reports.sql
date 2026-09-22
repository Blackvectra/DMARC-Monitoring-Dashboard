-- Make forensic_reports storable: three columns it was missing, and the
-- uniqueness that stops re-importing a mailbox duplicating everyone's mail.
--
-- The table has been in the schema from the beginning and has never held a
-- row, because nothing parsed RFC 6591. Writing to it for the first time
-- turned up what was missing.
--
-- raw_hash is the one that matters. aggregate_reports and tls_reports each
-- carry one, and it is what makes importing the same export twice a no-op
-- instead of a second copy of every report. Without it the commonest thing an
-- operator does - point the importer at the mailbox again to be sure nothing
-- was missed - would double the stored count. These hold real message headers,
-- so a duplicate here is not just a wrong number: it is a second copy of
-- somebody's correspondence, kept for its own thirty days.
ALTER TABLE forensic_reports ADD COLUMN raw_hash TEXT;

-- What the receiver did with the message, which the record was silent about.
--
-- It carries more than it looks. A failure report for a message that was
-- DELIVERED anyway is a domain at p=none watching a forgery land in somebody's
-- inbox; the identical report with 'reject' is the policy doing its job. The
-- two read the same way without this column, and they are the difference
-- between a finding and a reassurance.
ALTER TABLE forensic_reports ADD COLUMN delivery_result TEXT;

-- Which receiver sent the report, from the feedback part's User-Agent.
--
-- Worth keeping because so few receivers send these at all. When a domain
-- publishes ruf= and two reports arrive in a month, the first question is who
-- is sending them - and the answer tells an operator what the silence from
-- everybody else means.
ALTER TABLE forensic_reports ADD COLUMN reported_by TEXT;

-- NULLs do not collide in a SQLite unique index, so rows written before this
-- existed - there are none, but the rule should not depend on that - keep
-- working, and every row written from here on is deduplicated.
CREATE UNIQUE INDEX IF NOT EXISTS ux_forensic_hash ON forensic_reports(raw_hash);
