-- When a domain's DNS was last read, and whether that read worked.
--
-- dns_snapshots is content-addressed - UNIQUE(domain_id, content_hash) - so a
-- domain whose records have not changed since the first capture can never get
-- a second row. captured_at therefore means "when this content first
-- appeared", and it can never mean "when we last looked". Those are different
-- facts, and the difference is the whole point of a status chip: a tick drawn
-- from a reading taken in March is not a tick, it is a memory.
--
-- A failed lookup has no home in dns_snapshots either, and must not be given
-- one. Writing an empty snapshot on a timeout would make the newest row say
-- the domain publishes nothing, which is precisely the false "no record" this
-- codebase refuses to produce anywhere else - the one that has somebody
-- publish a second DMARC record over the top of a working first. So the
-- outcome of the last attempt lives here, beside the domain, and
-- dns_snapshots keeps only readings that really happened.
ALTER TABLE domains ADD COLUMN dns_checked_at TEXT;
ALTER TABLE domains ADD COLUMN dns_check_status TEXT;   -- ok / failed / nxdomain

-- More than one TXT record beginning v=spf1 at an apex is a fault on its own:
-- RFC 7208 section 4.5 has the receiver return permerror, so every SPF check
-- for the domain fails, however correct either record is. spf_record holds
-- one record, so without a count that fault is invisible to anything reading
-- the snapshot afterwards.
ALTER TABLE dns_snapshots ADD COLUMN spf_record_count INTEGER;

-- When each stored reading was last observed, and which of them is current.
--
-- captured_at answers neither, and the reason is subtle enough to be worth
-- writing down. The rows are deduplicated by content, so a domain that goes
-- from record A to record B and back to A inserts no third row - A is already
-- there - and A keeps the captured_at of the first time it was seen, months
-- before B. Ordering by captured_at then names B as the current state of a
-- domain that is publishing A. So captured_at keeps meaning "when this state
-- was first seen", which is what "unchanged since" has to be measured from,
-- and last_seen_at records when it was last observed.
--
-- last_seen_at still cannot decide which row is current, and no timestamp
-- can. Two readings stored in the same tick tie, and the tie then falls to
-- insertion order, which is exactly backwards for a revert: the row that is
-- current is the older one. Whatever resolution the clock has, a machine fast
-- enough to beat it exists - this was found by CI doing three writes inside
-- one millisecond on hardware where a laptop took longer.
--
-- So ordering is decided by a counter this code controls, bumped on every
-- observation of a domain whether it inserts a row or touches one. No clock,
-- no ties, no dependence on how fast the machine is.
ALTER TABLE dns_snapshots ADD COLUMN last_seen_at TEXT;
ALTER TABLE dns_snapshots ADD COLUMN last_seen_seq INTEGER;

UPDATE dns_snapshots SET last_seen_at = captured_at WHERE last_seen_at IS NULL;
UPDATE dns_snapshots SET last_seen_seq = rowid WHERE last_seen_seq IS NULL;

CREATE INDEX ix_dns_snap_latest ON dns_snapshots(domain_id, last_seen_seq DESC);

-- DKIM keeps no column here at all. DNS cannot be asked which selectors a
-- domain has - there is nothing to enumerate and no wildcard to walk - so the
-- only selectors worth looking up are the ones the reports have already seen
-- signing, and dkim_selectors records each of those with its own key_status
-- and last_seen. Counting them into the snapshot as well would be a second
-- copy of the same fact, free to disagree with the first.
