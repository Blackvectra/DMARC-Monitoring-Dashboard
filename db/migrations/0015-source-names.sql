-- Remember what an address reverses to, so a report can name its senders.
--
-- The Sources page has been listing addresses: 35.174.145.124 against four
-- clients, 192.3.180.38 against two. Every one of those lines is research
-- somebody has to go and do, and the answer is the same every time for the
-- same address. "Avanan (Check Point Harmony) is breaking signatures for four
-- of your clients" is the same finding, already read.
--
-- A cache rather than a column on aggregate_records, for three reasons. The
-- same address appears in thousands of rows and its name is a property of the
-- address, not of any one report. A PTR changes on its own schedule and has
-- to be re-read without rewriting history. And a reverse lookup is a network
-- call, so it cannot happen while a page renders.
--
-- Not scoped to a tenant. A PTR is public DNS and identical for everybody
-- asking, so scoping it would mean resolving the same address once per
-- customer and getting the same answer each time. Nothing customer-specific
-- is stored here: only an address that was already in a report, and what the
-- public DNS says about it.
--
-- WHAT THIS IS NOT
--
-- A PTR is written by whoever holds the address, so it identifies a sender
-- the way a return address on an envelope does. That is enough to recognise a
-- provider and nowhere near enough to trust one, which is why nothing derived
-- from this feeds a verdict: the judging stays where it already is - whether
-- anything was signed, and whether the same address is failing against other
-- customers.
CREATE TABLE IF NOT EXISTS source_names (
    -- The address, exactly as aggregate_records stores it.
    ip            TEXT PRIMARY KEY,

    -- What it reverses to, or NULL for "asked, and there is no name". The
    -- distinction between those two states is the whole point of storing a
    -- row with a null: without it, an address with no PTR would be looked up
    -- again on every single run, for ever, and reverse zones for the ranges
    -- that spoof most are exactly the ones that do not answer.
    reverse_name  TEXT,

    -- When it was asked. Drives re-reading, and lets a stale name be shown as
    -- stale rather than as current.
    checked_at    TEXT NOT NULL,

    -- Whether the last attempt got an answer from the reverse zone at all. A
    -- timeout and a confirmed "no such name" both leave reverse_name null and
    -- mean different things: the first is worth retrying soon, the second is
    -- not.
    answered      INTEGER NOT NULL DEFAULT 1
);

-- The nightly pass asks "what have I not looked at lately", which is a scan
-- of this column and nothing else.
CREATE INDEX IF NOT EXISTS ix_source_names_checked ON source_names(checked_at);
