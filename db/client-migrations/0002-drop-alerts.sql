-- The alerts table goes. It was designed for a lifecycle - dedup, fired,
-- resolved - that nothing ever wrote to, and that lifecycle now lives in
-- findings, in the organization's database (migration 0022 there). Dropping
-- the table here rather than leaving it empty, because a table that exists
-- is one somebody will write to next.
DROP TABLE alerts;
