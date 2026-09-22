-- Record when a report ACTUALLY arrived, or admit we do not know.
--
-- received_at has been a copy of the reporting window's end since the table
-- was written: the insert bound it to report.Metadata.End, the same value
-- already in date_end. So the column named "when we got this" has never once
-- held when anything was got.
--
-- Three things went wrong because of it.
--
-- The question "when do reports usually arrive?" is unanswerable from this
-- database. Asked of the real one, every reporter came back with a lag of
-- exactly 0.0 hours from window end to arrival, for all 1,892 reports, which
-- is not a finding about mail - it is the column being date_end in a hat.
--
-- The tie-break in DomainDetailService does not break ties. It reads
-- ORDER BY date_end DESC, received_at DESC, with a comment explaining that
-- receivers send several reports covering the same window and date_end alone
-- cannot separate them. True, and the second key is equal to the first on
-- every row, so it separates nothing and SQLite still picks whichever it
-- likes. The bug the comment describes was never actually fixed. Fixed
-- properly, it now orders by ingested_at, which is always present.
--
-- And a real arrival time was being thrown away. The Graph collector already
-- reads receivedDateTime and carries it as IMailboxClient.ReceivedAt; the
-- store dropped it on the floor.
--
-- NULL is now allowed, and means exactly one thing: nobody knows when this
-- one arrived. That is the honest answer for a report imported from a folder
-- or a zip, where there is no arrival to know - a file's timestamp is when it
-- was copied, not when the mail came. Writing the window's end there instead
-- would be inventing a fact, which is the error this codebase refuses to make
-- about a DNS record and should not make about a timestamp either.
--
-- Existing rows are set to NULL rather than left as they are. Every one of
-- them holds date_end, and keeping that would mean the column went on lying
-- about all the history while telling the truth about anything new. The
-- information was never there to lose.
--
-- DROP COLUMN / ADD COLUMN, not the usual rename-rebuild-drop. Both tables
-- are the parent side of an ON DELETE CASCADE (aggregate_records ->
-- aggregate_reports, tls_failure_details -> tls_reports), and
-- Microsoft.Data.Sqlite enables PRAGMA foreign_keys by default - unlike the
-- sqlite3 CLI, where it is off. Renaming the parent table out from under a
-- CASCADE child is harmless; DROPPING that renamed copy afterwards is not:
-- with enforcement on, SQLite honours the CASCADE and deletes every
-- referencing row along with it. Proved against a copy of a live database
-- before this file was written: aggregate_records went from 23,697 rows to
-- zero. Editing a column in place never touches the parent table's identity,
-- so no child row's foreign key is ever in question.

ALTER TABLE aggregate_reports DROP COLUMN received_at;
ALTER TABLE aggregate_reports ADD COLUMN received_at TEXT;

ALTER TABLE tls_reports DROP COLUMN received_at;
ALTER TABLE tls_reports ADD COLUMN received_at TEXT;
