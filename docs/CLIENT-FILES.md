# One database file per client

Every client's mail data lives in a database file of its own. The
organization's database says who the clients are; each client's file holds
what receivers reported about that client's domains, and nothing else.

    /opt/dmarc/data/
      dmarc.db                                   the organization's database
      dmarc-clients/                             0700
        acme-corp-6f0c1e2a....db                 0600, one per client
        globex-91d4b7c0....db
        unassigned-fe9f0909....db                domains not yet filed under a client

A file is named for its client's slug, so a person can find it, and its id,
so two organizations' `acme-corp` never share a name. Neither changes: a
slug is printed on reports the client has already been sent.

Beside a file there may be a `-wal` and a `-shm`: SQLite's journal for that
file. A process that only read the file cannot remove them, so they stay
until something next writes to it. They belong to the file beside them, and
backups, restores and erasure treat them that way.

## What is where

| The organization's database (`db/schema.sql`) | Each client's file (`db/client-schema.sql`) |
|---|---|
| organizations (`tenants`), `clients`, `domains` | `aggregate_reports`, `aggregate_records` |
| `users`, `user_client_access`, `audit_log` | `forensic_reports` (failure reports' headers) |
| `client_contacts`, `client_settings` | `tls_reports`, `tls_failure_details` |
| `ingest_log` | `senders` |
| `dns_provider_configs` (a credential *reference*, never a secret) | `dns_snapshots`, `dns_drift_events`, `dkim_selectors` |
| `mta_sts_policies` | `compliance_scores`, `enforcement_assessments` |
| `threat_indicators`, `source_names` | `cousin_domains`, `alerts` |
| `row_ids` - see [Row ids](#row-ids) | `dns_change_plans`, `dns_changes`, `spf_flatten_state` |
| `schema_migrations` | `client_file` - whose file this is - and its own `schema_migrations` |

Nothing in the organization's database is anybody's mail. The threat
indicators are what was learned *across* clients - an address impersonating
three of them - and hold the address, the counts and the domains it was seen
against, not the reports.

A client with nothing stored yet has no file until the first thing is
written for it.

## Why

**A page for one client cannot show another client's mail.** It opens the
organization's database and attaches that one client's file. The other
clients' rows are not in any table the query can name, so a query with its
`WHERE` clause missing still returns only this client's rows. Before, the
same guarantee rested on every query remembering to filter.

**A client is a file.** Erasing one deletes its file. Handing a departing
customer their history is copying one file. A client's data can be backed
up, restored or inspected on its own with the ordinary `sqlite3` tool.

**A file says whose it is.** `client_file` is written when the file is
created and checked every time it is opened for a client. A file copied or
renamed into another client's place - by hand, from a backup, or by a bug -
is refused rather than read as theirs.

## How the pages read them

One client: its file is attached to the connection, read-only unless the
page is writing.

Several - triage, the organization's totals, threat intelligence, anything
that exists to see one sender working through several customers: the rows
of the tables that page needs are copied from each file into temporary
tables in memory, for that connection only. SQLite attaches at most ten files
to a connection, and an organization has more clients than that. The cost of
those pages grows with the size of the whole estate; the cost of a
one-client page does not.

No connection is pooled. A pooled connection keeps whatever was attached and
whatever temporary tables were made on it, and the next caller to reuse it
would inherit another page's view of every client.

The figure a client's page carries about the others - "failing at 3 other
customers" - is asked of each other client's file as a count. Nothing more of
another client's mail leaves its file for it.

## Row ids

Aggregate records, failure reports and TLS failure details are numbered, and
those numbers are unique across every client's file, not just within one:
`dmarc export --after-id` resumes from the last number it wrote, whichever
file that row was in, and the failure report page is asked for a report by
its number. The organization's database hands them out (`row_ids`).

Two safeguards keep that true when the files and the organization's database
have been restored from different days:

- a new row never takes a number its own file already has, and
- `dmarc init-db` moves each sequence past the largest number in any file,
  and says so when it had to.

## Upgrading a database from before this (migration 0019)

`dmarc init-db` does it; `deploy/update.sh` runs `init-db`, and so does the
Windows trial when it opens an older database.

1. A copy of the database as it was is written beside it:
   `dmarc.pre-0019.db`.
2. The database is locked for writing, so a collector still running the old
   version cannot add a row between being copied and being dropped.
3. Each client's rows are copied into a new file, in a staging folder, and
   every table is counted in both places. Any difference stops the upgrade
   with nothing changed.
4. The folder is renamed into place, the old tables are dropped, and the
   version is recorded - one transaction.

Interrupted at any point, the database is as it was. A folder left by an
attempt that got as far as the rename is moved aside to
`dmarc-clients.set-aside-<time>`, never deleted, and the files are rebuilt.

Rows whose client no longer exists - never written by this product, but a
database edited by hand is not somewhere to lose rows on the way past - go
into `dmarc-clients/unfiled-rows.db` rather than being dropped, and the
upgrade says how many.

**Delete `dmarc.pre-0019.db` once the dashboard shows what it should.** It is
a complete copy of every client's data. Nothing prunes it, and erasing a
client does not reach it (`dmarc client erase` lists it among the copies that
still hold the client's data).

## Backups and restores

`dmarc backup` writes one `.bak` file, as before. It is now a zip holding the
organization's database and the client folder, laid out as they are on disk,
each copy integrity-checked before it goes in. The client files are copied
before the organization's database, so the backup never holds a report whose
domain it does not have.

To put one back:

    sudo systemctl stop dmarc-web 'dmarc-ingest*.timer' dmarc-backup.timer
    sudo -u dmarc dmarc restore --from /opt/dmarc/backups/dmarc-20260922-032000.bak --db /opt/dmarc/data/dmarc.db
    sudo systemctl start dmarc-web 'dmarc-ingest*.timer' dmarc-backup.timer

`restore` checks every file in the backup - that its names are where a
backup keeps things, that it is intact, that it is one of this product's -
before it touches anything live. Then it moves the database in place aside,
with its `-wal` and `-shm` and its client folder, to
`dmarc-replaced-<time>.db` and `dmarc-replaced-<time>-clients/`. They are
never deleted: whatever arrived since the backup is in them and nowhere else.
Last, it brings what it restored up to date. A `.bak` from before the split -
a single database - restores the same way and is split on the way in.

`deploy/update.sh` takes its own copy before an update:
`dmarc-<stamp>.db` with `dmarc-<stamp>-clients/` beside it.
`deploy/rollback.sh <stamp> --database` puts both back. An update that fails
after it has migrated the database puts the copy back by itself, because the
previous version cannot read a database the new one has migrated.

## When the files and the organization's database disagree

Two things change both: filing a domain under another client, which moves
its rows to that client's file, and moving a client to another organization,
which relabels every row in its file. SQLite commits each file separately, so
a crash at the wrong moment can leave them disagreeing.

`dmarc init-db` puts that right every time it runs, and it is safe to run at
any time:

- rows for a domain now filed under another client are moved into that
  client's file;
- rows labelled with another client or organization than their file's are
  relabelled;
- row id sequences behind the files are moved past them;
- rows for a domain the organization's database no longer has are counted and
  left where they are - there is no one to give them to, and deleting data is
  never done by inference;
- a file that is not the client's it is named for is named and not touched.

## Erasing a client

    dmarc client erase --client acme-corp
    dmarc client erase --client acme-corp --apply --confirm acme-corp --by matthew

Removes the client's rows from the organization's database and deletes its
file, under one lock, and checks both are gone. If the file cannot be
deleted - open in another program on Windows, say - nothing is removed.

What it cannot reach, and says so: the nightly backups, until they age out,
and the whole copies kept beside the database - `dmarc.pre-0019.db`,
`update.sh`'s, and anything a restore or rollback set aside.

## Looking inside

A client's file is an ordinary SQLite database:

    sqlite3 -readonly /opt/dmarc/data/dmarc-clients/acme-corp-6f0c1e2a....db \
        "SELECT client_id FROM client_file; SELECT COUNT(*) FROM aggregate_records;"

Do not copy one client's file over another's, or rename one: the application
refuses a file whose `client_file` does not name the client it is opened for.
