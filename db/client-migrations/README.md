# Client file migrations

Changes to `db/client-schema.sql` after its baseline (client schema 0001), one
numbered `.sql` file each, applied to every client's file in order by
`dmarc init-db`. The organization's database has its own series in
`db/migrations`; the two are versioned apart because they are different files.

None yet. The first one is `0002-<what-it-does>.sql`, and client-schema.sql's
baseline moves to 0002 in the same change, so a file created from the schema
never has the migration replayed into it.
