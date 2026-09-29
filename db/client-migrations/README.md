# Client file migrations

Changes to `db/client-schema.sql` after its baseline (client schema 0001), one
numbered `.sql` file each, applied to every client's file in order by
`dmarc init-db`. The organization's database has its own series in
`db/migrations`; the two are versioned apart because they are different files.

Each one moves client-schema.sql's baseline with it, so a file created from
the schema never has the migration replayed into it.

- `0002-drop-alerts.sql` - the unused alerts table goes; its lifecycle lives
  in `findings`, in the organization's database (migration 0022 there).
