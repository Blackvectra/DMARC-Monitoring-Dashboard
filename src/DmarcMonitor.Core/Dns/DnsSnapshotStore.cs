using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Dns;

/// <summary>How the last attempt to read a domain's DNS went.</summary>
public enum DnsCheckStatus
{
    /// <summary>Nobody has looked yet. The absence of a record proves nothing.</summary>
    NeverChecked,

    /// <summary>The resolver answered, and what it said is in the snapshot.</summary>
    Ok,

    /// <summary>
    /// The lookup failed. Whatever the snapshot holds is the last thing that
    /// was really seen, not what is published now.
    /// </summary>
    Failed,

    /// <summary>The resolver answered that there is no such domain.</summary>
    NoSuchDomain,
}

/// <summary>What a domain publishes, as last read.</summary>
public sealed record DomainDns
{
    public required string Domain { get; init; }

    /// <summary>When a check last finished, whatever its outcome.</summary>
    public DateTimeOffset? CheckedAt { get; init; }

    public DnsCheckStatus Status { get; init; } = DnsCheckStatus.NeverChecked;

    /// <summary>
    /// When the records below were first seen in this state.
    /// </summary>
    /// <remarks>
    /// Not the same as <see cref="CheckedAt"/> and usually much older:
    /// snapshots are content-addressed, so a record that has not changed in a
    /// year still carries last year's date. Useful for "unchanged since",
    /// useless for "how current is this".
    /// </remarks>
    public DateTimeOffset? CapturedAt { get; init; }

    public string? SpfRecord { get; init; }

    /// <summary>How many TXT records at the apex began v=spf1. More than one is a fault.</summary>
    public int SpfRecordCount { get; init; }

    /// <summary>DNS lookups the record really costs, includes followed.</summary>
    public int? SpfLookups { get; init; }

    /// <summary>The final all mechanism: -all, ~all, ?all, +all, or empty when absent.</summary>
    public string SpfAll { get; init; } = "";

    public string? DmarcRecord { get; init; }
    public string DmarcPolicy { get; init; } = "";
    public string DmarcRua { get; init; } = "";

    /// <summary>The TXT record at _mta-sts, which announces a policy id and nothing else.</summary>
    public string? MtaStsRecord { get; init; }

    /// <summary>
    /// The mode of the policy file really being served, as last observed.
    /// </summary>
    /// <remarks>
    /// One of enforce, testing, none, or <c>unreachable</c> when the domain
    /// announces a policy and the file could not be fetched or did not parse.
    /// Empty means nobody asked, which is a third answer and not an absence:
    /// the mode is not in DNS at all - <see cref="MtaStsRecord"/> carries an id
    /// and the mode lives in a file at mta-sts.&lt;domain&gt; - so a reading
    /// taken by something that does not fetch simply does not know it.
    /// </remarks>
    public string MtaStsMode { get; init; } = "";

    /// <summary>The TXT record at _smtp._tls, if there is one.</summary>
    public string? TlsRptRecord { get; init; }

    /// <summary>Selectors the reports have named, with what DNS says about each.</summary>
    public IReadOnlyList<ObservedSelector> DkimSelectors { get; init; } = [];

    /// <summary>True when a reading exists at all, whatever its age.</summary>
    public bool HasReading => CapturedAt is not null;
}

/// <summary>
/// One selector the reports named, what DNS said about it, and when a report
/// last showed it signing.
/// </summary>
/// <param name="Selector">The selector, as the reports spelled it.</param>
/// <param name="Key">
/// What was published at it, or null when the lookup could not answer. Null
/// refreshes how recently the selector was used without touching what is
/// recorded about its key, because a selector that timed out has not changed.
/// </param>
/// <param name="LastSeen">
/// When a report last showed this selector signing - taken from the reports,
/// never from the clock. A selector that happens to resolve today is not
/// thereby in use.
/// </param>
public sealed record SelectorReading(string Selector, DkimKey? Key, DateTimeOffset LastSeen);

/// <summary>What storing a reading did.</summary>
/// <param name="Stored">
/// False when the domain is not in the book. Readings hang off a domain row,
/// and domains are created by reports arriving - so checking a prospect's DNS
/// before they are a customer, which is the commonest use of
/// <c>dmarc check</c>, has nothing to attach to. Saying so beats inventing a
/// customer, and beats reporting a reading that went nowhere.
/// </param>
/// <param name="Changed">
/// True when the domain now publishes something other than what it was last
/// seen publishing. False for a first reading: there was nothing to differ
/// from, and calling it a change would fire "this domain's DNS was edited" at
/// every newly onboarded customer.
/// </param>
public sealed record SnapshotSave(bool Stored, bool Changed)
{
    /// <summary>What changed, record by record, when <see cref="Changed"/> is true.</summary>
    public IReadOnlyList<DriftChange> Drift { get; init; } = [];

    /// <summary>
    /// True when this was the first reading on record for the domain.
    /// </summary>
    /// <remarks>
    /// Distinct from "nothing changed", which is what a first reading was
    /// reported as: a fresh install scanning nineteen domains was told nothing
    /// had changed since readings that did not exist.
    /// </remarks>
    public bool First { get; init; }
}

/// <summary>A selector seen signing, and the key found at it.</summary>
/// <param name="Selector">The selector, as the reports spelled it.</param>
/// <param name="Status">What was published there: strong, acceptable, weak, revoked, invalid.</param>
/// <param name="Bits">Key size, when it could be read.</param>
/// <param name="LastSeen">When a report last showed this selector signing.</param>
public sealed record ObservedSelector(string Selector, string Status, int? Bits, DateTimeOffset? LastSeen)
{
    /// <summary>True when a verifier asking DNS today would get a key it can use.</summary>
    public bool Usable => Status is "strong" or "acceptable" or "weak";
}

/// <summary>
/// Reads and writes <c>dns_snapshots</c>, which until now nothing wrote.
///
/// The table was in the schema from the beginning and stayed empty, so every
/// screen that wanted to say what a domain publishes had to resolve it live.
/// That is fine for one domain on one page and impossible for a table of
/// eighty rows: it would be eighty DNS lookups per render, each able to hang
/// for five seconds, on a page somebody reloads.
///
/// So the readings are taken on a schedule and stored, and the table renders
/// from storage. What that costs is currency, and currency is therefore part
/// of what gets stored and part of what gets shown - a tick with no date
/// behind it is the thing this is trying not to produce.
/// </summary>
public sealed class DnsSnapshotStore(string databasePath)
{
    private readonly string _databasePath = NotBlank(databasePath);

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>The organization's database and each client's file; see ClientDatabases.</summary>
    private ClientDatabases Files => new(_databasePath);

    /// <summary>
    /// The current DNS state of every domain in scope, keyed by domain name.
    /// </summary>
    /// <param name="tenantId">One organization's, or null for every organization's.</param>
    /// <param name="clientSlug">One client's, or null for every client's.</param>
    /// <param name="selectorDays">
    /// How far back a selector must have been seen signing to still count.
    /// A selector retired last spring should not be drawn as a broken key
    /// forever, and its dkim_selectors row is never deleted.
    /// </param>
    public async Task<IReadOnlyDictionary<string, DomainDns>> LatestAsync(
        string? tenantId = null, string? clientSlug = null, int selectorDays = 30,
        CancellationToken ct = default)
    {
        var results = new Dictionary<string, DomainDns>(StringComparer.OrdinalIgnoreCase);

        await using var db = await Files.OpenAsync(
            ClientScope.For(tenantId, clientSlug), ["dns_snapshots", "dkim_selectors"], ct: ct).ConfigureAwait(false);

        var ids = new Dictionary<string, string>(StringComparer.Ordinal);

        await using (var command = db.CreateCommand())
        {
            // Picked by last_seen_seq, not by either timestamp. The rows are
            // deduplicated by content, so a domain that reverts to a record it
            // published before updates that old row rather than inserting a
            // new one, and that row keeps the captured_at of months ago -
            // ordering by captured_at would name the abandoned record as
            // current. last_seen_at cannot decide it either: two readings in
            // the same tick tie, and the tie falls to insertion order, which
            // is backwards for exactly that revert. The counter has no ties.
            command.CommandText = """
                SELECT d.id, d.name, d.dns_checked_at, d.dns_check_status,
                       s.captured_at, s.spf_record, s.spf_record_count, s.spf_lookup_count,
                       s.spf_all_mechanism, s.dmarc_record, s.dmarc_p, s.dmarc_rua,
                       s.mta_sts_record, s.mta_sts_mode, s.tls_rpt_record
                FROM domains d
                LEFT JOIN dns_snapshots s
                       ON s.id = (SELECT x.id FROM dns_snapshots x
                                   WHERE x.domain_id = d.id
                                   ORDER BY x.last_seen_seq DESC LIMIT 1)
                JOIN clients c ON c.id = d.client_id
                WHERE d.is_active = 1 AND d.deleted_at IS NULL
                  AND ($tenant IS NULL OR d.tenant_id = $tenant)
                  AND ($client IS NULL OR c.slug = $client)
                """;
            command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);
            command.Parameters.AddWithValue("$client", (object?)Slug(clientSlug) ?? DBNull.Value);

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                var name = reader.GetString(1);
                ids[reader.GetString(0)] = name;

                results[name] = new DomainDns
                {
                    Domain = name,
                    CheckedAt = reader.IsDBNull(2) ? null : ParseDate(reader.GetString(2)),
                    Status = Status(reader.IsDBNull(3) ? null : reader.GetString(3)),
                    CapturedAt = reader.IsDBNull(4) ? null : ParseDate(reader.GetString(4)),
                    SpfRecord = reader.IsDBNull(5) ? null : reader.GetString(5),
                    SpfRecordCount = reader.IsDBNull(6) ? 0 : reader.GetInt32(6),
                    SpfLookups = reader.IsDBNull(7) ? null : reader.GetInt32(7),
                    SpfAll = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    DmarcRecord = reader.IsDBNull(9) ? null : reader.GetString(9),
                    DmarcPolicy = reader.IsDBNull(10) ? "" : reader.GetString(10),
                    DmarcRua = reader.IsDBNull(11) ? "" : reader.GetString(11),
                    MtaStsRecord = reader.IsDBNull(12) ? null : reader.GetString(12),
                    MtaStsMode = reader.IsDBNull(13) ? "" : reader.GetString(13),
                    TlsRptRecord = reader.IsDBNull(14) ? null : reader.GetString(14),
                };
            }
        }

        if (ids.Count == 0) { return results; }

        var selectors = new Dictionary<string, List<ObservedSelector>>(StringComparer.Ordinal);

        await using (var command = db.CreateCommand())
        {
            command.CommandText = """
                SELECT domain_id, selector, key_status, key_length, last_seen
                FROM dkim_selectors
                WHERE last_seen >= $since
                ORDER BY selector
                """;
            command.Parameters.AddWithValue("$since", Stamp(DateTimeOffset.UtcNow.AddDays(-selectorDays)));

            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                var domainId = reader.GetString(0);
                if (!ids.ContainsKey(domainId)) { continue; }

                if (!selectors.TryGetValue(domainId, out var list))
                {
                    list = [];
                    selectors[domainId] = list;
                }

                list.Add(new ObservedSelector(
                    reader.GetString(1),
                    reader.IsDBNull(2) ? "" : reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetInt32(3),
                    reader.IsDBNull(4) ? null : ParseDate(reader.GetString(4))));
            }
        }

        foreach (var (domainId, list) in selectors)
        {
            var name = ids[domainId];
            results[name] = results[name] with { DkimSelectors = list };
        }

        return results;
    }

    /// <summary>
    /// Records what a domain was seen to publish.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The check outcome is written whatever it was; the snapshot is written
    /// only when the lookup really succeeded. A failed reading must not land
    /// in dns_snapshots, because the newest row there is what every screen
    /// reads as "what this domain publishes", and a timeout would turn that
    /// into a confident claim that the domain publishes nothing.
    /// </para>
    /// <para>
    /// A domain that does not exist is a success, not a failure: the resolver
    /// answered. It is stored as a check outcome and no snapshot, because
    /// there are no records to snapshot and an empty row would read as a
    /// domain that has some.
    /// </para>
    /// </remarks>
    /// <param name="scopeTenantId">
    /// The organization this reading belongs to, or null for every one. A
    /// domain name is unique per organization, so without it a reading can
    /// land on another organization's row of the same name.
    /// </param>
    public async Task<SnapshotSave> SaveAsync(
        string domain, PublishedRecords published, IReadOnlyList<SelectorReading>? dkim = null,
        string? scopeTenantId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentNullException.ThrowIfNull(published);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var now = DateTimeOffset.UtcNow;

        var status = published switch
        {
            { LookupFailed: true } => DnsCheckStatus.Failed,
            { DomainDoesNotExist: true } => DnsCheckStatus.NoSuchDomain,
            _ => DnsCheckStatus.Ok,
        };

        var files = Files;

        // The reading goes into the file of the client that owns the domain,
        // and the domain's check status into the organization's database, in
        // one transaction. Found first, then confirmed under the lock: the
        // domain could be filed under another client in between, and a
        // reading written into the file it just left would never be read.
        string? domainId = null, tenantId = null, clientId = null;
        SqliteConnection? db = null;
        SqliteTransaction? transaction = null;

        for (var attempt = 1; db is null; attempt++)
        {
            await using (var registry = await files.OpenRegistryAsync(write: false, ct).ConfigureAwait(false))
            {
                (domainId, tenantId, clientId) = await IdsAsync(registry, name, scopeTenantId, ct).ConfigureAwait(false);
            }
            if (domainId is null) { return new SnapshotSave(Stored: false, Changed: false); }

            var open = await files.OpenAsync(ClientScope.Client(clientId!), write: true, ct: ct).ConfigureAwait(false);
            var tx = open.BeginTransaction(deferred: false);

            await using (var owner = open.CreateCommand())
            {
                owner.Transaction = tx;
                owner.CommandText = "SELECT client_id FROM main.domains WHERE id = $id";
                owner.Parameters.AddWithValue("$id", domainId);
                if (await owner.ExecuteScalarAsync(ct).ConfigureAwait(false) as string == clientId)
                {
                    (db, transaction) = (open, tx);
                    break;
                }
            }

            await tx.DisposeAsync().ConfigureAwait(false);
            await open.DisposeAsync().ConfigureAwait(false);
            if (attempt >= 5)
            {
                throw new InvalidOperationException($"{name} kept changing client while its reading was being stored.");
            }
        }

        await using var connection = db;
        await using var inTransaction = transaction!;
        return await SaveAsync(db, inTransaction, domainId!, tenantId!, clientId!, published, dkim, status, now, ct)
            .ConfigureAwait(false);
    }

    private static async Task<SnapshotSave> SaveAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, string tenantId, string clientId,
        PublishedRecords published, IReadOnlyList<SelectorReading>? dkim, DnsCheckStatus status, DateTimeOffset now,
        CancellationToken ct)
    {
        await using (var command = db.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "UPDATE domains SET dns_checked_at = $at, dns_check_status = $status, updated_at = $at WHERE id = $id";
            command.Parameters.AddWithValue("$at", Stamp(now));
            command.Parameters.AddWithValue("$status", Text(status));
            command.Parameters.AddWithValue("$id", domainId);
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        IReadOnlyList<DriftChange>? drift = null;
        var first = false;

        if (status == DnsCheckStatus.Ok)
        {
            first = await LatestAsync(db, transaction, domainId, ct).ConfigureAwait(false) is null;

            drift = await WriteSnapshotAsync(
                db, transaction, domainId, tenantId, clientId, published, now, ct).ConfigureAwait(false);

            await WriteDkimAsync(
                db, transaction, domainId, tenantId, clientId, dkim ?? [], ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return drift is null
            ? new SnapshotSave(Stored: true, Changed: false) { First = first }
            : new SnapshotSave(Stored: true, Changed: true) { Drift = drift };
    }

    /// <returns>
    /// Null when the domain publishes what it was last seen publishing, or
    /// this is its first reading; otherwise what changed.
    /// </returns>
    private static async Task<IReadOnlyList<DriftChange>?> WriteSnapshotAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, string tenantId, string clientId,
        PublishedRecords published, DateTimeOffset now, CancellationToken ct)
    {
        var spf = published.SpfRecords.Count > 0 ? published.SpfRecords[0] : null;
        var dmarc = published.DmarcRecord is null ? null : DmarcRecord.Parse(published.DmarcRecord);
        var all = spf is null ? null : SpfRecord.Parse(spf).All?.Raw;

        // Every record value, so an unchanged reading updates nothing and the
        // table holds one row per state the domain has really been in.
        var hash = Hash(
            spf, published.SpfRecords.Count.ToString(CultureInfo.InvariantCulture),
            published.DmarcRecord, published.MtaStsRecord, published.TlsRptRecord, all);

        // Whether the domain now publishes something other than what it was
        // last seen publishing. Compared against the current reading rather
        // than against every reading ever stored, because a domain that
        // reverts to a record it used to have HAS changed, and its old row
        // still being on file does not make that a non-event.
        var previous = await LatestAsync(db, transaction, domainId, ct).ConfigureAwait(false);
        var changed = previous is not null && !string.Equals(previous.Value.Hash, hash, StringComparison.Ordinal);

        // The next place in this domain's order of observations. Read and
        // written inside the transaction, which SQLite serialises against
        // other writers, so two scans cannot land on the same number.
        var seq = await NextSequenceAsync(db, transaction, domainId, ct).ConfigureAwait(false);

        // The same state seen again is not a new observation, and inserting a
        // second row for it would make the history say the record changed on
        // a day it did not. Only when it was last seen, and its place in the
        // order, move.
        await using (var seen = db.CreateCommand())
        {
            seen.Transaction = transaction;
            seen.CommandText = """
                UPDATE dns_snapshots SET last_seen_at = $at, last_seen_seq = $seq
                WHERE domain_id = $domain AND content_hash = $hash
                """;
            seen.Parameters.AddWithValue("$at", Stamp(now));
            seen.Parameters.AddWithValue("$seq", seq);
            seen.Parameters.AddWithValue("$domain", domainId);
            seen.Parameters.AddWithValue("$hash", hash);

            if (await seen.ExecuteNonQueryAsync(ct).ConfigureAwait(false) == 0)
            {
                await InsertAsync(
                    db, transaction, domainId, tenantId, clientId,
                    published, spf, all, dmarc, hash, now, seq, ct).ConfigureAwait(false);
            }
        }

        await WriteServedModeAsync(db, transaction, domainId, hash, published, ct).ConfigureAwait(false);

        if (dmarc is { IsValid: true })
        {
            // The denormalized pair the schema has always carried a comment
            // about and nothing ever filled. It is what the domain publishes
            // now, which is a different question from what policy the
            // receivers in the last report were applying, so it replaces
            // nothing that the triage view reads.
            await using var update = db.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = "UPDATE domains SET current_policy = $p, current_pct = $pct WHERE id = $id";
            update.Parameters.AddWithValue("$p", dmarc.Policy);
            update.Parameters.AddWithValue("$pct", dmarc.Percent);
            update.Parameters.AddWithValue("$id", domainId);
            await update.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        if (!changed) { return null; }

        var drift = DnsDrift.Compare(previous!.Value.State, new DnsState
        {
            Spf = spf,
            SpfCount = published.SpfRecords.Count,
            Dmarc = published.DmarcRecord,
            MtaSts = published.MtaStsRecord,
            TlsRpt = published.TlsRptRecord,
        });

        await WriteDriftAsync(db, transaction, domainId, tenantId, clientId, drift, now, ct).ConfigureAwait(false);
        return drift;
    }

    /// <summary>
    /// Records each change, marked expected when this product changed the
    /// domain's DNS itself in the two days before.
    /// </summary>
    /// <remarks>
    /// "Change I made" against "change the client made without telling me"
    /// is the distinction the table was designed around. A change applied
    /// here and not rolled back is the first kind; anything else is the
    /// second, and is what an MSP needs to hear about.
    /// </remarks>
    private static async Task WriteDriftAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, string tenantId, string clientId,
        IReadOnlyList<DriftChange> drift, DateTimeOffset now, CancellationToken ct)
    {
        if (drift.Count == 0) { return; }

        bool expected;
        await using (var ours = db.CreateCommand())
        {
            ours.Transaction = transaction;
            ours.CommandText = """
                SELECT EXISTS (SELECT 1 FROM dns_changes
                               WHERE domain_id = $domain AND rolled_back_at IS NULL AND applied_at >= $since)
                """;
            ours.Parameters.AddWithValue("$domain", domainId);
            ours.Parameters.AddWithValue("$since", Stamp(now.AddDays(-2)));
            expected = Convert.ToInt64(await ours.ExecuteScalarAsync(ct).ConfigureAwait(false), CultureInfo.InvariantCulture) == 1;
        }

        foreach (var change in drift)
        {
            await using var insert = db.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO dns_drift_events
                    (id, tenant_id, client_id, domain_id, detected_at, record_type,
                     old_value, new_value, summary, severity, was_expected)
                VALUES ($id, $tenant, $client, $domain, $at, $type, $old, $new, $summary, $severity, $expected)
                """;
            insert.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            insert.Parameters.AddWithValue("$tenant", tenantId);
            insert.Parameters.AddWithValue("$client", clientId);
            insert.Parameters.AddWithValue("$domain", domainId);
            insert.Parameters.AddWithValue("$at", Stamp(now));
            insert.Parameters.AddWithValue("$type", change.RecordType);
            insert.Parameters.AddWithValue("$old", (object?)change.OldValue ?? DBNull.Value);
            insert.Parameters.AddWithValue("$new", (object?)change.NewValue ?? DBNull.Value);
            insert.Parameters.AddWithValue("$summary", change.Summary);
            insert.Parameters.AddWithValue("$severity", change.Severity);
            insert.Parameters.AddWithValue("$expected", expected ? 1 : 0);
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// What mode the served policy file was in, written onto the row that is
    /// now current.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately outside the content hash, and so outside the insert. The
    /// policy file is not a DNS record: it is an HTTPS fetch from a host that
    /// can time out on its own schedule, and folding it into the hash would
    /// have a flaky minute of network insert a snapshot row and report that
    /// the zone had been edited - which is a sentence somebody acts on.
    /// </para>
    /// <para>
    /// Written only when a fetch really happened. A null
    /// <see cref="PublishedRecords.ServedMtaSts"/> means this run did not ask -
    /// an offline caller, or a domain announcing no policy worth asking about -
    /// and overwriting a known mode with "we did not look" would turn every
    /// reading taken by something that does not fetch into an erasure.
    /// </para>
    /// </remarks>
    private static async Task WriteServedModeAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, string hash,
        PublishedRecords published, CancellationToken ct)
    {
        if (published.ServedMtaSts is not { } served) { return; }

        // Reachable with a policy that parsed is the only case with a mode.
        // Everything else is a domain announcing a policy senders cannot use,
        // which protects nothing and is its own state rather than an absence.
        var mode = served is { Reachable: true, Policy: { } policy } ? policy.Mode : "unreachable";

        await using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE dns_snapshots SET mta_sts_mode = $mode
            WHERE domain_id = $domain AND content_hash = $hash
            """;
        command.Parameters.AddWithValue("$mode", mode);
        command.Parameters.AddWithValue("$domain", domainId);
        command.Parameters.AddWithValue("$hash", hash);

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task<(string Hash, DnsState State)?> LatestAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT content_hash, spf_record, COALESCE(spf_record_count, 0), dmarc_record, mta_sts_record, tls_rpt_record
            FROM dns_snapshots
            WHERE domain_id = $domain
            ORDER BY last_seen_seq DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$domain", domainId);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { return null; }

        string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);

        return (reader.GetString(0), new DnsState
        {
            Spf = Text(1),
            SpfCount = reader.GetInt32(2),
            Dmarc = Text(3),
            MtaSts = Text(4),
            TlsRpt = Text(5),
        });
    }

    /// <summary>
    /// The next place in a domain's order of observations.
    /// </summary>
    /// <remarks>
    /// A counter rather than a clock. Two readings stored in the same tick
    /// tie on any timestamp, and the tie then falls to insertion order, which
    /// is exactly backwards for a domain that has reverted to a record it
    /// published before: the row that is current is the older one. Whatever
    /// resolution the timestamp has, a machine fast enough to beat it exists.
    /// </remarks>
    private static async Task<long> NextSequenceAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT COALESCE(MAX(last_seen_seq), 0) + 1 FROM dns_snapshots WHERE domain_id = $domain";
        command.Parameters.AddWithValue("$domain", domainId);

        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    private static async Task InsertAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, string tenantId, string clientId,
        PublishedRecords published, string? spf, string? all, DmarcRecord? dmarc, string hash,
        DateTimeOffset now, long seq, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO dns_snapshots
                (id, tenant_id, client_id, domain_id, captured_at, last_seen_at, last_seen_seq,
                 spf_record, spf_record_count, dmarc_record, mta_sts_record, tls_rpt_record,
                 spf_lookup_count, spf_all_mechanism,
                 dmarc_p, dmarc_sp, dmarc_pct, dmarc_adkim, dmarc_aspf, dmarc_rua,
                 content_hash)
            VALUES ($id, $tenant, $client, $domain, $at, $at, $seq,
                    $spf, $spfCount, $dmarc, $mtaSts, $tlsRpt,
                    $lookups, $all,
                    $p, $sp, $pct, $adkim, $aspf, $rua,
                    $hash)
            """;
        command.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
        command.Parameters.AddWithValue("$tenant", tenantId);
        command.Parameters.AddWithValue("$client", clientId);
        command.Parameters.AddWithValue("$domain", domainId);
        command.Parameters.AddWithValue("$at", Stamp(now));
        command.Parameters.AddWithValue("$seq", seq);
        command.Parameters.AddWithValue("$spf", (object?)spf ?? DBNull.Value);
        command.Parameters.AddWithValue("$spfCount", published.SpfRecords.Count);
        command.Parameters.AddWithValue("$dmarc", (object?)published.DmarcRecord ?? DBNull.Value);
        command.Parameters.AddWithValue("$mtaSts", (object?)published.MtaStsRecord ?? DBNull.Value);
        command.Parameters.AddWithValue("$tlsRpt", (object?)published.TlsRptRecord ?? DBNull.Value);
        command.Parameters.AddWithValue("$lookups", spf is null ? DBNull.Value : published.SpfLookups);
        command.Parameters.AddWithValue("$all", (object?)all ?? DBNull.Value);
        command.Parameters.AddWithValue("$p", (object?)dmarc?.Policy ?? DBNull.Value);
        command.Parameters.AddWithValue("$sp", (object?)dmarc?.SubdomainPolicy ?? DBNull.Value);
        command.Parameters.AddWithValue("$pct", dmarc is null ? DBNull.Value : dmarc.Percent);
        command.Parameters.AddWithValue("$adkim", dmarc is null ? DBNull.Value : dmarc.StrictDkim ? "s" : "r");
        command.Parameters.AddWithValue("$aspf", dmarc is null ? DBNull.Value : dmarc.StrictSpf ? "s" : "r");
        command.Parameters.AddWithValue("$rua", (object?)dmarc?.Rua ?? DBNull.Value);
        command.Parameters.AddWithValue("$hash", hash);

        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task WriteDkimAsync(
        SqliteConnection db, SqliteTransaction transaction, string domainId, string tenantId, string clientId,
        IReadOnlyList<SelectorReading> readings, CancellationToken ct)
    {
        foreach (var reading in readings)
        {
            ct.ThrowIfCancellationRequested();

            await using var command = db.CreateCommand();
            command.Transaction = transaction;

            if (reading.Key is null)
            {
                // The lookup could not answer. How recently the selector was
                // used is still known, and is still worth recording; what is
                // published at it is not, and the row keeps whatever was last
                // really observed. An UPDATE rather than an upsert on purpose:
                // with no existing row there is nothing known about this
                // selector at all, and inserting one would invent a status.
                command.CommandText =
                    "UPDATE dkim_selectors SET last_seen = $at WHERE domain_id = $domain AND selector = $selector";
                command.Parameters.AddWithValue("$at", Stamp(reading.LastSeen));
                command.Parameters.AddWithValue("$domain", domainId);
                command.Parameters.AddWithValue("$selector", reading.Selector);
                await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                continue;
            }

            var key = reading.Key;

            // first_seen is left alone on conflict: it is when this selector
            // was first observed, and a rotation of the key under it does not
            // make the selector new.
            command.CommandText = """
                INSERT INTO dkim_selectors
                    (id, tenant_id, client_id, domain_id, selector, algorithm, key_length, key_status,
                     first_seen, last_seen)
                VALUES ($id, $tenant, $client, $domain, $selector, $algorithm, $bits, $status, $at, $at)
                ON CONFLICT(domain_id, selector) DO UPDATE SET
                    algorithm  = excluded.algorithm,
                    key_length = excluded.key_length,
                    key_status = excluded.key_status,
                    last_seen  = excluded.last_seen
                """;
            command.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            command.Parameters.AddWithValue("$tenant", tenantId);
            command.Parameters.AddWithValue("$client", clientId);
            command.Parameters.AddWithValue("$domain", domainId);
            command.Parameters.AddWithValue("$selector", reading.Selector);
            command.Parameters.AddWithValue("$algorithm", key.Algorithm);
            command.Parameters.AddWithValue("$bits", (object?)key.Bits ?? DBNull.Value);
            command.Parameters.AddWithValue("$status", key.StatusText);
            command.Parameters.AddWithValue("$at", Stamp(reading.LastSeen));

            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The row a domain name refers to, inside one organization.
    /// </summary>
    /// <remarks>
    /// The tenant is part of the key, not decoration. A domain name is unique
    /// per organization and not globally - UNIQUE(tenant_id, name), and
    /// deliberately, so two MSPs on one install can each manage example.com
    /// for their own customer. Resolving by name alone takes whichever row
    /// SQLite hands back first, so a scan run for one organization wrote its
    /// readings and DKIM selectors onto the other's domain - leaving one of
    /// them reading "never checked" for ever while the other was written
    /// twice.
    ///
    /// Null means every organization, which is what a command-line run by the
    /// operator wants and what a request on behalf of a signed-in person never
    /// does.
    /// </remarks>
    private static async Task<(string? Domain, string? Tenant, string? Client)> IdsAsync(
        SqliteConnection db, string name, string? tenantId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText =
            "SELECT id, tenant_id, client_id FROM domains "
            + "WHERE name = $name AND deleted_at IS NULL "
            + "  AND ($tenant IS NULL OR tenant_id = $tenant) LIMIT 1";
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$tenant", (object?)tenantId ?? DBNull.Value);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false)
            ? (reader.GetString(0), reader.GetString(1), reader.GetString(2))
            : (null, null, null);
    }

    private static string Hash(params string?[] values)
    {
        // The separator is a character no DNS record contains, so two
        // different readings cannot be concatenated into the same string -
        // an SPF record ending where the DMARC record begins.
        var joined = string.Join('\u0000', values.Select(v => v ?? ""));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(joined)));
    }

    private static string Stamp(DateTimeOffset when) =>
        when.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static DateTimeOffset? ParseDate(string raw) =>
        DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? new DateTimeOffset(parsed, TimeSpan.Zero)
            : null;

    private static string? Slug(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();

    internal static string Text(DnsCheckStatus status) => status switch
    {
        DnsCheckStatus.Ok => "ok",
        DnsCheckStatus.Failed => "failed",
        DnsCheckStatus.NoSuchDomain => "nxdomain",
        _ => "",
    };

    private static DnsCheckStatus Status(string? stored) => stored switch
    {
        "ok" => DnsCheckStatus.Ok,
        "failed" => DnsCheckStatus.Failed,
        "nxdomain" => DnsCheckStatus.NoSuchDomain,
        _ => DnsCheckStatus.NeverChecked,
    };
}
