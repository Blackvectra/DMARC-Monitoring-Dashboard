using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// A client, and where its own database file is.
/// </summary>
/// <param name="Id">The client's id in the organization's database.</param>
/// <param name="Slug">Its slug, which the file is named after so a person can find it.</param>
/// <param name="TenantId">The organization it belongs to.</param>
public sealed record ClientFile(string Id, string Slug, string TenantId);

/// <summary>What putting the client files right against the organization's database changed.</summary>
/// <param name="MovedDomains">Domains whose rows were in another client's file, as "domain: from -> to".</param>
/// <param name="RetaggedRows">Rows whose client or organization was rewritten to their file's.</param>
/// <param name="HomelessRows">Rows for domains the organization's database no longer has, left in place.</param>
/// <param name="Refused">Files that are not the client's they are named for, left alone.</param>
/// <param name="RaisedSequences">
/// Row id sequences that were behind the ids already in the files, as
/// "table: from -> to" - the mark of an organization's database put back from
/// a copy older than its client files.
/// </param>
public sealed record ReconcileResult(
    IReadOnlyList<string> MovedDomains, long RetaggedRows, long HomelessRows, IReadOnlyList<string> Refused,
    IReadOnlyList<string> RaisedSequences)
{
    public bool Changed => MovedDomains.Count > 0 || RetaggedRows > 0 || RaisedSequences.Count > 0;
}

/// <summary>
/// Which clients' files a connection is to see.
/// </summary>
/// <remarks>
/// Built from the same arguments the services already filter by - an
/// organization, a client's slug, a domain - so the files a query can reach
/// are narrowed by exactly what its WHERE clause says it wants. The WHERE
/// clauses stay as they were; this only takes away the files they were never
/// meant to read.
/// </remarks>
public sealed record ClientScope
{
    private ClientScope() { }

    public string? TenantId { get; private init; }
    public string? ClientId { get; private init; }
    public string? ClientSlug { get; private init; }
    public string? DomainName { get; private init; }
    public string? DomainId { get; private init; }

    /// <summary>Every client of one organization, or of every organization when null.</summary>
    public static ClientScope Organization(string? tenantId) => new() { TenantId = Clean(tenantId) };

    /// <summary>One client, by id.</summary>
    public static ClientScope Client(string clientId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        return new() { ClientId = clientId.Trim() };
    }

    /// <summary>The domain's client, by the domain's id.</summary>
    public static ClientScope ForDomainId(string domainId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainId);
        return new() { DomainId = domainId.Trim() };
    }

    /// <summary>
    /// The narrowest scope the arguments describe: a domain's client, else the
    /// clients with this slug, else the whole organization.
    /// </summary>
    public static ClientScope For(string? tenantId, string? clientSlug = null, string? domain = null) => new()
    {
        TenantId = Clean(tenantId),
        ClientSlug = Clean(clientSlug)?.ToLowerInvariant(),
        DomainName = Clean(domain)?.TrimEnd('.').ToLowerInvariant(),
    };

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>
/// Where every client's own database file lives, and connections that see the
/// right ones.
/// </summary>
/// <remarks>
/// <para>
/// The organization's database (db/schema.sql) says who the clients are.
/// Each client's reports, DNS history and changes are in a file of its own
/// (db/client-schema.sql), in a folder beside it: dmarc.db keeps its clients
/// in dmarc-clients/, one file each, named for the client so a person can
/// find it and for its id so two organizations' "acme-corp" never collide.
/// </para>
/// <para>
/// Every connection here opens the organization's database as <c>main</c>
/// and then makes a client's tables visible in one of two ways, so that SQL
/// written for the single database reads unchanged:
/// </para>
/// <list type="bullet">
/// <item>
/// One client: its file is attached. SQLite looks an unqualified table name up
/// in main, then temp, then the attached files, and the organization's
/// database has none of a client's tables - so <c>FROM aggregate_records</c>
/// is that client's file and nothing else. A page scoped to one customer
/// cannot read another's mail even with a WHERE clause missing.
/// </item>
/// <item>
/// Several: their rows are copied into TEMP tables of the same names, for the
/// cross-client pages - the ones that exist to see one sender working through
/// several customers. SQLite attaches at most ten files to a connection, and
/// an organization has more clients than that, so a union of attached files
/// cannot serve them; the copy is read from each file in turn and lives only
/// in this connection's memory.
/// </item>
/// </list>
/// <para>
/// No connection here is pooled. A pooled handle keeps whatever was attached
/// and whatever TEMP tables were made on it, and the next caller to rent it
/// would inherit them: a customer's page opened on a handle a staff page had
/// filled with every client's rows would read all of them, because TEMP is
/// searched before an attached file.
/// </para>
/// </remarks>
public sealed partial class ClientDatabases
{
    /// <summary>The name a single client's attached file is known by.</summary>
    internal const string Attached = "client_db";

    /// <summary>The name each file is attached as while its rows are copied.</summary>
    private const string Source = "client_src";

    public ClientDatabases(string registryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryPath);
        if (registryPath.Trim() == ":memory:")
        {
            throw new ArgumentException(
                "Client files live in a folder beside the organization's database, so an in-memory database cannot have them.",
                nameof(registryPath));
        }

        RegistryPath = Path.GetFullPath(registryPath);
        Folder = FolderFor(RegistryPath);
    }

    /// <summary>The organization's database.</summary>
    public string RegistryPath { get; }

    /// <summary>The folder the client files are in.</summary>
    public string Folder { get; }

    /// <summary>"/data/dmarc.db" keeps its clients in "/data/dmarc-clients".</summary>
    public static string FolderFor(string registryPath)
    {
        var full = Path.GetFullPath(registryPath);
        return Path.Combine(
            Path.GetDirectoryName(full) ?? ".",
            Path.GetFileNameWithoutExtension(full) + "-clients");
    }

    /// <summary>Where a client's file is, whether or not it exists yet.</summary>
    /// <remarks>
    /// The slug makes the file findable by a person; the id makes it unique,
    /// because slugs are unique only within one organization. Neither ever
    /// changes - a client's slug is printed on reports it has already been
    /// sent, and nothing in this product renames one - so the name is stable.
    /// </remarks>
    public string PathFor(ClientFile client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return Path.Combine(Folder, $"{SafeName(client.Slug)}-{SafeName(client.Id)}.db");
    }

    /// <summary>
    /// Whole copies of a database left beside it, with their client folders:
    /// the one migration 0019 kept (<c>dmarc.pre-0019.db</c>), update.sh's
    /// (<c>dmarc-&lt;stamp&gt;.db</c>), and what a restore, a rollback or an
    /// interrupted split set aside.
    /// </summary>
    /// <remarks>
    /// Each holds every client's data as it was, and none is pruned by
    /// retention or reached by erasure - they are there to be gone back to.
    /// So whatever says a client's data is gone also says these are not.
    /// </remarks>
    public static IReadOnlyList<string> CopiesBeside(string registryPath)
    {
        var full = Path.GetFullPath(registryPath);
        var directory = Path.GetDirectoryName(full) ?? ".";
        var name = Path.GetFileNameWithoutExtension(full);
        if (!Directory.Exists(directory)) { return []; }

        string[] kept = [$"{name}.pre-", $"{name}-replaced-", $"{name}-partial-", $"{name}-clients.set-aside-", $"{name}.restoring-"];

        // dmarc-20260925-170601.db and dmarc-20260925-170601-clients: update.sh's.
        bool Stamped(string entry)
        {
            if (!entry.StartsWith(name + "-", StringComparison.Ordinal)) { return false; }
            var rest = entry[(name.Length + 1)..];
            return rest.Length >= 15
                && rest[..8].All(char.IsAsciiDigit) && rest[8] == '-' && rest[9..15].All(char.IsAsciiDigit)
                && rest[15..] is ".db" or "-clients";
        }

        return [.. Directory.EnumerateFileSystemEntries(directory)
            .Where(path =>
            {
                var entry = Path.GetFileName(path);
                return !entry.EndsWith("-wal", StringComparison.Ordinal)
                    && !entry.EndsWith("-shm", StringComparison.Ordinal)
                    && (kept.Any(k => entry.StartsWith(k, StringComparison.Ordinal)) || Stamped(entry));
            })
            .Order(StringComparer.Ordinal)];
    }

    /// <summary>A slug or id as a piece of a file name: letters, digits and hyphens only.</summary>
    private static string SafeName(string value)
    {
        var name = SafeCharacters().Replace((value ?? "").Trim().ToLowerInvariant(), "-").Trim('-');
        if (name.Length > 60) { name = name[..60].Trim('-'); }
        return name.Length == 0 ? "client" : name;
    }

    [GeneratedRegex("[^a-z0-9-]+", RegexOptions.CultureInvariant)]
    private static partial Regex SafeCharacters();

    // ---- the tables a client file holds ------------------------------------

    /// <summary>
    /// The tables every client file has, in the order the schema creates them.
    /// </summary>
    /// <remarks>
    /// Read from the schema itself rather than listed, so a table added to
    /// client-schema.sql is copied, moved and erased with the rest without
    /// anybody having to remember to add it here.
    /// </remarks>
    public static IReadOnlyList<string> Tables => Reference.Value.Tables;

    /// <summary>
    /// Tables keyed by an INTEGER PRIMARY KEY, which is the rowid: numbered
    /// from one in every file, so a row keeps its id only inside its own.
    /// </summary>
    public static IReadOnlySet<string> RowidTables => Reference.Value.RowidTables;

    /// <summary>
    /// The tables in a client's file that belong to one domain, in the order
    /// they are copied: parents before the rows that refer to them.
    /// </summary>
    /// <remarks>
    /// tls_failure_details has no domain_id of its own and goes with its
    /// report. senders is not here: it is a client's inventory of who sends
    /// for it rather than a fact about one domain, and stays with the client.
    /// ReportStoreAssignmentTests recomputes this from the schema.
    /// </remarks>
    public static IReadOnlyList<string> DomainTables { get; } =
    [
        "aggregate_reports",
        "aggregate_records",
        "tls_reports",
        "tls_failure_details",
        "forensic_reports",
        "dns_snapshots",
        "dns_drift_events",
        "dkim_selectors",
        "compliance_scores",
        "enforcement_assessments",
        "cousin_domains",
        "alerts",
        "dns_change_plans",
        "dns_changes",
        "spf_flatten_state",
    ];

    private static readonly Lazy<ReferenceSchema> Reference = new(ReferenceSchema.Build);

    /// <summary>What the client schema looks like, read once from an in-memory copy of it.</summary>
    private sealed record ReferenceSchema(
        IReadOnlyList<string> Tables,
        IReadOnlyDictionary<string, IReadOnlyList<(string Name, string Type)>> Columns,
        IReadOnlyDictionary<string, IReadOnlyList<string>> TempIndexes,
        IReadOnlySet<string> RowidTables)
    {
        /// <summary>Tables in the file that are about the file rather than the client's mail.</summary>
        private static readonly HashSet<string> Bookkeeping = new(StringComparer.OrdinalIgnoreCase)
        {
            "client_file", "schema_migrations",
        };

        public static ReferenceSchema Build()
        {
            using var db = new SqliteConnection("Data Source=:memory:;Pooling=False");
            db.Open();

            using (var create = db.CreateCommand())
            {
                create.CommandText = DatabaseSchema.ClientSql;
                create.ExecuteNonQuery();
            }

            var tables = new List<string>();
            using (var list = db.CreateCommand())
            {
                list.CommandText =
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid";
                using var reader = list.ExecuteReader();
                while (reader.Read())
                {
                    var name = reader.GetString(0);
                    if (!Bookkeeping.Contains(name)) { tables.Add(name); }
                }
            }

            var columns = new Dictionary<string, IReadOnlyList<(string, string)>>(StringComparer.OrdinalIgnoreCase);
            var indexes = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
            var rowid = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var table in tables)
            {
                var cols = new List<(string, string)>();
                using (var info = db.CreateCommand())
                {
                    info.CommandText = $"SELECT name, type, pk FROM pragma_table_info('{table}') ORDER BY cid";
                    using var reader = info.ExecuteReader();
                    while (reader.Read())
                    {
                        cols.Add((reader.GetString(0), reader.GetString(1)));
                        if (reader.GetInt64(2) == 1 && reader.GetString(1).Equals("INTEGER", StringComparison.OrdinalIgnoreCase))
                        {
                            rowid.Add(table);
                        }
                    }
                }
                columns[table] = cols;

                // The schema's own indexes, made non-unique and moved to TEMP.
                // Unique ones cannot survive a union: aggregate_records.id is
                // a rowid, so every file has its own 1, 2, 3. An index on id
                // is added for every table that has one, because the
                // PRIMARY KEY that used to serve joins on it is not copied.
                var made = new List<string>();
                using (var list = db.CreateCommand())
                {
                    list.CommandText =
                        "SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = $t AND sql IS NOT NULL";
                    list.Parameters.AddWithValue("$t", table);
                    using var reader = list.ExecuteReader();
                    while (reader.Read())
                    {
                        made.Add(IndexStatement().Replace(reader.GetString(0), "CREATE INDEX temp.$2 ON", 1));
                    }
                }
                if (cols.Any(c => c.Item1 == "id"))
                {
                    made.Add($"CREATE INDEX temp.union_{table}_id ON {table}(id)");
                }
                indexes[table] = made;
            }

            return new ReferenceSchema(tables, columns, indexes, rowid);
        }
    }

    [GeneratedRegex(@"^CREATE\s+(UNIQUE\s+)?INDEX\s+(\w+)\s+ON", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IndexStatement();

    // ---- connections ----------------------------------------------------------

    /// <summary>
    /// The organization's database on its own: clients, domains, people, the
    /// audit log. No client's mail is reachable from it.
    /// </summary>
    public async Task<SqliteConnection> OpenRegistryAsync(bool write = false, CancellationToken ct = default)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            // A URI rather than a path, because only a connection opened from
            // one lets ATTACH take a URI - and the files a union copies from
            // are attached read-only through ?mode=ro, whatever this is.
            DataSource = SqliteUri(RegistryPath, readOnly: false),
            Mode = write ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
            Pooling = false,
            ForeignKeys = write ? true : null,
        }.ToString());

        try
        {
            await db.OpenAsync(ct).ConfigureAwait(false);
            return db;
        }
        catch
        {
            await db.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// The organization's database, with the tables of the clients in
    /// <paramref name="scope"/> readable as if they were in it.
    /// </summary>
    /// <param name="tables">
    /// Which client tables a query here reads, when the scope may be several
    /// clients: only those are copied. Null copies every table. Ignored for one
    /// client, whose file is attached whole.
    /// </param>
    /// <param name="write">
    /// Whether this connection writes into the client's file (and the
    /// organization's database). Writing needs the scope to be exactly one
    /// client, whose file is created if it does not exist yet; a union is a
    /// copy, and a write to it would be lost when the connection closes.
    /// </param>
    /// <param name="writeRegistry">
    /// Whether the organization's database is opened for writing while the
    /// clients' tables are only read - for what is derived across clients and
    /// kept in it, such as the threat indicators.
    /// </param>
    public async Task<SqliteConnection> OpenAsync(
        ClientScope scope, IReadOnlyCollection<string>? tables = null, bool write = false, bool writeRegistry = false,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var db = await OpenRegistryAsync(write || writeRegistry, ct).ConfigureAwait(false);
        try
        {
            await EnsureSplitAsync(db, "main", ct).ConfigureAwait(false);
            var clients = await ResolveAsync(db, scope, ct).ConfigureAwait(false);

            if (clients.Count == 1)
            {
                var client = clients[0];
                var path = write
                    ? await EnsureFileAsync(client, ct).ConfigureAwait(false)
                    : PathFor(client);

                if (File.Exists(path))
                {
                    await AttachAsync(db, path, Attached, client, readOnly: !write, ct).ConfigureAwait(false);
                    return db;
                }
            }
            else if (write)
            {
                throw new InvalidOperationException(clients.Count == 0
                    ? "There is no client to write for: the organization's database has none matching."
                    : $"Writing needs exactly one client's file, and {clients.Count} match.");
            }

            // Several clients, or one that has nothing stored yet: the union,
            // which for a client with no file is the tables with no rows.
            await UnionAsync(db, clients, tables, ct).ConfigureAwait(false);
            return db;
        }
        catch
        {
            await db.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// The name the organization's database is attached as on a connection
    /// that has a client's file as main; see <see cref="OpenClientFirstAsync"/>.
    /// </summary>
    internal const string Organization = "org";

    /// <summary>
    /// A client's file as main, with the organization's database attached as
    /// <c>org</c>: for writes that take a row id from the organization's
    /// database (<see cref="AllocateIdsAsync"/>).
    /// </summary>
    /// <remarks>
    /// The order of the two is the point. SQLite commits the files of a
    /// transaction main first, so on this connection a row reaches its client's
    /// file before the id handed out for it is committed in the organization's
    /// database - and anything that sees next_id at N can rely on every row
    /// below N already being in its file. With the organization's database as
    /// main, an id could be visible for a moment before its row, and an export
    /// resuming from the last id it wrote could step over the row for good.
    /// </remarks>
    internal async Task<SqliteConnection> OpenClientFirstAsync(ClientFile client, CancellationToken ct)
    {
        var path = await EnsureFileAsync(client, ct).ConfigureAwait(false);

        var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = SqliteUri(path, readOnly: false),
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            ForeignKeys = true,
        }.ToString());

        try
        {
            await db.OpenAsync(ct).ConfigureAwait(false);

            await using (var check = db.CreateCommand())
            {
                check.CommandText = "SELECT client_id FROM main.client_file LIMIT 1";
                var owner = await check.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
                if (!string.Equals(owner, client.Id, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"{path} belongs to client {owner ?? "(none recorded)"}, not {client.Id} ({client.Slug}). "
                        + "Nothing was written to it.");
                }
            }

            await using (var attach = db.CreateCommand())
            {
                attach.CommandText = $"ATTACH DATABASE $file AS {Organization}";
                attach.Parameters.AddWithValue("$file", SqliteUri(RegistryPath, readOnly: false));
                await attach.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await EnsureSplitAsync(db, Organization, ct).ConfigureAwait(false);
            return db;
        }
        catch
        {
            await db.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Hands out <paramref name="count"/> consecutive row ids for a
    /// rowid-keyed table, on a connection from <see cref="OpenClientFirstAsync"/>
    /// and in its transaction, and returns the first.
    /// </summary>
    /// <remarks>
    /// Never an id at or below one already in the client's file. The sequence
    /// is in the organization's database and the rows are in the files, so
    /// putting the organization's database back from a copy older than the
    /// files - one restored without the other - leaves the sequence behind
    /// them, and the next report would take an id its file already holds and
    /// fail to store at all, every night, until somebody worked out why.
    /// <see cref="ReconcileAsync"/> puts the sequence right across every file;
    /// this keeps the file being written safe until it has run. Reading the
    /// largest id of a rowid table is one step down its b-tree, not a scan.
    /// </remarks>
    internal static Task<long> AllocateIdsAsync(
        SqliteConnection db, SqliteTransaction tx, string table, int count, CancellationToken ct) =>
        AllocateIdsAsync(db, tx, Organization, "main", table, count, ct);

    /// <param name="registry">Where the organization's database is on this connection.</param>
    /// <param name="file">Where the client file the ids are for is on this connection.</param>
    internal static async Task<long> AllocateIdsAsync(
        SqliteConnection db, SqliteTransaction tx, string registry, string file, string table, int count,
        CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (!RowidTables.Contains(table))
        {
            throw new ArgumentException($"{table} is not a client table keyed by a row id.", nameof(table));
        }

        await using var command = db.CreateCommand();
        command.Transaction = tx;

        // The table name is checked against the schema above, and the two
        // schema names are this class's own, so they are interpolated; the
        // values are bound.
        command.CommandText = $"""
            UPDATE {registry}.row_ids
               SET next_id = MAX(next_id, (SELECT COALESCE(MAX(id), 0) + 1 FROM {file}.{table})) + $n
             WHERE table_name = $t
            RETURNING next_id - $n
            """;
        command.Parameters.AddWithValue("$n", count);
        command.Parameters.AddWithValue("$t", table);

        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) is long first
            ? first
            : throw new InvalidOperationException(
                $"The organization's database has no row id sequence for {table}; run dmarc init-db.");
    }

    /// <summary>
    /// The first row id not yet handed out for a table: every row below it is
    /// already in its client's file (see <see cref="OpenClientFirstAsync"/>).
    /// </summary>
    public async Task<long> NextIdAsync(string table, CancellationToken ct = default)
    {
        await using var db = await OpenRegistryAsync(write: false, ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT next_id FROM main.row_ids WHERE table_name = $t";
        command.Parameters.AddWithValue("$t", table);
        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) is long next ? next : long.MaxValue;
    }

    /// <summary>Set once the organization's database is known to have been split.</summary>
    private volatile bool _split;

    /// <summary>
    /// Refuses a database that still holds every client's reports itself.
    /// </summary>
    /// <remarks>
    /// Before 0019 the reports are in the organization's database, and a
    /// connection here would make a client's tables out of files that do not
    /// exist yet: every page would open, and show nothing. Nothing is read or
    /// changed; the message says the one command that fixes it.
    /// </remarks>
    private async Task EnsureSplitAsync(SqliteConnection db, string schema, CancellationToken ct)
    {
        if (_split) { return; }

        await using var command = db.CreateCommand();
        command.CommandText = $"""
            SELECT
              (SELECT COUNT(*) FROM {schema}.sqlite_master WHERE type = 'table' AND name = 'aggregate_records'),
              (SELECT COALESCE(MAX(version), 'none') FROM {schema}.schema_migrations)
            """;
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        await reader.ReadAsync(ct).ConfigureAwait(false);

        if (reader.GetInt64(0) > 0)
        {
            throw new DatabaseNotSplitException(RegistryPath, reader.GetString(1));
        }

        _split = true;
    }

    /// <summary>The clients a scope names, from the organization's database.</summary>
    /// <remarks>
    /// Soft-deleted clients are included. Their rows were visible to every
    /// query before the split, and the queries that should not show them say
    /// so in their own WHERE clauses; narrowing here would change what those
    /// queries mean.
    /// </remarks>
    public async Task<IReadOnlyList<ClientFile>> ResolveAsync(ClientScope scope, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        await using var db = await OpenRegistryAsync(write: false, ct).ConfigureAwait(false);
        return await ResolveAsync(db, scope, ct).ConfigureAwait(false);
    }

    internal static async Task<IReadOnlyList<ClientFile>> ResolveAsync(
        SqliteConnection registry, ClientScope scope, CancellationToken ct)
    {
        await using var command = registry.CreateCommand();
        command.CommandText = """
            SELECT c.id, c.slug, c.tenant_id
            FROM main.clients c
            WHERE ($tenant IS NULL OR c.tenant_id = $tenant)
              AND ($id IS NULL OR c.id = $id)
              AND ($slug IS NULL OR c.slug = $slug)
              AND ($domain IS NULL OR EXISTS
                    (SELECT 1 FROM main.domains d WHERE d.client_id = c.id AND d.name = $domain))
              AND ($domainId IS NULL OR EXISTS
                    (SELECT 1 FROM main.domains d WHERE d.client_id = c.id AND d.id = $domainId))
            ORDER BY c.id
            """;
        command.Parameters.AddWithValue("$tenant", (object?)scope.TenantId ?? DBNull.Value);
        command.Parameters.AddWithValue("$id", (object?)scope.ClientId ?? DBNull.Value);
        command.Parameters.AddWithValue("$slug", (object?)scope.ClientSlug ?? DBNull.Value);
        command.Parameters.AddWithValue("$domain", (object?)scope.DomainName ?? DBNull.Value);
        command.Parameters.AddWithValue("$domainId", (object?)scope.DomainId ?? DBNull.Value);

        var found = new List<ClientFile>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            found.Add(new ClientFile(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }
        return found;
    }

    /// <summary>
    /// Runs <paramref name="action"/> on each client file in scope, one at a
    /// time, until it returns true.
    /// </summary>
    /// <remarks>
    /// For finding the one file that holds a row known by an id - a drift
    /// event to acknowledge, a DNS change to roll back - and for work that is
    /// done file by file. Clients with no file yet are skipped: there is
    /// nothing in them to find.
    /// </remarks>
    /// <returns>True when the action returned true for some file.</returns>
    public async Task<bool> FirstAsync(
        ClientScope scope, bool write,
        Func<SqliteConnection, ClientFile, CancellationToken, Task<bool>> action, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(action);

        foreach (var client in await ResolveAsync(scope, ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(PathFor(client))) { continue; }

            await using var db = await OpenAsync(ClientScope.Client(client.Id), write: write, ct: ct).ConfigureAwait(false);
            if (await action(db, client, ct).ConfigureAwait(false)) { return true; }
        }

        return false;
    }

    /// <summary>
    /// For each address, how many of an organization's clients hold failing
    /// mail from it - asked of each client's file in turn.
    /// </summary>
    /// <remarks>
    /// The cross-client figure the per-client pages carry ("seen at 3 other
    /// customers"). Each file is asked only which of these addresses failed
    /// in it, so a count is all that leaves one client's file for another's
    /// page. The organization's clients only: another organization's
    /// customers are none of this one's business, and were being counted.
    /// </remarks>
    /// <param name="exceptClientId">A client not to count - the one the page is about.</param>
    /// <param name="exceptDomainId">A domain whose own rows do not count - the one the page is about.</param>
    public async Task<IReadOnlyDictionary<string, int>> ClientsFailingAsync(
        string tenantId, IReadOnlyCollection<string> addresses,
        string? exceptClientId = null, string? exceptDomainId = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentNullException.ThrowIfNull(addresses);

        var reach = new Dictionary<string, int>(StringComparer.Ordinal);
        if (addresses.Count == 0) { return reach; }

        var list = System.Text.Json.JsonSerializer.Serialize(addresses.Distinct(StringComparer.Ordinal));

        await FirstAsync(ClientScope.Organization(tenantId), write: false, async (db, client, token) =>
        {
            if (client.Id == exceptClientId) { return false; }

            await using var command = db.CreateCommand();
            command.CommandText = $"""
                SELECT DISTINCT source_ip FROM {Attached}.aggregate_records
                WHERE dmarc_result = 'fail'
                  AND source_ip IN (SELECT value FROM json_each($ips))
                  AND ($domain IS NULL OR domain_id <> $domain)
                """;
            command.Parameters.AddWithValue("$ips", list);
            command.Parameters.AddWithValue("$domain", (object?)exceptDomainId ?? DBNull.Value);

            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                var ip = reader.GetString(0);
                reach[ip] = reach.GetValueOrDefault(ip) + 1;
            }

            return false;   // every file, not the first
        }, ct).ConfigureAwait(false);

        return reach;
    }

    /// <summary>Every client of one organization, or of all of them, with where its file is.</summary>
    public Task<IReadOnlyList<ClientFile>> ListAsync(string? tenantId = null, CancellationToken ct = default) =>
        ResolveAsync(ClientScope.Organization(tenantId), ct);

    /// <summary>
    /// Attaches a client's file, having checked it is theirs.
    /// </summary>
    /// <remarks>
    /// The file says whose it is (client_file, written when it was created).
    /// A file copied or renamed into another client's place - by hand, from a
    /// backup, or by a bug in naming - would otherwise be read as theirs, and
    /// shown to their login.
    /// </remarks>
    internal static async Task AttachAsync(
        SqliteConnection db, string path, string alias, ClientFile client, bool readOnly, CancellationToken ct)
    {
        await using (var attach = db.CreateCommand())
        {
            attach.CommandText = $"ATTACH DATABASE $file AS {alias}";
            attach.Parameters.AddWithValue("$file", SqliteUri(path, readOnly));
            await attach.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        string? owner;
        await using (var check = db.CreateCommand())
        {
            check.CommandText = $"SELECT client_id FROM {alias}.client_file LIMIT 1";
            try
            {
                owner = await check.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
            }
            catch (SqliteException ex)
            {
                throw new InvalidOperationException(
                    $"{path} is not a client file this product wrote ({ex.Message}). It was not read.", ex);
            }
        }

        if (!string.Equals(owner, client.Id, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{path} belongs to client {owner ?? "(none recorded)"}, not {client.Id} ({client.Slug}). "
                + "It was not read as theirs.");
        }
    }

    /// <summary>
    /// Fills TEMP tables named like a client file's with the rows of every file
    /// in <paramref name="clients"/>.
    /// </summary>
    /// <remarks>
    /// Constraints are left off: rowid keys repeat from file to file, and the
    /// copy is read, never written. Each file is read in one transaction, so
    /// its tables are copied as of one moment; files are read one after
    /// another, so two clients may be a moment apart, which no query here
    /// depends on.
    /// </remarks>
    private async Task UnionAsync(
        SqliteConnection db, IReadOnlyList<ClientFile> clients, IReadOnlyCollection<string>? only, CancellationToken ct)
    {
        var reference = Reference.Value;
        var tables = only is null
            ? reference.Tables
            : [.. reference.Tables.Where(t => only.Contains(t, StringComparer.OrdinalIgnoreCase))];

        if (only is not null)
        {
            var unknown = only.Where(t => !reference.Tables.Contains(t, StringComparer.OrdinalIgnoreCase)).ToList();
            if (unknown.Count > 0)
            {
                throw new ArgumentException(
                    $"Not a client table: {string.Join(", ", unknown)}.", nameof(only));
            }
        }

        // In memory: the rows are other people's mail, and TEMP otherwise
        // spills to a file in the system's temp folder.
        await ExecuteAsync(db, "PRAGMA temp_store = MEMORY", ct).ConfigureAwait(false);

        foreach (var table in tables)
        {
            var columns = string.Join(", ", reference.Columns[table].Select(c => $"{c.Name} {c.Type}".Trim()));
            await ExecuteAsync(db, $"CREATE TEMP TABLE {table} ({columns})", ct).ConfigureAwait(false);
        }

        foreach (var client in clients)
        {
            ct.ThrowIfCancellationRequested();

            var path = PathFor(client);
            if (!File.Exists(path)) { continue; }

            await AttachAsync(db, path, Source, client, readOnly: true, ct).ConfigureAwait(false);
            try
            {
                await ExecuteAsync(db, "BEGIN", ct).ConfigureAwait(false);
                try
                {
                    foreach (var table in tables)
                    {
                        // By name, not position, and only the columns both
                        // sides have: a file a migration has not reached yet
                        // still copies what it does have.
                        var present = await ColumnsAsync(db, Source, table, ct).ConfigureAwait(false);
                        var shared = reference.Columns[table].Select(c => c.Name).Where(present.Contains).ToList();
                        if (shared.Count == 0) { continue; }

                        var list = string.Join(", ", shared);
                        await ExecuteAsync(db,
                            $"INSERT INTO temp.{table} ({list}) SELECT {list} FROM {Source}.{table}", ct)
                            .ConfigureAwait(false);
                    }
                    await ExecuteAsync(db, "COMMIT", ct).ConfigureAwait(false);
                }
                catch
                {
                    await ExecuteAsync(db, "ROLLBACK", CancellationToken.None).ConfigureAwait(false);
                    throw;
                }
            }
            finally
            {
                await ExecuteAsync(db, $"DETACH DATABASE {Source}", CancellationToken.None).ConfigureAwait(false);
            }
        }

        // After the rows, so each index is built once rather than maintained
        // through every insert.
        foreach (var table in tables)
        {
            foreach (var index in reference.TempIndexes[table])
            {
                await ExecuteAsync(db, index, ct).ConfigureAwait(false);
            }
        }
    }

    private static async Task<HashSet<string>> ColumnsAsync(
        SqliteConnection db, string schema, string table, CancellationToken ct)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var command = db.CreateCommand();
        command.CommandText = $"SELECT name FROM pragma_table_info('{table}', '{schema}')";
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false)) { columns.Add(reader.GetString(0)); }
        return columns;
    }

    // ---- creating a file ------------------------------------------------------

    /// <summary>
    /// The client's file, created from client-schema.sql if it does not exist yet.
    /// </summary>
    /// <remarks>
    /// Built under a temporary name and renamed into place, so a process that
    /// finds the file finds a whole one, and two processes creating the same
    /// client's file at once end up with one of them rather than a half of each.
    /// </remarks>
    public async Task<string> EnsureFileAsync(ClientFile client, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        var path = PathFor(client);
        if (File.Exists(path)) { return path; }

        CreateFolder(Folder);
        var staging = $"{path}.new-{Guid.NewGuid():N}";

        try
        {
            await CreateAtAsync(staging, client, ct).ConfigureAwait(false);

            try
            {
                File.Move(staging, path);
            }
            catch (IOException) when (File.Exists(path))
            {
                // Somebody else made it first. Theirs is as good as this one.
            }
        }
        finally
        {
            DeleteFileAndJournals(staging);
        }

        return path;
    }

    /// <summary>Writes a new, empty client file at a path.</summary>
    internal static async Task CreateAtAsync(string path, ClientFile client, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await ExecuteAsync(db, DatabaseSchema.ClientSql, ct).ConfigureAwait(false);
        OwnerOnly(path, directory: false);

        await using var owner = db.CreateCommand();
        owner.CommandText = "INSERT INTO client_file (client_id, created_at) VALUES ($id, $at)";
        owner.Parameters.AddWithValue("$id", client.Id);
        owner.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.UtcDateTime
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        await owner.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>A folder for client files, readable by this account alone.</summary>
    internal static void CreateFolder(string folder)
    {
        if (Directory.Exists(folder)) { return; }
        Directory.CreateDirectory(folder);
        OwnerOnly(folder, directory: true);
    }

    /// <summary>
    /// Takes a client file, or the folder of them, down to its owner alone:
    /// 0600 and 0700.
    /// </summary>
    /// <remarks>
    /// Every client's mail is in that folder, and the process umask would
    /// leave it 0755 with each file 0644 - readable by any account that can
    /// reach it. The data directory above it is closed to other accounts on
    /// an install made by deploy/install.sh, and this does not rely on that.
    /// SQLite gives a file's journals the mode of the file, so they follow.
    /// Unix only: on Windows the folder inherits the data directory's ACL,
    /// which the installer restricts. Failing to tighten it never fails the
    /// write - the file is still where it should be, with what it should hold.
    /// </remarks>
    internal static void OwnerOnly(string path, bool directory)
    {
        if (OperatingSystem.IsWindows()) { return; }

        try
        {
            File.SetUnixFileMode(path, directory
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                : UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
        }
    }

    /// <summary>A database file and the journal files SQLite keeps beside it.</summary>
    internal static void DeleteFileAndJournals(string path)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            try { File.Delete(path + suffix); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    // ---- client file migrations -----------------------------------------------

    /// <summary>
    /// Changes to client-schema.sql after its baseline, in order: db/client-migrations.
    /// </summary>
    public static IReadOnlyList<Migration> Migrations { get; } = LoadMigrations();

    /// <summary>The version client-schema.sql builds a file at.</summary>
    public const string BaselineVersion = "0001";

    /// <summary>
    /// Brings every client file of this organization's database up to the
    /// current client schema, and says which files changed.
    /// </summary>
    public async Task<IReadOnlyList<string>> MigrateAllAsync(CancellationToken ct = default)
    {
        var changed = new List<string>();
        if (Migrations.Count == 0 || !Directory.Exists(Folder)) { return changed; }

        foreach (var client in await ListAsync(ct: ct).ConfigureAwait(false))
        {
            var path = PathFor(client);
            if (!File.Exists(path)) { continue; }

            var result = await DatabaseMigrations.ApplyAsync(path, Migrations, ct).ConfigureAwait(false);
            if (result.Changed) { changed.Add(Path.GetFileName(path)); }
        }

        return changed;
    }

    private static List<Migration> LoadMigrations()
    {
        var assembly = Assembly.GetExecutingAssembly();

        return [.. assembly
            .GetManifestResourceNames()
            .Where(name => name.StartsWith("client-migration.", StringComparison.Ordinal)
                        && name.EndsWith(".sql", StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .Select(name =>
            {
                using var stream = assembly.GetManifestResourceStream(name)!;
                using var reader = new StreamReader(stream);
                var parts = name["client-migration.".Length..].Replace(".sql", "", StringComparison.Ordinal).Split('-', 2);
                return new Migration(parts[0], parts.Length > 1 ? parts[1].Replace('-', ' ') : parts[0], reader.ReadToEnd());
            })];
    }

    // ---- moving a domain's rows between files ----------------------------------

    /// <summary>
    /// Moves one domain's rows from one attached client file to another, in the
    /// caller's transaction, merging rather than overwriting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A merge, so it is safe to run again. SQLite commits each file of a
    /// transaction separately in WAL mode, so a move interrupted mid-commit can
    /// leave the rows in both files - and reports stored for the domain after
    /// the organization's database said it had moved are only in the new one.
    /// Rows the destination already holds are left alone: unique keys decide
    /// for most tables (INSERT OR IGNORE), and the two that have none,
    /// aggregate_records and tls_failure_details, follow their report - a
    /// report is copied with its rows or not at all, so a report already
    /// there already has them.
    /// </para>
    /// <para>
    /// Rowid-keyed rows keep their ids, which are shared across files. Whose
    /// the rows are is rewritten to the destination's client; a record's
    /// pointer into the source client's inventory of senders is cleared,
    /// since that inventory stays with the source.
    /// </para>
    /// </remarks>
    internal static async Task MoveDomainRowsAsync(
        SqliteConnection db, SqliteTransaction tx, string from, string to,
        string domainId, ClientFile destination, CancellationToken ct)
    {
        foreach (var table in DomainTables)
        {
            var columns = (await ColumnsAsync(db, to, table, ct).ConfigureAwait(false))
                .Intersect(await ColumnsAsync(db, from, table, ct).ConfigureAwait(false), StringComparer.OrdinalIgnoreCase)
                .ToList();

            // idAs, when given, is what the id column is written as instead.
            string Values(string alias, bool withId, string? idAs = null) => string.Join(", ", columns
                .Where(c => withId || c != "id")
                .Select(c => c switch
                {
                    "id" when idAs is not null => idAs,
                    "client_id" => "$client",
                    "tenant_id" => "$tenant",
                    "sender_id" => "NULL",
                    _ => $"{alias}.{c}",
                }));

            string Columns(bool withId) => string.Join(", ", columns.Where(c => withId || c != "id"));

            var already = table switch
            {
                "aggregate_records" =>
                    $" AND NOT EXISTS (SELECT 1 FROM {to}.aggregate_records x WHERE x.report_id = s.report_id)",
                "tls_failure_details" =>
                    $" AND NOT EXISTS (SELECT 1 FROM {to}.tls_failure_details x WHERE x.tls_report_id = s.tls_report_id)",
                _ => "",
            };

            if (!RowidTables.Contains(table))
            {
                await RunAsync(db, tx,
                    $"INSERT OR IGNORE INTO {to}.{table} ({Columns(true)}) "
                    + $"SELECT {Values("s", true)} FROM {from}.{table} s WHERE {DomainRows(table, from, "s")}{already}",
                    destination, domainId, ct).ConfigureAwait(false);
                continue;
            }

            // Rowid-keyed rows keep their ids, which are unique across every
            // file (see row_ids in schema.sql). A row may still find its id
            // taken in the destination - by a hand-edited file, or after the
            // sequence was behind the files (see AllocateIdsAsync) - and is
            // then given a new one from the sequence rather than lost, or
            // numbered by the destination alone, which could repeat an id
            // another file holds. Which rows collide is decided before any is
            // copied, so the copy cannot see its own writes.
            await RunAsync(db, tx, "DROP TABLE IF EXISTS temp.moving", destination, domainId, ct).ConfigureAwait(false);
            await RunAsync(db, tx,
                $"CREATE TEMP TABLE moving AS SELECT s.*, "
                + $"EXISTS (SELECT 1 FROM {to}.{table} x WHERE x.id = s.id) AS collides "
                + $"FROM {from}.{table} s WHERE {DomainRows(table, from, "s")}{already}",
                destination, domainId, ct).ConfigureAwait(false);
            await RunAsync(db, tx,
                $"INSERT INTO {to}.{table} ({Columns(true)}) SELECT {Values("m", true)} FROM temp.moving m WHERE m.collides = 0",
                destination, domainId, ct).ConfigureAwait(false);

            int collisions;
            await using (var count = db.CreateCommand())
            {
                count.Transaction = tx;
                count.CommandText = "SELECT COUNT(*) FROM temp.moving WHERE collides = 1";
                collisions = Convert.ToInt32(await count.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0, CultureInfo.InvariantCulture);
            }

            if (collisions > 0)
            {
                // Both callers have the organization's database as main.
                var first = await AllocateIdsAsync(db, tx, "main", to, table, collisions, ct).ConfigureAwait(false);
                var renumbered = Values("m", true,
                    idAs: $"{first.ToString(CultureInfo.InvariantCulture)} + ROW_NUMBER() OVER (ORDER BY m.id) - 1");
                await RunAsync(db, tx,
                    $"INSERT INTO {to}.{table} ({Columns(true)}) SELECT {renumbered} FROM temp.moving m WHERE m.collides = 1",
                    destination, domainId, ct).ConfigureAwait(false);
            }

            await RunAsync(db, tx, "DROP TABLE temp.moving", destination, domainId, ct).ConfigureAwait(false);
        }

        // Children first, so no foreign key inside the source is broken on the way.
        foreach (var table in DomainTables.Reverse())
        {
            await RunAsync(db, tx, $"DELETE FROM {from}.{table} WHERE {DomainRows(table, from)}",
                destination, domainId, ct).ConfigureAwait(false);
        }
    }

    /// <summary>The rows of one table that belong to the domain, with columns qualified by <paramref name="alias"/> when given.</summary>
    private static string DomainRows(string table, string schema, string? alias = null)
    {
        var prefix = alias is null ? "" : alias + ".";
        return table == "tls_failure_details"
            ? $"{prefix}tls_report_id IN (SELECT id FROM {schema}.tls_reports WHERE domain_id = $domain)"
            : $"{prefix}domain_id = $domain";
    }

    private static async Task RunAsync(
        SqliteConnection db, SqliteTransaction tx, string sql, ClientFile destination, string domainId, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.Transaction = tx;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$client", destination.Id);
        command.Parameters.AddWithValue("$tenant", destination.TenantId);
        command.Parameters.AddWithValue("$domain", domainId);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    // ---- putting files right against the organization's database -------------

    /// <summary>
    /// Makes every client file agree with the organization's database, and
    /// says what it changed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The organization's database is the truth about who owns what; the files
    /// follow it. Two operations change both - filing a domain under another
    /// client, and moving a client to another organization - and SQLite in WAL
    /// mode commits each file of a transaction separately, so a crash at the
    /// wrong instant can leave them disagreeing. This finds and repairs both
    /// kinds of disagreement:
    /// </para>
    /// <list type="bullet">
    /// <item>rows for a domain another client now owns are merged into that client's file;</item>
    /// <item>rows whose client or organization is not the file's are rewritten to it.</item>
    /// </list>
    /// <para>
    /// Rows for a domain the organization's database no longer has at all are
    /// counted and left where they are: there is no owner to give them to,
    /// and deleting a customer's data is never something to do by inference.
    /// Run by init-db, and harmless to run at any time.
    /// </para>
    /// </remarks>
    public async Task<ReconcileResult> ReconcileAsync(CancellationToken ct = default)
    {
        var moved = new List<string>();
        long retagged = 0, homeless = 0;
        var refused = new List<string>();

        if (!Directory.Exists(Folder)) { return new ReconcileResult(moved, retagged, homeless, refused, []); }

        IReadOnlyList<ClientFile> clients;
        Dictionary<string, ClientFile> owners;
        await using (var registry = await OpenRegistryAsync(write: false, ct).ConfigureAwait(false))
        {
            clients = await ResolveAsync(registry, ClientScope.Organization(null), ct).ConfigureAwait(false);
            var byId = clients.ToDictionary(c => c.Id, StringComparer.Ordinal);

            owners = new Dictionary<string, ClientFile>(StringComparer.Ordinal);
            await using var domains = registry.CreateCommand();
            domains.CommandText = "SELECT id, client_id FROM main.domains";
            await using var reader = await domains.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (byId.TryGetValue(reader.GetString(1), out var owner)) { owners[reader.GetString(0)] = owner; }
            }
        }

        foreach (var client in clients)
        {
            ct.ThrowIfCancellationRequested();

            var path = PathFor(client);
            if (!File.Exists(path)) { continue; }

            // Which domains this file holds rows for.
            var held = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                await using var file = await OpenAsync(ClientScope.Client(client.Id), ct: ct).ConfigureAwait(false);
                foreach (var table in DomainTables.Where(t => t != "tls_failure_details"))
                {
                    await using var list = file.CreateCommand();
                    list.CommandText = $"SELECT DISTINCT domain_id FROM {Attached}.{table} WHERE domain_id IS NOT NULL";
                    await using var reader = await list.ExecuteReaderAsync(ct).ConfigureAwait(false);
                    while (await reader.ReadAsync(ct).ConfigureAwait(false)) { held.Add(reader.GetString(0)); }
                }
            }
            catch (InvalidOperationException ex)
            {
                // Not this client's file, or not a client file. Said, and not touched.
                refused.Add(ex.Message);
                continue;
            }

            foreach (var domainId in held)
            {
                if (!owners.TryGetValue(domainId, out var owner))
                {
                    homeless += await CountDomainRowsAsync(client, domainId, ct).ConfigureAwait(false);
                    continue;
                }

                if (owner.Id == client.Id) { continue; }

                var target = await EnsureFileAsync(owner, ct).ConfigureAwait(false);
                await using var db = await OpenRegistryAsync(write: true, ct).ConfigureAwait(false);
                await AttachAsync(db, path, "src", client, readOnly: false, ct).ConfigureAwait(false);
                await AttachAsync(db, target, "dst", owner, readOnly: false, ct).ConfigureAwait(false);
                await using var tx = db.BeginTransaction(deferred: false);
                await MoveDomainRowsAsync(db, tx, "src", "dst", domainId, owner, ct).ConfigureAwait(false);
                await tx.CommitAsync(ct).ConfigureAwait(false);
                moved.Add($"{domainId}: {client.Slug} -> {owner.Slug}");
            }

            // Every row in a client's file is that client's, in that client's organization.
            await using (var file = await OpenAsync(ClientScope.Client(client.Id), write: true, ct: ct).ConfigureAwait(false))
            await using (var tx = file.BeginTransaction(deferred: false))
            {
                foreach (var table in Tables)
                {
                    await using var update = file.CreateCommand();
                    update.Transaction = tx;
                    update.CommandText =
                        $"UPDATE {Attached}.{table} SET client_id = $client, tenant_id = $tenant "
                        + "WHERE client_id IS NOT $client OR tenant_id IS NOT $tenant";
                    update.Parameters.AddWithValue("$client", client.Id);
                    update.Parameters.AddWithValue("$tenant", client.TenantId);
                    retagged += await update.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                }
                await tx.CommitAsync(ct).ConfigureAwait(false);
            }
        }

        var raised = await RaiseSequencesAsync(clients, ct).ConfigureAwait(false);
        return new ReconcileResult(moved, retagged, homeless, refused, raised);
    }

    /// <summary>
    /// Puts each row id sequence past the largest id in any client's file.
    /// </summary>
    /// <remarks>
    /// A sequence behind the files means the organization's database was put
    /// back from a copy older than they are. Ids handed out from it would
    /// repeat ones already stored - in another client's file, where nothing
    /// refuses them, and an export resuming from the last id it wrote would
    /// step over rows it has never sent.
    /// </remarks>
    private async Task<IReadOnlyList<string>> RaiseSequencesAsync(IReadOnlyList<ClientFile> clients, CancellationToken ct)
    {
        var highest = RowidTables.ToDictionary(t => t, _ => 0L, StringComparer.Ordinal);

        foreach (var client in clients)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(PathFor(client))) { continue; }

            try
            {
                await using var file = await OpenAsync(ClientScope.Client(client.Id), ct: ct).ConfigureAwait(false);
                foreach (var table in RowidTables)
                {
                    await using var max = file.CreateCommand();
                    max.CommandText = $"SELECT COALESCE(MAX(id), 0) FROM {Attached}.{table}";
                    var id = Convert.ToInt64(await max.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture);
                    highest[table] = Math.Max(highest[table], id);
                }
            }
            catch (InvalidOperationException)
            {
                // Not this client's file: already reported, and not read.
            }
        }

        var raised = new List<string>();
        await using var registry = await OpenRegistryAsync(write: true, ct).ConfigureAwait(false);
        await using var tx = registry.BeginTransaction(deferred: false);
        foreach (var (table, id) in highest.OrderBy(h => h.Key, StringComparer.Ordinal))
        {
            await using var raise = registry.CreateCommand();
            raise.Transaction = tx;
            raise.CommandText =
                "UPDATE main.row_ids SET next_id = $next WHERE table_name = $t AND next_id < $next RETURNING next_id";
            raise.Parameters.AddWithValue("$next", id + 1);
            raise.Parameters.AddWithValue("$t", table);
            if (await raise.ExecuteScalarAsync(ct).ConfigureAwait(false) is not null)
            {
                raised.Add($"{table}: now continues from {id + 1:N0}");
            }
        }
        await tx.CommitAsync(ct).ConfigureAwait(false);

        return raised;
    }

    private async Task<long> CountDomainRowsAsync(ClientFile client, string domainId, CancellationToken ct)
    {
        long rows = 0;
        await using var file = await OpenAsync(ClientScope.Client(client.Id), ct: ct).ConfigureAwait(false);
        foreach (var table in DomainTables)
        {
            await using var count = file.CreateCommand();
            count.CommandText = $"SELECT COUNT(*) FROM {Attached}.{table} WHERE {DomainRows(table, Attached)}";
            count.Parameters.AddWithValue("$domain", domainId);
            rows += Convert.ToInt64(await count.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture);
        }
        return rows;
    }

    // ---- helpers --------------------------------------------------------------

    /// <summary>
    /// A path as the URI SQLite takes, with the three characters that mean
    /// something in one escaped, and <c>mode=ro</c> when it is only to be read.
    /// </summary>
    internal static string SqliteUri(string path, bool readOnly)
    {
        var full = Path.GetFullPath(path).Replace('\\', '/');
        var uri = new StringBuilder("file:");

        // C:/data/x.db is file:///C:/data/x.db; //server/share/x.db keeps its
        // two slashes as the path after an empty authority.
        if (!full.StartsWith('/')) { uri.Append("///"); }
        else if (full.StartsWith("//", StringComparison.Ordinal)) { uri.Append("//"); }

        foreach (var ch in full)
        {
            if (ch is '%' or '?' or '#')
            {
                uri.Append('%').Append(((int)ch).ToString("x2", CultureInfo.InvariantCulture));
            }
            else
            {
                uri.Append(ch);
            }
        }

        if (readOnly) { uri.Append("?mode=ro"); }
        return uri.ToString();
    }

    private static async Task ExecuteAsync(SqliteConnection db, string sql, CancellationToken ct)
    {
        await using var command = db.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}

/// <summary>
/// The database still holds every client's reports itself: it was made by a
/// version from before one file per client, and has not been through init-db
/// since.
/// </summary>
public sealed class DatabaseNotSplitException(string path, string version)
    : InvalidOperationException(
        $"{path} is at schema {version}, from before each client had a file of its own. "
        + $"Run `dmarc init-db --db {path}` to bring it up to date - it keeps a copy of the database as it was - "
        + "and try again. Nothing was read or changed.")
{
    public string DatabasePath { get; } = path;

    public string Version { get; } = version;
}
