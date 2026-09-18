using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Tls;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Storage;

/// <summary>
/// Stores parsed reports in SQLite, against the schema in db/schema.sql.
///
/// The schema is multi-tenant from the start, so every report needs a tenant,
/// a client and a domain to hang off. A domain nobody has assigned to a client
/// is filed under an "Unassigned" client rather than rejected: reports arrive
/// for domains before anybody gets round to onboarding them, and discarding
/// those loses data that cannot be recovered afterwards. Unassigned is then a
/// visible list of unbilled work rather than a silent gap.
/// </summary>
public sealed class ReportStore
{
    private readonly string _connectionString;

    public const string DefaultTenantSlug = "local";
    public const string UnassignedClientSlug = "unassigned";

    public ReportStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        _databasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            ForeignKeys = true,
        }.ToString();
    }

    private readonly string _databasePath;

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);

        // WAL lets the dashboard read while an ingest run writes. Without it a
        // long run blocks anyone looking at the data.
        await Execute(connection, "PRAGMA journal_mode=WAL;", ct).ConfigureAwait(false);
        await Execute(connection, "PRAGMA foreign_keys=ON;", ct).ConfigureAwait(false);
        return connection;
    }

    /// <summary>
    /// Creates the database from the schema file if it is not already there.
    /// </summary>
    public async Task InitialiseAsync(string schemaSql, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaSql);

        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = schemaSql;
            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
    }

    /// <summary>True when the expected tables are present.</summary>
    /// <remarks>
    /// Checks for the file before opening it, because opening a SQLite path
    /// that is not there CREATES it. Every command asks this question first,
    /// so without this check running any of them in the wrong directory left
    /// an empty dmarc.db behind, told the operator to run init-db, and then
    /// init-db refused because a file it had just created itself "does not
    /// look like a DMARC Monitor database". A dead end reached by following
    /// the instructions.
    /// </remarks>
    public async Task<bool> IsInitialisedAsync(CancellationToken ct = default)
    {
        if (_databasePath is not ":memory:" && !File.Exists(_databasePath)) { return false; }

        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('aggregate_reports','tls_reports','domains')";
        var count = Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture);
        return count == 3;
    }

    /// <summary>
    /// Whether a report has already been stored.
    /// </summary>
    /// <remarks>
    /// Scoped by reporter AND domain, because report ids are unique per
    /// reporter rather than globally. An unscoped check would discard a second
    /// receiver's entire view of a domain the first time the ids collided.
    /// </remarks>
    public async Task<bool> IsAggregateStoredAsync(string orgName, string externalReportId, string domain, CancellationToken ct = default)
    {
        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM aggregate_reports r
            JOIN domains d ON d.id = r.domain_id
            WHERE r.org_name = $org AND r.external_report_id = $rid AND d.name = $domain
            """;
        command.Parameters.AddWithValue("$org", orgName);
        command.Parameters.AddWithValue("$rid", externalReportId);
        command.Parameters.AddWithValue("$domain", domain);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture) > 0;
    }

    public async Task<bool> IsTlsStoredAsync(string orgName, string externalReportId, string domain, CancellationToken ct = default)
    {
        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM tls_reports r
            JOIN domains d ON d.id = r.domain_id
            WHERE r.org_name = $org AND r.external_report_id = $rid AND d.name = $domain
            """;
        command.Parameters.AddWithValue("$org", orgName);
        command.Parameters.AddWithValue("$rid", externalReportId);
        command.Parameters.AddWithValue("$domain", domain);
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L, CultureInfo.InvariantCulture) > 0;
    }

    /// <summary>
    /// Saves an aggregate report and its records.
    /// </summary>
    /// <returns>The stored report id, or null when it was already present.</returns>
    public async Task<string?> SaveAggregateAsync(
        AggregateReport report, string rawContent, string? sourceMessageId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);

        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
        var tx = (SqliteTransaction)transaction;

        var ids = await EnsureDomainAsync(connection, tx, report.Policy.Domain, ct).ConfigureAwait(false);
        var reportId = Guid.NewGuid().ToString("N");
        var now = Iso(DateTimeOffset.UtcNow);

        try
        {
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = tx;
                command.CommandText = """
                    INSERT INTO aggregate_reports
                      (id, tenant_id, client_id, domain_id, org_name, org_email, external_report_id,
                       date_begin, date_end, policy_p, policy_sp, policy_pct, policy_adkim, policy_aspf,
                       source_message_id, raw_hash, received_at, ingested_at)
                    VALUES
                      ($id, $tenant, $client, $domain, $org, $orgEmail, $rid,
                       $begin, $end, $p, $sp, $pct, $adkim, $aspf,
                       $msg, $hash, $received, $ingested)
                    """;
                command.Parameters.AddWithValue("$id", reportId);
                command.Parameters.AddWithValue("$tenant", ids.TenantId);
                command.Parameters.AddWithValue("$client", ids.ClientId);
                command.Parameters.AddWithValue("$domain", ids.DomainId);
                command.Parameters.AddWithValue("$org", report.Metadata.OrgName);
                command.Parameters.AddWithValue("$orgEmail", Nullable(report.Metadata.Email));
                command.Parameters.AddWithValue("$rid", report.Metadata.ReportId);
                command.Parameters.AddWithValue("$begin", Iso(report.Metadata.Begin));
                command.Parameters.AddWithValue("$end", Iso(report.Metadata.End));
                command.Parameters.AddWithValue("$p", report.Policy.P.ToString().ToLowerInvariant());
                command.Parameters.AddWithValue("$sp", report.Policy.Sp is { } sp ? sp.ToString().ToLowerInvariant() : DBNull.Value);
                command.Parameters.AddWithValue("$pct", report.Policy.Pct);
                command.Parameters.AddWithValue("$adkim", report.Policy.Adkim == AlignmentMode.Strict ? "s" : "r");
                command.Parameters.AddWithValue("$aspf", report.Policy.Aspf == AlignmentMode.Strict ? "s" : "r");
                command.Parameters.AddWithValue("$msg", Nullable(sourceMessageId));
                command.Parameters.AddWithValue("$hash", Sha256(rawContent));
                command.Parameters.AddWithValue("$received", Iso(report.Metadata.End));
                command.Parameters.AddWithValue("$ingested", now);

                await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            // UNIQUE(org_name, external_report_id, domain_id). The database is
            // the last line of defence against double-counting, behind the
            // ingestor's own check: a crash between the two must not inflate a
            // customer's volume when the message is read again.
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
            return null;
        }

        foreach (var record in report.Records)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = tx;
            command.CommandText = """
                INSERT INTO aggregate_records
                  (report_id, tenant_id, client_id, domain_id, date_begin,
                   source_ip, source_ip_version, message_count,
                   disposition, dkim_result, spf_result, dmarc_result, fail_reason,
                   override_reason, override_comment,
                   header_from, envelope_from, envelope_to, is_subdomain,
                   dkim_domain, dkim_selector, dkim_auth_result, spf_domain, spf_auth_result)
                VALUES
                  ($report, $tenant, $client, $domain, $begin,
                   $ip, $ipv, $count,
                   $disp, $dkim, $spf, $dmarc, $fail,
                   $orType, $orComment,
                   $hfrom, $efrom, $eto, $isSub,
                   $dkimDomain, $dkimSelector, $dkimAuth, $spfDomain, $spfAuth)
                """;
            command.Parameters.AddWithValue("$report", reportId);
            command.Parameters.AddWithValue("$tenant", ids.TenantId);
            command.Parameters.AddWithValue("$client", ids.ClientId);
            command.Parameters.AddWithValue("$domain", ids.DomainId);
            command.Parameters.AddWithValue("$begin", Iso(report.Metadata.Begin));
            command.Parameters.AddWithValue("$ip", record.SourceIp);
            command.Parameters.AddWithValue("$ipv", record.SourceIp.Contains(':', StringComparison.Ordinal) ? 6 : 4);
            command.Parameters.AddWithValue("$count", record.Count);
            command.Parameters.AddWithValue("$disp", record.Disposition.ToString().ToLowerInvariant());
            command.Parameters.AddWithValue("$dkim", record.Dkim.ToString().ToLowerInvariant());
            command.Parameters.AddWithValue("$spf", record.Spf.ToString().ToLowerInvariant());
            command.Parameters.AddWithValue("$dmarc", record.IsDmarcPass ? "pass" : "fail");
            command.Parameters.AddWithValue("$fail", FailReason(record));
            command.Parameters.AddWithValue("$orType", record.Overrides.Count > 0
                ? string.Join(';', record.Overrides.Select(o => o.Type.ToString().ToLowerInvariant()))
                : (object)DBNull.Value);
            command.Parameters.AddWithValue("$orComment", record.Overrides.Count > 0
                ? Nullable(record.Overrides[0].Comment)
                : DBNull.Value);
            command.Parameters.AddWithValue("$hfrom", Nullable(record.HeaderFrom));
            command.Parameters.AddWithValue("$efrom", Nullable(record.EnvelopeFrom));
            command.Parameters.AddWithValue("$eto", Nullable(record.EnvelopeTo));
            command.Parameters.AddWithValue("$isSub", IsSubdomain(record.HeaderFrom, report.Policy.Domain) ? 1 : 0);

            // Prefer an auth result that PASSED, falling back to the first.
            // A record can carry several, and taking index zero would report a
            // failed check while a successful one sat beside it.
            var dkim = PreferPassing(record.DkimResults);
            var spf = PreferPassing(record.SpfResults);

            // The RESULT travels with the domain. A source forging a signature
            // as its victim produces domain=victim.com with result=fail, so
            // storing only the domain makes a forgery indistinguishable from
            // the victim's own misconfigured service, which inverts the advice
            // an operator is given.
            command.Parameters.AddWithValue("$dkimDomain", dkim is null ? DBNull.Value : dkim.Domain);
            command.Parameters.AddWithValue("$dkimSelector", dkim is null ? DBNull.Value : Nullable(dkim.Selector));
            command.Parameters.AddWithValue("$dkimAuth", dkim is null ? DBNull.Value : Nullable(dkim.Result));
            command.Parameters.AddWithValue("$spfDomain", spf is null ? DBNull.Value : spf.Domain);
            command.Parameters.AddWithValue("$spfAuth", spf is null ? DBNull.Value : Nullable(spf.Result));

            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return reportId;
    }

    /// <summary>Saves a TLS report. Returns the id, or null when already present.</summary>
    public async Task<string?> SaveTlsAsync(
        TlsReport report, string rawContent, string? sourceMessageId = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Policies.Count == 0) { return null; }

        var domain = report.Policies[0].Policy.Domain;
        if (string.IsNullOrWhiteSpace(domain)) { return null; }

        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(ct).ConfigureAwait(false);
        var tx = (SqliteTransaction)transaction;

        var ids = await EnsureDomainAsync(connection, tx, domain, ct).ConfigureAwait(false);
        var reportId = Guid.NewGuid().ToString("N");

        try
        {
            await using var command = connection.CreateCommand();
            command.Transaction = tx;
            command.CommandText = """
                INSERT INTO tls_reports
                  (id, tenant_id, client_id, domain_id, org_name, external_report_id,
                   date_begin, date_end, policy_type, policy_domain, policy_mode,
                   total_success, total_failure,
                   source_message_id, raw_hash, received_at, ingested_at)
                VALUES
                  ($id, $tenant, $client, $domain, $org, $rid,
                   $begin, $end, $ptype, $pdomain, $pmode,
                   $ok, $fail,
                   $msg, $hash, $received, $ingested)
                """;
            command.Parameters.AddWithValue("$id", reportId);
            command.Parameters.AddWithValue("$tenant", ids.TenantId);
            command.Parameters.AddWithValue("$client", ids.ClientId);
            command.Parameters.AddWithValue("$domain", ids.DomainId);
            command.Parameters.AddWithValue("$org", report.OrganizationName);
            command.Parameters.AddWithValue("$rid", report.ReportId);
            command.Parameters.AddWithValue("$begin", Iso(report.Begin));
            command.Parameters.AddWithValue("$end", Iso(report.End));
            command.Parameters.AddWithValue("$ptype", report.Policies[0].Policy.Type.ToString().ToLowerInvariant());
            command.Parameters.AddWithValue("$pdomain", domain);
            command.Parameters.AddWithValue("$pmode", report.Policies[0].Policy.Mode.ToString().ToLowerInvariant());
            command.Parameters.AddWithValue("$ok", report.SuccessfulSessions);
            command.Parameters.AddWithValue("$fail", report.FailedSessions);
            command.Parameters.AddWithValue("$msg", Nullable(sourceMessageId));
            command.Parameters.AddWithValue("$hash", Sha256(rawContent));
            command.Parameters.AddWithValue("$received", Iso(report.End));
            command.Parameters.AddWithValue("$ingested", Iso(DateTimeOffset.UtcNow));

            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
            return null;
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return reportId;
    }

    /// <summary>Domains with no client assigned: reports arriving that nobody is billed for.</summary>
    public async Task<IReadOnlyList<string>> GetUnassignedDomainsAsync(CancellationToken ct = default)
    {
        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT d.name FROM domains d
            JOIN clients c ON c.id = d.client_id
            WHERE c.slug = $slug
            ORDER BY d.name
            """;
        command.Parameters.AddWithValue("$slug", UnassignedClientSlug);

        var result = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result.Add(reader.GetString(0));
        }
        return result;
    }

    /// <summary>A client and how much is filed under it.</summary>
    public sealed record ClientSummary(string Slug, string Name, int Domains, long Messages);

    /// <summary>Why an assignment did not happen, or that it did.</summary>
    public enum AssignOutcome
    {
        Assigned,
        DomainNotFound,
        ClientNotFound,
        AlreadyAssigned,
    }

    /// <summary>
    /// Every table that carries a denormalised client_id alongside a domain_id.
    ///
    /// Moving a domain to a client has to move its history too. Updating only
    /// the domains row would leave every report still filed under Unassigned,
    /// so the client's own report would come back empty and look like a domain
    /// that has never sent mail.
    ///
    /// Spelled out rather than discovered at run time so the SQL stays
    /// greppable; ReportStoreAssignmentTests recomputes the set from the live
    /// schema and fails if a new table appears that is not handled here.
    /// </summary>
    public static readonly IReadOnlyList<string> DomainScopedTables =
    [
        "aggregate_reports",
        "aggregate_records",
        "forensic_reports",
        "tls_reports",
        "dns_snapshots",
        "dns_drift_events",
        "dkim_selectors",
        "compliance_scores",
        "enforcement_assessments",
        "cousin_domains",
        "alerts",
        "dns_provider_configs",
        "dns_change_plans",
        "dns_changes",
        "spf_flatten_state",
        "mta_sts_policies",
    ];

    /// <summary>Every client, with the Unassigned one included: unbilled work is worth seeing.</summary>
    public async Task<IReadOnlyList<ClientSummary>> GetClientsAsync(CancellationToken ct = default)
    {
        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var command = connection.CreateCommand();

        // Left joins throughout: a client onboarded before its first report
        // still needs to appear, or it looks like the assignment failed.
        command.CommandText = """
            SELECT c.slug, c.name,
                   COUNT(DISTINCT d.id)                  AS domains,
                   COALESCE(SUM(r.message_count), 0)     AS messages
            FROM clients c
            LEFT JOIN domains d ON d.client_id = c.id
            LEFT JOIN aggregate_records r ON r.domain_id = d.id
            GROUP BY c.id, c.slug, c.name
            ORDER BY c.name
            """;

        var result = new List<ClientSummary>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result.Add(new ClientSummary(reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetInt64(3)));
        }
        return result;
    }

    /// <summary>
    /// Creates a client. Returns its slug, or null when that slug is taken.
    /// </summary>
    public async Task<string?> CreateClientAsync(string name, string? slug = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var wanted = Slugify(string.IsNullOrWhiteSpace(slug) ? name : slug);
        if (wanted.Length == 0)
        {
            return null;
        }

        var now = Iso(DateTimeOffset.UtcNow);

        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(ct).ConfigureAwait(false);

        var tenantId = await EnsureRowAsync(connection, transaction,
            "SELECT id FROM tenants WHERE slug = $slug",
            """
            INSERT INTO tenants (id, name, slug, deployment_mode, status, secret_backend, created_at, updated_at)
            VALUES ($id, 'Local', $slug, 'self_hosted', 'active', 'dpapi', $now, $now)
            """,
            DefaultTenantSlug, now, ct).ConfigureAwait(false);

        await using (var exists = connection.CreateCommand())
        {
            exists.Transaction = transaction;
            exists.CommandText = "SELECT 1 FROM clients WHERE slug = $slug LIMIT 1";
            exists.Parameters.AddWithValue("$slug", wanted);
            if (await exists.ExecuteScalarAsync(ct).ConfigureAwait(false) is not null)
            {
                await transaction.RollbackAsync(ct).ConfigureAwait(false);
                return null;
            }
        }

        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO clients (id, tenant_id, name, slug, status, collection_method, created_at, updated_at)
                VALUES ($id, $tenant, $name, $slug, 'active', 'central_mailbox', $now, $now)
                """;
            insert.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
            insert.Parameters.AddWithValue("$tenant", tenantId);
            insert.Parameters.AddWithValue("$name", name.Trim());
            insert.Parameters.AddWithValue("$slug", wanted);
            insert.Parameters.AddWithValue("$now", now);
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return wanted;
    }

    /// <summary>
    /// Files a domain, and everything already stored for it, under a client.
    /// </summary>
    public async Task<AssignOutcome> AssignDomainAsync(string domain, string clientSlug, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSlug);

        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var slug = clientSlug.Trim().ToLowerInvariant();

        await using var connection = await OpenAsync(ct).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(ct).ConfigureAwait(false);

        string domainId, currentClientId;
        await using (var lookup = connection.CreateCommand())
        {
            lookup.Transaction = transaction;
            lookup.CommandText = "SELECT id, client_id FROM domains WHERE name = $name LIMIT 1";
            lookup.Parameters.AddWithValue("$name", name);
            await using var reader = await lookup.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                await transaction.RollbackAsync(ct).ConfigureAwait(false);
                return AssignOutcome.DomainNotFound;
            }
            domainId = reader.GetString(0);
            currentClientId = reader.GetString(1);
        }

        string clientId;
        await using (var lookup = connection.CreateCommand())
        {
            lookup.Transaction = transaction;
            lookup.CommandText = "SELECT id FROM clients WHERE slug = $slug LIMIT 1";
            lookup.Parameters.AddWithValue("$slug", slug);
            if (await lookup.ExecuteScalarAsync(ct).ConfigureAwait(false) is not string found)
            {
                await transaction.RollbackAsync(ct).ConfigureAwait(false);
                return AssignOutcome.ClientNotFound;
            }
            clientId = found;
        }

        if (clientId == currentClientId)
        {
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
            return AssignOutcome.AlreadyAssigned;
        }

        var now = Iso(DateTimeOffset.UtcNow);

        await using (var move = connection.CreateCommand())
        {
            move.Transaction = transaction;
            move.CommandText = "UPDATE domains SET client_id = $client, updated_at = $now WHERE id = $domain";
            move.Parameters.AddWithValue("$client", clientId);
            move.Parameters.AddWithValue("$now", now);
            move.Parameters.AddWithValue("$domain", domainId);
            await move.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        foreach (var table in DomainScopedTables)
        {
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;

            // The table name is from this constant list, never from a caller,
            // so there is nothing here to inject; the values stay parameters.
            update.CommandText = $"UPDATE {table} SET client_id = $client WHERE domain_id = $domain";
            update.Parameters.AddWithValue("$client", clientId);
            update.Parameters.AddWithValue("$domain", domainId);
            await update.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await transaction.CommitAsync(ct).ConfigureAwait(false);
        return AssignOutcome.Assigned;
    }

    /// <summary>"Morton, ND" becomes "morton-nd": usable in a filename and a URL.</summary>
    public static string Slugify(string raw)
    {
        ArgumentNullException.ThrowIfNull(raw);

        var builder = new StringBuilder(raw.Length);
        foreach (var c in raw.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(c)) { builder.Append(c); }
            else if (builder.Length > 0 && builder[^1] != '-') { builder.Append('-'); }
        }

        return builder.ToString().Trim('-');
    }

    private sealed record DomainIds(string TenantId, string ClientId, string DomainId);

    /// <summary>
    /// Resolves a domain to its ids, creating the tenant, the Unassigned
    /// client and the domain row as needed.
    /// </summary>
    private static async Task<DomainIds> EnsureDomainAsync(
        SqliteConnection connection, SqliteTransaction tx, string domain, CancellationToken ct)
    {
        var name = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var now = Iso(DateTimeOffset.UtcNow);

        // An existing domain keeps whatever client it was assigned to, so
        // onboarding is never undone by a later report arriving.
        await using (var lookup = connection.CreateCommand())
        {
            lookup.Transaction = tx;
            lookup.CommandText = "SELECT id, tenant_id, client_id FROM domains WHERE name = $name LIMIT 1";
            lookup.Parameters.AddWithValue("$name", name);
            await using var reader = await lookup.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                return new DomainIds(reader.GetString(1), reader.GetString(2), reader.GetString(0));
            }
        }

        var tenantId = await EnsureRowAsync(connection, tx,
            "SELECT id FROM tenants WHERE slug = $slug",
            """
            INSERT INTO tenants (id, name, slug, deployment_mode, status, secret_backend, created_at, updated_at)
            VALUES ($id, 'Local', $slug, 'self_hosted', 'active', 'dpapi', $now, $now)
            """,
            DefaultTenantSlug, now, ct).ConfigureAwait(false);

        var clientId = await EnsureRowAsync(connection, tx,
            "SELECT id FROM clients WHERE slug = $slug",
            $"""
            INSERT INTO clients (id, tenant_id, name, slug, status, collection_method, created_at, updated_at)
            VALUES ($id, '{tenantId}', 'Unassigned', $slug, 'onboarding', 'central_mailbox', $now, $now)
            """,
            UnassignedClientSlug, now, ct).ConfigureAwait(false);

        var domainId = Guid.NewGuid().ToString("N");
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = """
                INSERT INTO domains (id, tenant_id, client_id, name, is_active, created_at, updated_at)
                VALUES ($id, $tenant, $client, $name, 1, $now, $now)
                """;
            insert.Parameters.AddWithValue("$id", domainId);
            insert.Parameters.AddWithValue("$tenant", tenantId);
            insert.Parameters.AddWithValue("$client", clientId);
            insert.Parameters.AddWithValue("$name", name);
            insert.Parameters.AddWithValue("$now", now);
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        return new DomainIds(tenantId, clientId, domainId);
    }

    private static async Task<string> EnsureRowAsync(
        SqliteConnection connection, SqliteTransaction tx,
        string selectSql, string insertSql, string slug, string now, CancellationToken ct)
    {
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = tx;
            select.CommandText = selectSql;
            select.Parameters.AddWithValue("$slug", slug);
            if (await select.ExecuteScalarAsync(ct).ConfigureAwait(false) is string existing)
            {
                return existing;
            }
        }

        var id = Guid.NewGuid().ToString("N");
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = insertSql;
            insert.Parameters.AddWithValue("$id", id);
            insert.Parameters.AddWithValue("$slug", slug);
            insert.Parameters.AddWithValue("$now", now);
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        return id;
    }

    private static async Task Execute(SqliteConnection connection, string sql, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The auth result worth storing: one that passed if there is one,
    /// otherwise the first. A record can carry several, and taking index zero
    /// would record a failed check while a successful one sat beside it.
    /// </summary>
    private static AuthResult? PreferPassing(IReadOnlyList<AuthResult> results)
    {
        if (results.Count == 0) { return null; }

        for (var i = 0; i < results.Count; i++)
        {
            if (results[i].IsPass) { return results[i]; }
        }
        return results[0];
    }

    /// <summary>Which half of DMARC failed, matching the prototype's vocabulary.</summary>
    private static string FailReason(ReportRecord record)
    {
        if (record.Dkim == DmarcResult.Pass && record.Spf == DmarcResult.Pass) { return "aligned"; }
        if (record.Dkim == DmarcResult.Pass) { return "dkim-only"; }
        if (record.Spf == DmarcResult.Pass) { return "spf-only"; }
        return record.WasOverridden ? "override" : "both-fail";
    }

    private static bool IsSubdomain(string headerFrom, string policyDomain) =>
        !string.IsNullOrEmpty(headerFrom) &&
        !string.Equals(headerFrom, policyDomain, StringComparison.OrdinalIgnoreCase) &&
        headerFrom.EndsWith('.' + policyDomain, StringComparison.OrdinalIgnoreCase);

    private static string Iso(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static object Nullable(string? value) =>
        string.IsNullOrWhiteSpace(value) ? DBNull.Value : value;

    private static string Sha256(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content ?? ""));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
