using System.Globalization;
using DmarcMonitor.Core.Dns;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Reporting;

/// <summary>
/// Gathers what is needed to say whether each domain's reports can get back.
///
/// The network and the database live here so <see cref="ReportReachability"/>
/// stays pure. Nothing is concluded from a lookup that did not answer: an
/// authorization record that could not be read is reported as unread rather
/// than as absent, because the two lead somewhere opposite and the absent one
/// is an instruction to publish a record that may already be there.
/// </summary>
public sealed class ReachabilityService(string databasePath, DnsLookup? lookup = null, string? tenantId = null)
{
    private readonly string _databasePath = NotBlank(databasePath);
    private readonly DnsLookup _lookup = lookup ?? new DnsLookup();

    /// <summary>
    /// The organization this runs for, or null for every one.
    /// </summary>
    /// <remarks>
    /// A domain name is unique per organization and not globally, so a
    /// query keyed on the name alone answers with another organization's
    /// data whenever both hold a domain of the same name. Null is right for
    /// a command-line run by the operator; anything serving a signed-in
    /// person passes their organization.
    /// </remarks>
    private readonly string? _tenantId = string.IsNullOrWhiteSpace(tenantId) ? null : tenantId;

    private static string NotBlank(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value;
    }

    /// <summary>Every active domain in the book, with what is known about its route back.</summary>
    public async Task<IReadOnlyList<DomainReachability>> RunAsync(
        string? domain = null, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var held = await HeldAsync(domain, ct).ConfigureAwait(false);
        var results = new List<DomainReachability>(held.Count);

        foreach (var (name, reports, last) in held)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report(name);

            var published = await _lookup.ReadAsync(name, ct).ConfigureAwait(false);

            if (published.LookupFailed || published.DomainDoesNotExist)
            {
                results.Add(new DomainReachability
                {
                    Domain = name,
                    DnsFailed = true,
                    ReportsHeld = reports,
                    LastReport = last,
                });

                continue;
            }

            var record = DmarcRecord.Parse(published.DmarcRecord);
            var destinations = ReportReachability.Destinations(record.Rua, name);

            // One lookup per external destination, and only for those. A rua
            // inside the domain's own organization needs no authorization, so
            // asking would be a query whose answer means nothing.
            var authorizations = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            foreach (var destination in destinations.Where(d => d.External))
            {
                var authorizationName = destination.AuthorizationName(name);
                if (authorizations.ContainsKey(authorizationName)) { continue; }

                authorizations[authorizationName] =
                    await AuthorizationAsync(authorizationName, ct).ConfigureAwait(false);
            }

            results.Add(new DomainReachability
            {
                Domain = name,
                Destinations = destinations,
                Policy = record.IsValid ? record.Policy : "none",
                Authorizations = authorizations,
                ReportsHeld = reports,
                LastReport = last,
            });
        }

        return results;
    }

    /// <summary>
    /// What is published at an authorization name.
    /// </summary>
    /// <returns>
    /// The record, an empty string when the name resolves to nothing, or null
    /// when the lookup could not answer.
    /// </returns>
    /// <remarks>
    /// Three outcomes rather than two, for the reason the rest of this
    /// codebase insists on: "there is no record" is an instruction to publish
    /// one, and "the resolver did not reply" is not.
    /// </remarks>
    private async Task<string?> AuthorizationAsync(string name, CancellationToken ct)
    {
        var records = await _lookup.TxtAsync(name, ct).ConfigureAwait(false);
        if (records is null) { return null; }

        return records.FirstOrDefault(
            r => ZoneAudit.IsDmarcVersion(r, exact: false)) ?? (records.Count > 0 ? records[0] : "");
    }

    /// <summary>Every active domain, with how much has ever arrived for it.</summary>
    private async Task<List<(string Domain, int Reports, DateTimeOffset? Last)>> HeldAsync(
        string? domain, CancellationToken ct)
    {
        var found = new List<(string, int, DateTimeOffset?)>();

        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());

        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.name,
                   (SELECT COUNT(*) FROM aggregate_reports a WHERE a.domain_id = d.id),
                   (SELECT MAX(a.date_end) FROM aggregate_reports a WHERE a.domain_id = d.id)
            FROM domains d
            WHERE d.is_active = 1 AND d.deleted_at IS NULL
              AND ($domain IS NULL OR LOWER(d.name) = $domain)
              AND ($tenant IS NULL OR d.tenant_id = $tenant)
            ORDER BY d.name
            """;
        command.Parameters.AddWithValue("$tenant", (object?)_tenantId ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$domain", string.IsNullOrWhiteSpace(domain)
                ? DBNull.Value
                : domain.Trim().TrimEnd('.').ToLowerInvariant());

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            DateTimeOffset? last = null;
            if (!reader.IsDBNull(2)
                && DateTime.TryParse(reader.GetString(2), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                last = new DateTimeOffset(parsed, TimeSpan.Zero);
            }

            found.Add((reader.GetString(0), reader.GetInt32(1), last));
        }

        return found;
    }
}
