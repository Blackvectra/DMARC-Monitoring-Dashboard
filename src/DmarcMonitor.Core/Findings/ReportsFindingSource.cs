using System.Globalization;
using System.Text.Json;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Findings;

/// <summary>
/// Whether the reports keep arriving. A domain that had them and stopped is
/// a finding; a domain nobody has ever collected for is onboarding; and
/// silence is evidence only while the collector is known to be listening.
/// </summary>
/// <remarks>
/// <para>
/// The collector records each run against the organization (dmarc ingest
/// and an import both do), and that record is what this reads first. No run
/// recorded, a failed last run, or none succeeded within the collection
/// window, and nothing is observed: what is open becomes unknown, nothing is
/// raised and nothing is resolved. The same when the organization as a whole
/// has had nothing stored in the window: a mailbox that delivers nothing
/// makes every domain quiet at once, and that is the collection, not the
/// domains - dmarc health is what says so.
/// </para>
/// <para>
/// A domain is quiet when its newest report ended more than
/// <see cref="QuietAfterDays"/> ago. It is worth raising only when it
/// reported regularly before that, in <see cref="RegularWeeksOfFive"/> of
/// the five weeks up to its last report, so a parked domain a receiver
/// mentions once a month never fires. Reports covering the domain again
/// resolve it after the type's three successful observations.
/// </para>
/// </remarks>
public sealed class ReportsFindingSource(string databasePath, TimeProvider? clock = null)
{
    /// <summary>How often the collector is expected to run: dmarc-ingest.timer is hourly.</summary>
    public const int ExpectedEveryHours = 1;

    /// <summary>How long without a report before a domain is quiet; the health check's figure.</summary>
    public const int QuietAfterDays = HealthCheck.QuietAfterDays;

    /// <summary>How recently collection must have succeeded for silence to mean anything.</summary>
    public const int CollectionWindowHours = HealthCheck.StoppedAfterHours;

    /// <summary>In how many of the five weeks before its last report a domain must have reported to count as regular.</summary>
    public const int RegularWeeksOfFive = 4;

    private const string KeyPrefix = "reports:";

    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly FindingLifecycle _lifecycle = new(databasePath, clock);
    private readonly FindingSourceRegistry _registry = new(databasePath, clock);
    private readonly ClientDatabases _files = new(databasePath);
    private readonly DnsSnapshotStore _dns = new(databasePath);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string DedupKey(string domainId) => KeyPrefix + domainId;

    /// <summary>What one organization's observation came to.</summary>
    /// <param name="Quiet">Domains raised, or seen again, as quiet.</param>
    /// <param name="Reporting">Domains with an open finding that a report has covered again.</param>
    /// <param name="Unknown">Findings marked unknown because nothing could be observed.</param>
    /// <param name="NotObserved">Why nothing was observed, or null when it was.</param>
    public sealed record Observed(string TenantId, string Organization, int Quiet, int Reporting, int Unknown, string? NotObserved);

    private sealed record ActiveDomain(string Id, string Name, string ClientId);

    /// <summary>What a client's file says about one domain's reports.</summary>
    private sealed record History(string NewestId, DateTimeOffset LastEnd, int Weeks);

    private sealed record Payload(DateTimeOffset LastReportEndedAt, int WeeksReportedOfFive, bool? DmarcAsksForReports);

    /// <summary>Every organization, in turn.</summary>
    public async Task<IReadOnlyList<Observed>> ObserveAllAsync(DateTimeOffset? now = null, CancellationToken ct = default)
    {
        var when = now ?? _clock.GetUtcNow();
        var tenants = new List<(string Id, string Slug)>();
        await using (var db = await _files.OpenRegistryAsync(ct: ct).ConfigureAwait(false))
        await using (var command = db.CreateCommand())
        {
            command.CommandText = "SELECT id, slug FROM tenants WHERE deleted_at IS NULL ORDER BY slug";
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { tenants.Add((reader.GetString(0), reader.GetString(1))); }
        }

        var observed = new List<Observed>(tenants.Count);
        foreach (var (id, _) in tenants)
        {
            observed.Add(await ObserveOrganizationAsync(id, when, ct).ConfigureAwait(false));
        }
        return observed;
    }

    /// <summary>One organization's domains against its reports, if its collection can be trusted.</summary>
    public async Task<Observed> ObserveOrganizationAsync(string tenantId, DateTimeOffset? now = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        var when = now ?? _clock.GetUtcNow();
        var slug = await SlugAsync(tenantId, ct).ConfigureAwait(false);

        if (await WhyNotObservableAsync(tenantId, when, ct).ConfigureAwait(false) is { } why)
        {
            var unknown = await MarkUnknownAsync(tenantId, why, when, ct).ConfigureAwait(false);
            return new Observed(tenantId, slug, 0, 0, unknown, why);
        }

        var domains = await ActiveDomainsAsync(tenantId, ct).ConfigureAwait(false);
        var history = new Dictionary<string, History>(StringComparer.Ordinal);
        DateTimeOffset? lastStored = null;
        foreach (var client in await _files.ListAsync(tenantId, ct).ConfigureAwait(false))
        {
            var stored = await ReadAsync(client, history, ct).ConfigureAwait(false);
            if (stored is { } at && (lastStored is null || at > lastStored)) { lastStored = at; }
        }

        // Every domain quiet at once is the mailbox, not the domains.
        if (history.Count > 0 && (lastStored is null || when - lastStored.Value > TimeSpan.FromHours(CollectionWindowHours)))
        {
            var reason = "nothing has been stored for any of the organization's domains in the last "
                + CollectionWindowHours.ToString(CultureInfo.InvariantCulture)
                + " hours, which is the collection rather than a domain; dmarc health says so";
            var unknown = await MarkUnknownAsync(tenantId, reason, when, ct).ConfigureAwait(false);
            return new Observed(tenantId, slug, 0, 0, unknown, reason);
        }

        var open = await _lifecycle.Store.ListAsync(new FindingFilter
        {
            TenantId = tenantId,
            Types = [FindingTypes.ReportingStopped],
            SourceStates = [SourceStates.Active, SourceStates.Unknown],
            Limit = 10000,
        }, ct).ConfigureAwait(false);
        var openDomains = open.Where(f => f.DomainId is not null).Select(f => f.DomainId!).ToHashSet(StringComparer.Ordinal);
        var readings = await _dns.LatestAsync(tenantId, ct: ct).ConfigureAwait(false);

        int quiet = 0, reporting = 0;
        foreach (var domain in domains)
        {
            // Never reported on: onboarding, and dmarc reachability's question.
            if (!history.TryGetValue(domain.Id, out var seen)) { continue; }

            var silent = when - seen.LastEnd;
            if (silent > TimeSpan.FromDays(QuietAfterDays) && seen.Weeks >= RegularWeeksOfFive)
            {
                var dns = readings.GetValueOrDefault(domain.Name);
                bool? asks = dns is { Status: DnsCheckStatus.Ok } ? dns.DmarcRecord is not null && dns.DmarcRua.Length > 0 : null;
                // No day count in the title: it would change every night and read as a
                // new condition each time. How long is first_observed_at's to say.
                await _lifecycle.ObserveAsync(new Observation
                {
                    TenantId = tenantId,
                    ClientId = domain.ClientId,
                    DomainId = domain.Id,
                    SourceId = FindingSourceIds.Reports,
                    Type = FindingTypes.ReportingStopped,
                    Rule = asks == false ? "rua_gone" : "quiet",
                    Severity = asks == false ? "critical" : "warning",
                    Title = domain.Name + ": no report has covered it since "
                        + seen.LastEnd.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ", after reports in "
                        + seen.Weeks.ToString(CultureInfo.InvariantCulture) + " of the 5 weeks before"
                        + (asks == false ? ", and its DMARC record no longer asks for any." : "."),
                    DedupKey = DedupKey(domain.Id),
                    EvidenceRef = "report:" + seen.NewestId,
                    PayloadJson = JsonSerializer.Serialize(new Payload(seen.LastEnd, seen.Weeks, asks), Json),
                    At = when,
                }, ct).ConfigureAwait(false);
                quiet++;
            }
            else if (openDomains.Contains(domain.Id))
            {
                // A report has covered it again, or it was never regular: one
                // successful observation without the condition.
                await _lifecycle.ReconcileAsync(tenantId, domain.ClientId, FindingSourceIds.Reports, domain.Id,
                    new HashSet<string>(StringComparer.Ordinal), when, ct).ConfigureAwait(false);
                reporting++;
            }
        }

        return new Observed(tenantId, slug, quiet, reporting, 0, null);
    }

    /// <summary>Why silence would say nothing tonight, or null when the collector has been listening.</summary>
    private async Task<string?> WhyNotObservableAsync(string tenantId, DateTimeOffset now, CancellationToken ct)
    {
        var collector = (await _registry.ListAsync(tenantId, ct: ct).ConfigureAwait(false))
            .FirstOrDefault(s => string.Equals(s.Kind, FindingSourceIds.Reports, StringComparison.Ordinal) && s.ClientId is null);

        if (collector is null)
        {
            return "no collection has been recorded for the organization, so nothing is known about what has not arrived";
        }
        if (collector.LastError is not null)
        {
            return "the last collection failed: " + collector.LastError;
        }
        if (collector.LastSuccessAt is not { } ok || now - ok > TimeSpan.FromHours(CollectionWindowHours))
        {
            return "no collection has succeeded in the last " + CollectionWindowHours.ToString(CultureInfo.InvariantCulture) + " hours"
                + (collector.LastSuccessAt is { } last
                    ? "; the last did on " + last.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC"
                    : "; none ever has");
        }
        return null;
    }

    private async Task<int> MarkUnknownAsync(string tenantId, string reason, DateTimeOffset now, CancellationToken ct)
    {
        var open = await _lifecycle.Store.ListAsync(new FindingFilter
        {
            TenantId = tenantId,
            Types = [FindingTypes.ReportingStopped],
            SourceStates = [SourceStates.Active],
            Limit = 10000,
        }, ct).ConfigureAwait(false);

        var marked = 0;
        foreach (var clientId in open.Select(f => f.ClientId).Distinct(StringComparer.Ordinal))
        {
            marked += await _lifecycle.MarkUnknownAsync(tenantId, clientId, FindingSourceIds.Reports, null, reason, now, ct).ConfigureAwait(false);
        }
        return marked;
    }

    // ---- reading ---------------------------------------------------------------------------

    /// <summary>
    /// Each domain's newest report and how many of the five weeks up to it
    /// had one, from the client's file; returns when a report was last
    /// stored for the client.
    /// </summary>
    private async Task<DateTimeOffset?> ReadAsync(ClientFile client, Dictionary<string, History> history, CancellationToken ct)
    {
        await using var db = await _files.OpenAsync(ClientScope.Client(client.Id), ["aggregate_reports"], ct: ct).ConfigureAwait(false);

        await using (var command = db.CreateCommand())
        {
            // Weeks counted back from the newest report, not from tonight: the
            // question is whether the domain was regular while it reported.
            command.CommandText = """
                SELECT n.domain_id,
                       (SELECT r.id FROM aggregate_reports r
                         WHERE r.domain_id = n.domain_id ORDER BY r.date_end DESC, r.id LIMIT 1),
                       n.last_end,
                       (SELECT COUNT(DISTINCT CAST((julianday(n.last_end) - julianday(r.date_end)) / 7 AS INTEGER))
                          FROM aggregate_reports r
                         WHERE r.domain_id = n.domain_id AND julianday(r.date_end) > julianday(n.last_end) - 35)
                FROM (SELECT domain_id, MAX(date_end) AS last_end FROM aggregate_reports GROUP BY domain_id) n
                """;
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                if (Parse(reader.GetString(2)) is not { } lastEnd) { continue; }
                history[reader.GetString(0)] = new History(reader.GetString(1), lastEnd, reader.GetInt32(3));
            }
        }

        await using (var command = db.CreateCommand())
        {
            command.CommandText = "SELECT MAX(ingested_at) FROM aggregate_reports";
            var newest = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
            return newest is string text ? Parse(text) : null;
        }
    }

    private async Task<IReadOnlyList<ActiveDomain>> ActiveDomainsAsync(string tenantId, CancellationToken ct)
    {
        await using var db = await _files.OpenRegistryAsync(ct: ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT id, name, client_id FROM domains
            WHERE tenant_id = $tenant AND is_active = 1 AND deleted_at IS NULL
            ORDER BY name
            """;
        command.Parameters.AddWithValue("$tenant", tenantId);

        var domains = new List<ActiveDomain>();
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            domains.Add(new ActiveDomain(reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }
        return domains;
    }

    private async Task<string> SlugAsync(string tenantId, CancellationToken ct)
    {
        await using var db = await _files.OpenRegistryAsync(ct: ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT slug FROM tenants WHERE id = $id";
        command.Parameters.AddWithValue("$id", tenantId);
        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string
            ?? throw new ArgumentException($"No organization with id {tenantId}.", nameof(tenantId));
    }

    private static DateTimeOffset? Parse(string text) =>
        DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var at) ? at : null;
}
