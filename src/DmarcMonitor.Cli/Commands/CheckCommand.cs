using System.Net;
using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Reads what a domain publishes and says what is wrong with it.
///
/// Works with no database: point it at a domain and it reads DNS. With a
/// database it also cross-references what the reports have seen, which is
/// where the two halves earn their keep - a record can look correct and still
/// be wrong about what actually sends.
/// </summary>
public static class CheckCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var single = Args.Value(args, "--domain");
        var all = Args.Flag(args, "--all");

        if (string.IsNullOrWhiteSpace(single) && !all)
        {
            Console.Error.WriteLine("dmarc check --domain <domain>");
            Console.Error.WriteLine("dmarc check --all [--db <path>]    every domain reports have arrived for");
            return 64;
        }

        List<string> domains;
        var observed = new Dictionary<string, ObservedSending>(StringComparer.OrdinalIgnoreCase);

        if (all)
        {
            if (!File.Exists(dbPath))
            {
                Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}. Use --domain to check one domain.");
                return 66;
            }

            (domains, observed) = await FromDatabaseAsync(dbPath, ct).ConfigureAwait(false);
            if (domains.Count == 0)
            {
                Console.Error.WriteLine("No domains in the database yet. Import some reports first.");
                return 66;
            }
        }
        else
        {
            domains = [single!];

            // A database is optional here. Checking a prospect's domain before
            // they are a customer is the commonest use of this.
            if (File.Exists(dbPath))
            {
                var (_, seen) = await FromDatabaseAsync(dbPath, ct).ConfigureAwait(false);
                observed = seen;
            }
        }

        var lookup = new DnsLookup();
        var worst = 0;

        foreach (var domain in domains)
        {
            ct.ThrowIfCancellationRequested();

            var published = await lookup.ReadAsync(domain, ct).ConfigureAwait(false);
            var seen = observed.TryGetValue(domain, out var o) ? o : new ObservedSending();

            // Resolve each include to the addresses it authorises and match
            // them against what has actually sent. Only attempted with a
            // database: with no reports there is nothing to match against, and
            // calling an include unused on no evidence is the worst answer
            // this command could give.
            if (File.Exists(dbPath))
            {
                var (includes, days) = await UsageAsync(lookup, published, dbPath, domain, ct).ConfigureAwait(false);
                seen = seen with { Includes = includes, WindowDays = days };
            }

            var findings = DnsHygiene.Assess(published, seen);

            Console.WriteLine();
            Console.WriteLine($"  {domain}");

            if (findings.Count == 0)
            {
                Console.WriteLine("    nothing to change");
                continue;
            }

            foreach (var f in findings)
            {
                var label = f.Severity switch
                {
                    HygieneSeverity.Breaking => "BREAKING",
                    HygieneSeverity.Weakness => "weakness",
                    _ => "tidy",
                };

                Console.WriteLine($"    [{label}] {f.Record}: {f.Problem}");
                Console.WriteLine($"              fix: {f.Fix}");
                if (f.Reference.Length > 0) { Console.WriteLine($"              per: {f.Reference}"); }
            }

            worst = Math.Max(worst, findings.Max(f => (int)f.Severity));
        }

        Console.WriteLine();

        // Breaking findings exit non-zero so this can gate a pipeline.
        return worst >= (int)HygieneSeverity.Breaking ? 1 : 0;
    }

    /// <summary>
    /// What each include authorises, and how much of it has been used.
    /// </summary>
    /// <remarks>
    /// Matched by address rather than by name, because that is the only link
    /// there is: a report says mail came from 40.107.1.2, never that it came
    /// from Microsoft. Resolving the include to its ranges and testing
    /// membership is what turns "this address sent" into "this include is
    /// carrying mail".
    /// </remarks>
    private static async Task<(List<IncludeUsage> Usage, int Days)> UsageAsync(
        DnsLookup lookup, PublishedRecords published, string dbPath, string domain, CancellationToken ct)
    {
        var usage = new List<IncludeUsage>();
        if (published.SpfRecords.Count == 0) { return (usage, 0); }

        var (sources, days) = await SourcesAsync(dbPath, domain, ct).ConfigureAwait(false);
        _ = days;

        foreach (var term in SpfRecord.Parse(published.SpfRecords[0]).Terms)
        {
            if (term.Name != "include" || term.Value.Length == 0) { continue; }
            ct.ThrowIfCancellationRequested();

            var ranges = await lookup.RangesAsync(term.Value, ct).ConfigureAwait(false);

            long messages = 0;
            DateTimeOffset? last = null;

            foreach (var (address, count, seen) in sources)
            {
                if (!ranges.Any(r => r.Network.Contains(address))) { continue; }

                messages += count;
                if (seen > last) { last = seen; }
            }

            usage.Add(new IncludeUsage
            {
                Target = term.Value,
                Ranges = ranges,
                Messages = messages,
                LastSeen = last,
            });
        }

        return (usage, days);
    }

    /// <summary>
    /// Every address seen sending for this domain, and how many days of
    /// reports that is drawn from.
    /// </summary>
    private static async Task<(List<(IPAddress Address, long Count, DateTimeOffset Seen)> Sources, int Days)>
        SourcesAsync(string dbPath, string domain, CancellationToken ct)
    {
        var sources = new List<(IPAddress, long, DateTimeOffset)>();

        await using var db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadOnly }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = "SELECT r.source_ip, SUM(r.message_count), MAX(r.date_begin) "
                            + "FROM aggregate_records r JOIN domains d ON d.id = r.domain_id "
                            + "WHERE d.name = $domain GROUP BY r.source_ip";
        command.Parameters.AddWithValue("$domain", domain);

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            // A report can carry an address this cannot parse. Skipping it
            // understates an include's use, which is the safe direction: it
            // produces a "check this" rather than a false all-clear.
            if (!IPAddress.TryParse(reader.GetString(0), out var address)) { continue; }

            var seen = DateTime.TryParse(reader.GetString(2), out var when)
                ? new DateTimeOffset(DateTime.SpecifyKind(when, DateTimeKind.Utc))
                : DateTimeOffset.MinValue;

            sources.Add((address, reader.GetInt64(1), seen));
        }

        // The real span, so a claim about silence is backed by however much
        // history there actually is rather than by a constant.
        var days = sources.Count == 0
            ? 0
            : (int)(sources.Max(s => s.Item3) - sources.Min(s => s.Item3)).TotalDays + 1;

        return (sources, days);
    }

    private static async Task<(List<string>, Dictionary<string, ObservedSending>)> FromDatabaseAsync(
        string dbPath, CancellationToken ct)
    {
        var domains = new List<string>();
        var observed = new Dictionary<string, ObservedSending>(StringComparer.OrdinalIgnoreCase);

        await using var db = new SqliteConnection(
            new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadOnly }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);

        await using var command = db.CreateCommand();
        command.CommandText = """
            SELECT d.name,
                   COALESCE((SELECT t.policy_mode FROM tls_reports t
                              WHERE t.domain_id = d.id ORDER BY t.date_end DESC LIMIT 1), ''),
                   EXISTS (SELECT 1 FROM tls_reports t WHERE t.domain_id = d.id),
                   COALESCE((SELECT SUM(r.message_count) FROM aggregate_records r WHERE r.domain_id = d.id), 0)
            FROM domains d
            WHERE d.is_active = 1 AND d.deleted_at IS NULL
            ORDER BY d.name
            """;

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var name = reader.GetString(0);
            domains.Add(name);
            observed[name] = new ObservedSending
            {
                MtaStsMode = reader.GetString(1),
                TlsReportsArriving = reader.GetInt32(2) == 1,
                Messages = reader.GetInt64(3),
            };
        }

        return (domains, observed);
    }
}
