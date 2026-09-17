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
