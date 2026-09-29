using System.Globalization;
using DmarcMonitor.Core.Findings;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// The findings engines that work from what is stored, with no network: what
/// the reports say about each domain, whether an applied change has shown
/// up in the receivers' reports, and which exceptions have run out.
/// </summary>
/// <remarks>
/// Run nightly after the DNS scan (dmarc-dns.service's third step), before
/// dmarc-notify sends what was raised. Exits 0 when it ran; what it found is
/// in the findings, and dmarc health is what judges them.
/// </remarks>
public static class FindingsCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var sub = args.Length > 0 ? args[0].ToLowerInvariant() : "";
        var rest = args.Skip(1).ToArray();

        return sub switch
        {
            "observe" => await ObserveAsync(rest, ct).ConfigureAwait(false),
            "list" => await ListAsync(rest, ct).ConfigureAwait(false),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine("dmarc findings list [--db <path>] [--org <slug>] [--client <slug>] [--severity info|warning|critical] [--all]");
        Console.Error.WriteLine("                                        what is open and wants a person; exits 1 while a critical finding is. --all lists everything");
        Console.Error.WriteLine("dmarc findings observe [--db <path>]    what the stored reports say, applied changes shown in force, exceptions run out");
        return 64;
    }

    /// <summary>
    /// What is open, worst first, for a person or a script: exits 1 while a
    /// critical finding wants somebody, which is what a pipeline hangs off.
    /// </summary>
    private static async Task<int> ListAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db", "--org", "--client", "--severity", "!--all") is var bad and not 0) { return bad; }
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var all = Args.Flag(args, "--all");

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}.");
            return 66;
        }
        if (!await SchemaGuard.IsCurrentAsync(dbPath, ct).ConfigureAwait(false)) { return 69; }

        string? tenantId = null;
        if (Args.Value(args, "--org") is { } org)
        {
            tenantId = await TenantIdAsync(dbPath, org, ct).ConfigureAwait(false);
            if (tenantId is null)
            {
                Console.Error.WriteLine($"There is no organization '{org}'.");
                return 65;
            }
        }

        var findings = await new FindingStore(dbPath).ListAsync(new FindingFilter
        {
            TenantId = tenantId,
            ClientSlug = Args.Value(args, "--client"),
            MinSeverity = Args.Value(args, "--severity"),
            InQueueOnly = !all,
            SourceStates = all ? null : [SourceStates.Active, SourceStates.Unknown],
            Limit = 500,
        }, ct).ConfigureAwait(false);

        if (findings.Count == 0)
        {
            Console.WriteLine(all ? "No findings." : "Nothing open: no finding wants a person.");
            return 0;
        }

        Console.WriteLine();
        Console.WriteLine($"  {"severity",-8} {"source",-8} {"decision",-15} {"domain",-28} finding");
        foreach (var f in findings)
        {
            Console.WriteLine($"  {f.Severity,-8} {f.SourceState,-8} {f.AnalystState,-15} {f.Domain ?? "-",-28} {f.Title}");
            Console.WriteLine($"  {"",-8} {"",-8} {"",-15} {"",-28} {f.ClientName}; first seen {f.FirstObservedAt.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}, "
                + $"seen {f.ObservationCount.ToString(CultureInfo.InvariantCulture)}x; {f.Type}; {f.Id}");
        }

        var critical = findings.Count(f => f.InQueue && string.Equals(f.Severity, "critical", StringComparison.Ordinal)
            && !string.Equals(f.SourceState, SourceStates.Resolved, StringComparison.Ordinal));
        Console.WriteLine();
        Console.WriteLine($"  {findings.Count.ToString(CultureInfo.InvariantCulture)} finding(s); {critical.ToString(CultureInfo.InvariantCulture)} critical open.");
        return critical > 0 ? 1 : 0;
    }

    private static async Task<string?> TenantIdAsync(string dbPath, string slug, CancellationToken ct)
    {
        await using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        await db.OpenAsync(ct).ConfigureAwait(false);
        await using var command = db.CreateCommand();
        command.CommandText = "SELECT id FROM tenants WHERE slug = $slug AND deleted_at IS NULL";
        command.Parameters.AddWithValue("$slug", slug.Trim().ToLowerInvariant());
        return await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
    }

    private static async Task<int> ObserveAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--db") is var bad and not 0) { return bad; }
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}.");
            return 66;
        }
        if (!await SchemaGuard.IsCurrentAsync(dbPath, ct).ConfigureAwait(false)) { return 69; }

        var observed = await new ReportsFindingSource(dbPath).ObserveAllAsync(ct: ct).ConfigureAwait(false);
        if (observed.Count == 0) { Console.WriteLine("No organizations in the database yet."); }
        foreach (var org in observed)
        {
            Console.WriteLine(org.NotObserved is { } why
                ? $"{org.Organization}: reports not observed, {why}" + (org.Unknown > 0 ? $"; {org.Unknown} open finding(s) are now unknown" : "")
                : $"{org.Organization}: {org.Quiet} domain(s) quiet after reporting regularly; {org.Reporting} with an open finding reported on again");
        }

        var verified = await new RemediationFindingSource(dbPath).CheckEffectivenessAsync(ct: ct).ConfigureAwait(false);
        Console.WriteLine($"{verified} applied change(s) resolved: shown in force by a receiver's report, or fourteen days past DNS verification");

        var expired = await new FindingLifecycle(dbPath).ExpireExceptionsAsync(ct: ct).ConfigureAwait(false);
        Console.WriteLine($"{expired} exception(s) expired and their findings back in the queue");
        return 0;
    }
}
