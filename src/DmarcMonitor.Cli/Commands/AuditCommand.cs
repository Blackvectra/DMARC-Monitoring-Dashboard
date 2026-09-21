using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Audits a zone file against live DNS and against the reports.
///
/// The one input that can enumerate. DNS will not list a domain's DKIM
/// selectors and will not transfer a zone to a stranger, so every check that
/// asks "what else is in here" has to start from a file somebody exported.
/// GoDaddy, Cloudflare and Route 53 all hand one over in the same format, and
/// an operator asking for a zone to be audited has it in front of them
/// already.
/// </summary>
public static class AuditCommand
{
    /// <summary>
    /// The largest file this will read.
    /// </summary>
    /// <remarks>
    /// A zone with a hundred thousand records is not the sort of thing anybody
    /// pastes into a command, and reading whatever is pointed at is how a
    /// mistyped path turns into a process holding a database file in memory.
    /// </remarks>
    private const int MaxBytes = 4 * 1024 * 1024;

    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (Args.Reject(args, "--zone", "--domain", "--db", "!--offline") is var bad and not 0) { return bad; }

        var path = Args.Value(args, "--zone");
        var domain = Args.Value(args, "--domain");
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var offline = Args.Flag(args, "--offline");

        if (string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine("dmarc audit --zone <file> [--domain <d>] [--db <path>] [--offline]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  The file is a BIND-format zone export. Every registrar and DNS host");
            Console.Error.WriteLine("  offers one: GoDaddy calls it 'Export zone file', Cloudflare and");
            Console.Error.WriteLine("  Route 53 'Export DNS records'.");
            return 64;
        }

        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"No file at {Path.GetFullPath(path)}.");
            return 66;
        }

        var size = new FileInfo(path).Length;
        if (size > MaxBytes)
        {
            Console.Error.WriteLine($"{Path.GetFullPath(path)} is {size / 1024 / 1024} MB. "
                                  + $"This reads zone files, which are far smaller than {MaxBytes / 1024 / 1024} MB.");
            return 66;
        }

        var text = await File.ReadAllTextAsync(path, ct).ConfigureAwait(false);

        // No database is not an error here. Auditing a zone before the domain
        // is a customer is the commonest use of this, exactly as it is for
        // 'check', and the findings that need the reports stay quiet.
        var auditor = new ZoneAuditor(databasePath: File.Exists(dbPath) ? dbPath : null);
        var report = await auditor.RunAsync(text, domain, offline, ct).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine($"  {(report.Zone.Origin.Length > 0 ? report.Zone.Origin : Path.GetFileName(path))}");
        Console.WriteLine($"    {report.ReadSummary}");
        Console.WriteLine($"    {report.EvidenceSummary}");

        if (report.SelectorsNotChecked > 0)
        {
            Console.WriteLine($"    {report.SelectorsNotChecked} selector(s) past the limit of "
                            + $"{ZoneAuditor.SelectorLimit} were not resolved, so nothing is said about them");
        }

        // Before the findings, not after. A finding list read without knowing
        // that six lines were unreadable is a list somebody trusts as complete.
        foreach (var problem in report.Zone.Problems)
        {
            Console.WriteLine($"    line {problem.Line}: not read - {problem.Reason}");
            Console.WriteLine($"              {problem.Text}");
        }

        Console.WriteLine();

        if (report.Findings.Count == 0)
        {
            Console.WriteLine("    nothing to change");
            Console.WriteLine();
            return 0;
        }

        foreach (var f in report.Findings)
        {
            var label = f.Severity switch
            {
                HygieneSeverity.Breaking => "BREAKING",
                HygieneSeverity.Weakness => "weakness",
                _ => "tidy",
            };

            var where = f.Name.Length > 0 ? $" {f.Name}" : "";
            var line = f.Line > 0 ? $" (line {f.Line})" : "";

            Console.WriteLine($"    [{label}] {f.Record}{where}{line}: {f.Problem}");
            Console.WriteLine($"              fix: {f.Fix}");
            Console.WriteLine($"              from: {f.Evidence}");
            if (f.Reference.Length > 0) { Console.WriteLine($"              per: {f.Reference}"); }
        }

        Console.WriteLine();
        return report.AnythingBreaking ? 1 : 0;
    }
}
