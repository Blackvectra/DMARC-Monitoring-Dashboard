using System.Globalization;
using DmarcMonitor.Core.Reporting;
using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Writes the monthly report a client actually receives.
///
/// Defaults to the month that has ENDED rather than the one in progress, so
/// running it on the 3rd and again on the 20th produces the same document.
/// A report whose numbers move depending on when it was generated is one that
/// cannot be reconciled against an invoice.
/// </summary>
public static class ReportCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        var outPath = Args.Value(args, "--out") ?? "reports";
        var provider = Args.Value(args, "--provider") ?? "your IT provider";
        var slug = Args.Value(args, "--client");
        var all = Args.Flag(args, "--all");

        if (string.IsNullOrWhiteSpace(slug) && !all)
        {
            Console.Error.WriteLine("dmarc report --client <slug> [--month yyyy-MM] [--out <folder>] [--db <path>]");
            Console.Error.WriteLine("dmarc report --all     [--month yyyy-MM] [--out <folder>] [--db <path>]");
            return 64;
        }

        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {Path.GetFullPath(dbPath)}. Run: dmarc init-db --db {dbPath}");
            return 66;
        }

        if (!TryPeriod(Args.Value(args, "--month"), out var period, out var error))
        {
            Console.Error.WriteLine(error);
            return 64;
        }

        var builder = new ClientReportBuilder(dbPath);

        List<string> slugs;
        if (all)
        {
            var clients = await builder.GetClientsAsync(ct).ConfigureAwait(false);

            // Unassigned is a worklist, not a customer. Writing a report
            // addressed to it would be a document nobody can send.
            slugs = [.. clients.Where(c => c.Slug != ReportStore.UnassignedClientSlug).Select(c => c.Slug)];
            if (slugs.Count == 0)
            {
                Console.Error.WriteLine("No clients to report on yet. Run: dmarc client add --name \"<name>\"");
                return 66;
            }
        }
        else
        {
            slugs = [slug!];
        }

        // Checked, because Directory.CreateDirectory throws when the path is
        // an existing file and the exception reached the operator as a stack
        // trace under a banner saying "This is a bug". Naming a file where a
        // folder goes is an ordinary typo, not a bug.
        if (File.Exists(outPath))
        {
            Console.Error.WriteLine($"--out names a folder to write the reports into, not a file. {outPath} is a file.");
            return 66;
        }

        Directory.CreateDirectory(outPath);

        var written = 0;
        var empty = 0;

        foreach (var each in slugs)
        {
            ct.ThrowIfCancellationRequested();

            var report = await builder.BuildAsync(each, period, provider, ct).ConfigureAwait(false);
            if (report is null)
            {
                Console.Error.WriteLine($"  {each}: no such client.");
                continue;
            }

            // A month with no data still produces a report. The narrative says
            // so plainly, and that is worth sending: silence from a monitoring
            // provider is indistinguishable from a provider that stopped.
            if (report.Messages == 0) { empty++; }

            var file = Path.Combine(outPath, $"{each}-{period.Start:yyyy-MM}.html");
            await File.WriteAllTextAsync(file, ClientReportRenderer.ToHtml(report), ct).ConfigureAwait(false);

            Console.WriteLine($"  {file}  ({report.Messages:N0} message(s), {report.PassRate}% passing)");
            written++;
        }

        Console.WriteLine();
        Console.WriteLine($"{written} report(s) for {period.Label} written to {Path.GetFullPath(outPath)}");
        if (empty > 0)
        {
            Console.WriteLine($"{empty} of them cover a month with no reports at all, which is worth looking into.");
        }

        return written > 0 ? 0 : 1;
    }

    /// <summary>
    /// Reads --month, or falls back to the month that has ended.
    /// </summary>
    private static bool TryPeriod(string? month, out ReportPeriod period, out string error)
    {
        error = "";

        if (string.IsNullOrWhiteSpace(month))
        {
            period = ReportPeriod.MonthEnding(DateTimeOffset.UtcNow);
            return true;
        }

        if (!DateTime.TryParseExact(month, "yyyy-MM", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var parsed))
        {
            period = ReportPeriod.MonthEnding(DateTimeOffset.UtcNow);
            error = $"--month must look like 2026-08, not '{month}'.";
            return false;
        }

        period = ReportPeriod.ForMonth(parsed.Year, parsed.Month);
        return true;
    }
}
