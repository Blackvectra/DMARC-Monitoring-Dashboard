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
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--out", "--provider", "--client", "--month", "!--all", "!--pdf", "!--html") is var bad and not 0) { return bad; }

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
            var clients = await builder.GetClientsAsync(ct: ct).ConfigureAwait(false);

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

        // PDF is what a client receives, so PDF is what this writes. An .html
        // attachment is the one thing a mail gateway is most likely to strip
        // or warn about, and a customer warned about the document their
        // security provider just sent them has learned the wrong lesson.
        //
        // --html also writes the long on-screen version, which carries the
        // full evidence tables; --pdf is accepted and does nothing, so a
        // script written against the flag keeps working. The PDF is written
        // either way. It used to be switched off by --html, so asking for the
        // extra copy quietly lost the one document the command exists for.
        var wantsHtml = Args.Flag(args, "--html");

        // Said before writing, not after: a report built without names lists
        // a client's own mail filter among the impersonators, which is right
        // on what it knows and silent about knowing less than it could.
        var unnamed = await new DmarcMonitor.Core.Intelligence.SourceNameStore(dbPath)
            .UncheckedFailingSourcesAsync(period.Start, period.End, ct).ConfigureAwait(false);
        if (unnamed > 0)
        {
            Console.WriteLine($"  Note: {unnamed} failing source(s) in {period.Label} have not had their names looked up,");
            Console.WriteLine("  so these reports cannot recognize them as mail filters or known services. For that, first run:");
            Console.WriteLine($"    dmarc intel --names --db {dbPath}");
            Console.WriteLine();
        }

        var written = 0;
        var empty = 0;

        foreach (var each in slugs)
        {
            ct.ThrowIfCancellationRequested();

            var report = await builder.BuildAsync(each, period, provider, ct: ct).ConfigureAwait(false);
            if (report is null)
            {
                Console.Error.WriteLine($"  {each}: no such client.");
                continue;
            }

            // A month with no data still produces a report. The narrative says
            // so plainly, and that is worth sending: silence from a monitoring
            // provider is indistinguishable from a provider that stopped.
            if (report.Messages == 0) { empty++; }

            var stem = Path.Combine(outPath, $"{each}-{report.PeriodFileTag}");

            if (wantsHtml)
            {
                await File.WriteAllTextAsync($"{stem}.html", ClientReportRenderer.ToHtml(report), ct).ConfigureAwait(false);
                Console.WriteLine($"  {stem}.html  ({report.Messages:N0} message(s), {report.PassRate}% passing)");
            }

            await File.WriteAllBytesAsync($"{stem}.pdf", ClientReportPdf.Render(report), ct).ConfigureAwait(false);
            Console.WriteLine($"  {stem}.pdf   ({report.Messages:N0} message(s), {report.PassRate}% passing)");

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
