using System.Globalization;
using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Ingest;
using DmarcMonitor.Core.Tls;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Reads a report file and explains it in plain English.
///
/// Needs no mailbox, no database and no configuration, which makes it the one
/// thing that works the moment somebody hands you a report. Every other tool
/// renders the XML as a table, which moves the confusion rather than removing
/// it: a table shows that SPF said pass and DMARC said fail and leaves the
/// reader to work out how both can be true.
/// </summary>
public static class ExplainCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Give me a report file: dmarc explain <file>");
            Console.Error.WriteLine("It can be .xml, .json, .gz or .zip, exactly as it arrived.");
            return 64;
        }

        var path = args[0];
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"No such file: {path}");
            return 66;   // EX_NOINPUT
        }

        byte[] bytes;
        try
        {
            bytes = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"Could not read {path}: {ex.Message}");
            return 66;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"Could not read {path}: {ex.Message}");
            return 77;   // EX_NOPERM
        }

        var extracted = ReportAttachment.Extract(Path.GetFileName(path), bytes);
        if (extracted.Count == 0)
        {
            Console.Error.WriteLine($"{Path.GetFileName(path)} does not contain a DMARC or TLS report.");
            Console.Error.WriteLine("Aggregate reports are XML starting with <feedback>; TLS reports are JSON with a 'policies' array.");
            return 65;   // EX_DATAERR
        }

        var anyFailed = false;
        foreach (var report in extracted)
        {
            switch (report.Kind)
            {
                case ReportKind.DmarcAggregate:
                    if (!ExplainAggregate(report.Content)) { anyFailed = true; }
                    break;
                case ReportKind.TlsRpt:
                    if (!ExplainTls(report.Content)) { anyFailed = true; }
                    break;
                default:
                    Console.Error.WriteLine($"{report.FileName}: not a report this version can read.");
                    anyFailed = true;
                    break;
            }
        }

        return anyFailed ? 65 : 0;
    }

    private static bool ExplainAggregate(string xml)
    {
        var parsed = AggregateReportParser.Parse(xml);
        if (!parsed.Success)
        {
            Console.Error.WriteLine($"Could not read this report: {parsed.Error}");
            return false;
        }

        var report = parsed.Report!;
        var p = report.Policy;

        Console.WriteLine();
        Console.WriteLine($"  {report.Metadata.OrgName} reported on {p.Domain}");
        Console.WriteLine($"  {Window(report.Metadata.Begin, report.Metadata.End)}");
        Console.WriteLine();

        var rate = report.TotalMessages == 0
            ? 0
            : Math.Round(report.PassingMessages * 100.0 / report.TotalMessages, 1);

        Console.WriteLine($"  {Msgs(report.TotalMessages)} claimed to come from {p.Domain}.");
        Console.WriteLine($"  {N(report.PassingMessages)} ({rate}%) authenticated correctly. {N(report.FailingMessages)} did not.");
        Console.WriteLine();
        Console.WriteLine("  This is one receiver's view of your mail, not all of it.");
        Console.WriteLine();

        // The published policy, said in terms of what it DOES.
        Console.WriteLine($"  Your policy at the time was p={p.P.ToString().ToLowerInvariant()}, which means:");
        Console.WriteLine(p.P switch
        {
            DmarcPolicy.Reject => "    mail failing authentication for this domain was refused outright.",
            DmarcPolicy.Quarantine => "    mail failing authentication went to junk rather than the inbox.",
            _ => "    nothing was blocked. Receivers reported what they saw and delivered it anyway.",
        });

        if (p.Pct < 100)
        {
            Console.WriteLine($"    pct={p.Pct}, so the policy applied to only {p.Pct}% of it.");
        }
        if (p.Adkim == AlignmentMode.Strict || p.Aspf == AlignmentMode.Strict)
        {
            Console.WriteLine("    alignment is strict, so an exact domain match is required rather than a subdomain.");
        }
        if (p.Np is { } np && np != p.P)
        {
            Console.WriteLine($"    np={np.ToString().ToLowerInvariant()} covers subdomains that were never registered.");
        }
        Console.WriteLine();

        // Sources, worst first, grouped so one line means one sending server.
        var groups = report.Records
            .GroupBy(r => r.SourceIp, StringComparer.Ordinal)
            .Select(g => new
            {
                Ip = g.Key,
                Count = g.Sum(r => (long)r.Count),
                Passing = g.Where(r => r.IsDmarcPass).Sum(r => (long)r.Count),
                Overridden = g.Any(r => r.WasOverridden),
                SpfDomains = g.SelectMany(r => r.SpfResults).Select(a => a.Domain).Distinct(StringComparer.Ordinal).ToList(),
                DkimDomains = g.SelectMany(r => r.DkimResults).Select(a => a.Domain).Distinct(StringComparer.Ordinal).ToList(),
                HeaderFrom = g.Select(r => r.HeaderFrom).FirstOrDefault(h => !string.IsNullOrEmpty(h)) ?? p.Domain,
            })
            .OrderBy(g => g.Passing == g.Count)      // problems first
            .ThenByDescending(g => g.Count)
            .ToList();

        Console.WriteLine($"  Sending sources ({groups.Count}):");
        Console.WriteLine();

        foreach (var g in groups)
        {
            var failing = g.Count - g.Passing;
            if (failing == 0)
            {
                Console.WriteLine($"    OK        {g.Ip}  {Msgs(g.Count)}, all authenticated");
                continue;
            }

            if (g.Overridden)
            {
                Console.WriteLine($"    IGNORE    {g.Ip}  {N(failing)} failed, but the receiver recognised a forwarder or mailing list");
                Console.WriteLine("              Not an attack and not a misconfiguration. Nothing to do.");
                continue;
            }

            // The case every table renders as a contradiction: authentication
            // succeeded, but for a domain the recipient never sees.
            var elsewhere = g.SpfDomains.Concat(g.DkimDomains)
                .Where(d => !string.IsNullOrEmpty(d) && !Aligns(d, g.HeaderFrom))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (elsewhere.Count > 0)
            {
                Console.WriteLine($"    FIX       {g.Ip}  {N(failing)} failed");
                Console.WriteLine($"              Authentication succeeded, but for {string.Join(", ", elsewhere)} rather than {g.HeaderFrom}.");
                Console.WriteLine("              DMARC only counts authentication matching the address recipients see, so");
                Console.WriteLine("              this is recorded as a failure even though the checks themselves passed.");
                Console.WriteLine("              Almost always a real service of yours set up with the provider's own");
                Console.WriteLine("              domain. Under enforcement this mail starts going to junk.");
                continue;
            }

            Console.WriteLine($"    CHECK     {g.Ip}  {N(failing)} failed, nothing authenticated");
            Console.WriteLine("              Either a service of yours nobody recorded, or somebody sending as you.");
        }

        Console.WriteLine();
        return true;
    }

    private static bool ExplainTls(string json)
    {
        var parsed = TlsReportParser.Parse(json);
        if (!parsed.Success)
        {
            Console.Error.WriteLine($"Could not read this TLS report: {parsed.Error}");
            return false;
        }

        var report = parsed.Report!;
        var domain = report.Policies.Count > 0 ? report.Policies[0].Policy.Domain : "(unknown)";

        Console.WriteLine();
        Console.WriteLine($"  {report.OrganizationName} reported on TLS delivery to {domain}");
        Console.WriteLine($"  {Window(report.Begin, report.End)}");
        Console.WriteLine();
        Console.WriteLine($"  {N(report.SuccessfulSessions)} connections used TLS successfully. {N(report.FailedSessions)} failed.");
        Console.WriteLine();

        foreach (var policy in report.Policies)
        {
            var mode = policy.Policy.Mode;
            Console.WriteLine($"  Policy: {policy.Policy.Type.ToString().ToLowerInvariant()}, mode {mode.ToString().ToLowerInvariant()}");

            // The point of reading these at all.
            if (mode == MtaStsMode.Testing)
            {
                Console.WriteLine();
                Console.WriteLine("    Testing mode protects nothing. Receivers report failures and then");
                Console.WriteLine("    deliver over plaintext anyway. A domain can sit here for years,");
                Console.WriteLine("    generate perfectly clean reports, and be no better off than one with");
                Console.WriteLine("    no policy at all. Move to enforce once the reports look clean.");
            }
            else if (mode == MtaStsMode.Enforce)
            {
                Console.WriteLine("    Enforcing: a receiver that cannot negotiate TLS refuses to deliver.");
            }

            foreach (var failure in policy.Failures)
            {
                Console.WriteLine();
                Console.WriteLine($"    {failure.RawResultType}: {N(failure.FailedSessionCount)} sessions");
                if (!string.IsNullOrEmpty(failure.ReceivingMxHostname))
                {
                    Console.WriteLine($"      to {failure.ReceivingMxHostname}");
                }
                Console.WriteLine(failure.SuggestsInterception
                    ? "      This is what an active downgrade looks like from the sender's side. Worth investigating now."
                    : "      Looks like a certificate or configuration problem rather than an attack.");
            }
        }

        Console.WriteLine();
        return true;
    }

    /// <summary>Relaxed alignment, matching how DMARC actually decides.</summary>
    private static bool Aligns(string authDomain, string headerFrom)
    {
        if (string.IsNullOrEmpty(authDomain) || string.IsNullOrEmpty(headerFrom)) { return false; }
        if (string.Equals(authDomain, headerFrom, StringComparison.OrdinalIgnoreCase)) { return true; }
        return authDomain.EndsWith('.' + headerFrom, StringComparison.OrdinalIgnoreCase)
            || headerFrom.EndsWith('.' + authDomain, StringComparison.OrdinalIgnoreCase);
    }

    private static string Window(DateTimeOffset begin, DateTimeOffset end)
    {
        if (begin == DateTimeOffset.MinValue) { return "over an unstated period"; }
        var b = begin.UtcDateTime.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture);
        var e = end.UtcDateTime.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture);
        return $"{b} to {e} UTC";
    }

    /// <summary>Thousands separators: "14000 messages" reads as a typo.</summary>
    private static string N(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    /// <summary>A message count with the right noun. "1 messages" reads as a bug.</summary>
    private static string Msgs(long value) => value == 1 ? "1 message" : $"{N(value)} messages";
}
