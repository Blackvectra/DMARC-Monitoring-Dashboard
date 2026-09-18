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
        // The diagnosis is shared with the domain page rather than worked out
        // again here: the two disagreeing about the same report is worse than
        // either of them being wrong on its own.
        var sources = ReportSources.Describe(report);

        Console.WriteLine($"  Sending sources ({sources.Count}):");
        Console.WriteLine();

        foreach (var s in sources)
        {
            switch (s.Outcome)
            {
                case SourceOutcome.Authenticated:
                    Console.WriteLine($"    OK        {s.SourceIp}  {Msgs(s.Messages)}, all authenticated");
                    break;

                case SourceOutcome.Forwarded:
                    Console.WriteLine($"    IGNORE    {s.SourceIp}  {N(s.Failing)} failed, but the receiver recognised a forwarder or mailing list");
                    Console.WriteLine("              Not an attack and not a misconfiguration. Nothing to do.");
                    break;

                case SourceOutcome.SignedForAnotherDomain:
                    ExplainSignedElsewhere(s);
                    break;

                case SourceOutcome.PassedSpfForAnotherDomain:
                    Console.WriteLine($"    FIX       {s.SourceIp}  {N(s.Failing)} failed");
                    Console.WriteLine($"              SPF passed, for {Join(s.UnalignedSpf)} rather than {s.HeaderFrom}.");
                    Console.WriteLine("              DMARC only counts a pass that matches the address recipients see, and");
                    Console.WriteLine("              nothing here signed as you, so this mail has nothing to fall back on.");
                    Console.WriteLine("              A relay sending under its own envelope is normal and cannot be fixed");
                    Console.WriteLine("              by changing SPF. Have it sign with DKIM as your domain instead.");
                    break;

                default:
                    Console.WriteLine($"    CHECK     {s.SourceIp}  {N(s.Failing)} failed, nothing authenticated");
                    Console.WriteLine("              Either a service of yours nobody recorded, or somebody sending as you.");
                    break;
            }
        }

        Console.WriteLine();
        return true;
    }

    /// <summary>
    /// The line every DMARC table renders as a contradiction: the signature
    /// verified and the message was rejected anyway.
    /// </summary>
    /// <remarks>
    /// Said as its own case because the reader has usually already set DKIM up
    /// and concluded the report is wrong. It is not: the key is good, and it is
    /// signing the wrong name.
    /// </remarks>
    private static void ExplainSignedElsewhere(SourceExplanation s)
    {
        Console.WriteLine($"    FIX       {s.SourceIp}  {N(s.Failing)} failed");
        Console.WriteLine($"              DKIM verified, signing {Join(s.UnalignedDkim.Select(u => "d=" + u.Domain))}");
        Console.WriteLine($"              rather than {s.HeaderFrom}. The signature is good; DMARC discards it");
        Console.WriteLine("              because the signing domain is not the one recipients see.");

        if (s.WouldAlignIfRelaxed)
        {
            // The cheapest fix in DMARC, and invisible unless something says
            // it: the sender is already signing inside the domain's own
            // namespace and the domain's own record is refusing it.
            Console.WriteLine("              This is a subdomain of yours, refused only because you publish");
            Console.WriteLine("              adkim=s. Either have it sign as the domain itself, or change adkim");
            Console.WriteLine("              to r once you have confirmed the subdomain is yours.");
        }
        else
        {
            Console.WriteLine("              Almost always a real service of yours signing with its own domain.");
            Console.WriteLine("              Have it sign as you; senders call this custom or branded DKIM, and");
            Console.WriteLine("              it is usually set per product, so one kind of mail can be signing");
            Console.WriteLine("              correctly while another is not.");
        }
    }

    /// <summary>At most three, so one source cannot fill the screen.</summary>
    private static string Join(IEnumerable<string> values)
    {
        var list = values.ToList();
        return list.Count <= 3
            ? string.Join(", ", list)
            : string.Join(", ", list.Take(3)) + $" and {list.Count - 3} more";
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
