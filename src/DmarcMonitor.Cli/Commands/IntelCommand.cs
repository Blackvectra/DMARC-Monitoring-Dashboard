using DmarcMonitor.Core.Intelligence;

namespace DmarcMonitor.Cli.Commands;

/// <summary>Refreshes and shows what this operator has learned about impersonating sources.</summary>
public static class IntelCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--export", "!--names", "--names-limit") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {dbPath}. Run: dmarc init-db --db {dbPath}");
            return 69;
        }

        // Reverse lookups, which is network rather than database work and can
        // take minutes on an estate with dead reverse zones. Behind a flag
        // rather than folded into the refresh below, so that a person running
        // `dmarc intel` to read the summary gets it now, and the nightly unit
        // that has time asks for the names.
        if (Args.Flag(args, "--names"))
        {
            return await ResolveNamesAsync(dbPath, Args.Int(args, "--names-limit", 500), ct).ConfigureAwait(false);
        }

        var service = new ThreatIntelligenceService(dbPath);
        await service.RefreshAsync(ct: ct).ConfigureAwait(false);

        if (Args.Flag(args, "--export"))
        {
            Console.WriteLine(await service.ExportAsync(ct).ConfigureAwait(false));
            return 0;
        }

        var fleet = await service.GetFleetSummaryAsync(ct: ct).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine("  FLEET");
        Console.WriteLine($"    clients              {fleet.Clients}");
        Console.WriteLine($"    domains              {fleet.Domains}  ({fleet.DomainsEnforcing} enforcing, {fleet.DomainsAtNone} at p=none, {fleet.DomainsSilent} silent)");
        // The window is named because the two lines above it are current
        // counts, and a total that cannot be reconciled with them reads as a
        // bug rather than as a different question.
        Console.WriteLine($"    messages seen        {fleet.Messages:N0}  ({fleet.PassRate}% authenticated, last {fleet.WindowDays} days)");
        Console.WriteLine($"    enforcement          {fleet.EnforcementRate}% of domains");
        Console.WriteLine();
        Console.WriteLine("  INTELLIGENCE");
        Console.WriteLine($"    indicators           {fleet.Indicators}");
        Console.WriteLine($"    hitting >1 domain    {fleet.MultiTargetIndicators}");
        Console.WriteLine($"    forgery attempts     {fleet.ForgeryAttempts}");
        Console.WriteLine();

        var indicators = await service.GetIndicatorsAsync(ct: ct).ConfigureAwait(false);
        if (indicators.Count == 0) { Console.WriteLine("  Nothing impersonating any client."); return 0; }

        Console.WriteLine("  TOP SOURCES (strongest evidence first)");
        Console.WriteLine();
        foreach (var i in indicators.Take(12))
        {
            Console.WriteLine($"    [{i.Confidence,-9}] {i.Value,-16} {i.MessageCount,5:N0} msg  {i.DomainCount} domain(s)  {string.Join(", ", i.Domains)}");
            Console.WriteLine($"                  {i.Rationale}");
        }
        Console.WriteLine();
        return 0;
    }

    /// <summary>
    /// Asks DNS what the addresses in the reports reverse to, and remembers
    /// the answers.
    /// </summary>
    /// <remarks>
    /// Run nightly rather than while a page renders: one reverse lookup per
    /// row, on the request thread, against addresses chosen by whoever mailed
    /// the reports is slow when the zones answer and an outage when they do
    /// not. Run by hand after an import when somebody wants the names today
    /// rather than tomorrow.
    /// </remarks>
    private static async Task<int> ResolveNamesAsync(string dbPath, int limit, CancellationToken ct)
    {
        var store = new SourceNameStore(dbPath);
        var resolver = new SourceNameResolver(store, new DmarcMonitor.Core.Dns.DnsLookup());

        var before = await store.CoverageAsync(ct).ConfigureAwait(false);

        Console.WriteLine();
        Console.WriteLine($"  Looking up at most {limit} source(s), busiest first.");

        var run = await resolver.RunAsync(limit, ct).ConfigureAwait(false);
        var after = await store.CoverageAsync(ct).ConfigureAwait(false);

        Console.WriteLine($"  {run.Describe()}");
        Console.WriteLine();
        Console.WriteLine($"  Named {after.Named} of {after.Total} source(s) in the database"
            + (after.Named > before.Named ? $", up {after.Named - before.Named} this run." : "."));

        if (after.Named < after.Total)
        {
            // Said plainly, because "some are still addresses" is otherwise
            // read as the feature not working. An address with no PTR is an
            // ordinary thing and no amount of re-running fixes it.
            Console.WriteLine($"  {after.Total - after.Named} still have no name: either no reverse record exists,");
            Console.WriteLine("  or this run's limit was reached. Run it again to continue.");
        }

        Console.WriteLine();
        return 0;
    }
}
