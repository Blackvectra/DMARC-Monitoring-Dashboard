using DmarcMonitor.Core.Intelligence;

namespace DmarcMonitor.Cli.Commands;

/// <summary>Refreshes and shows what this operator has learned about impersonating sources.</summary>
public static class IntelCommand
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // A mistyped flag used to be ignored, which changed what the
        // command did without saying so. See Args.Reject.
        if (Args.Reject(args, "--db", "--export") is var bad and not 0) { return bad; }

        var dbPath = Args.Value(args, "--db") ?? "dmarc.db";
        if (!File.Exists(dbPath))
        {
            Console.Error.WriteLine($"No database at {dbPath}. Run: dmarc init-db --db {dbPath}");
            return 69;
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
}
