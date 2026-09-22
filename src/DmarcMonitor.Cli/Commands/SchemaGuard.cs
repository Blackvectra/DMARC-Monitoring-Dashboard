using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Cli.Commands;

/// <summary>
/// Refuses to write reports into a database older than this build expects.
///
/// Every command that stores reports has to ask, because the failure without
/// it is the worst shape there is: silent. A build whose schema has moved on
/// writes columns the old database does not allow, the insert is refused, and
/// - before this existed alongside a fix to how those refusals were read -
/// every report came back counted as one already held. `dmarc import` printed
/// "404 files seen, 0 stored, 404 already stored" and exited 0, having thrown
/// away sixty-five real reports.
///
/// That is now an error rather than a duplicate, but a hundred identical
/// errors is a worse way to learn this than one sentence before anything
/// starts. The fix is one command and it is named here.
/// </summary>
internal static class SchemaGuard
{
    /// <summary>
    /// True when the database is current and it is safe to write to it.
    /// Prints what to run, and why, when it is not.
    /// </summary>
    public static async Task<bool> IsCurrentAsync(string dbPath, CancellationToken ct)
    {
        var pending = await DatabaseMigrations.PendingAsync(dbPath, ct).ConfigureAwait(false);
        if (pending.Count == 0) { return true; }

        var version = await DatabaseMigrations.VersionAsync(dbPath, ct).ConfigureAwait(false);

        Console.Error.WriteLine(
            $"{Path.GetFullPath(dbPath)} is at schema {version}; this build expects "
          + $"{DatabaseMigrations.BaselineVersion}.");
        Console.Error.WriteLine();
        Console.Error.WriteLine($"  {Plural(pending.Count)} to apply:");
        foreach (var migration in pending) { Console.Error.WriteLine($"    {migration.Version} {migration.Description}"); }
        Console.Error.WriteLine();
        Console.Error.WriteLine($"  Bring it up to date first:  dmarc init-db --db {dbPath}");
        Console.Error.WriteLine();
        Console.Error.WriteLine("  Refused rather than attempted, because storing reports into a database");
        Console.Error.WriteLine("  this build does not match is how data goes missing quietly.");

        return false;
    }

    private static string Plural(int count) =>
        count == 1 ? "1 migration" : $"{count} migrations";
}
