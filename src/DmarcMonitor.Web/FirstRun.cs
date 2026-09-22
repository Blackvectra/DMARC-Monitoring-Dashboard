using DmarcMonitor.Core.Storage;

namespace DmarcMonitor.Web;

/// <summary>
/// What has to be true before the first request is served.
///
/// On a managed install none of this is needed: <c>deploy/install.sh</c> runs
/// <c>dmarc init-db</c> before it ever starts the service, so the database is
/// there with its schema in it by the time the app loads. That made the app's
/// own behaviour on a missing database invisible - and it was bad. Pointed at
/// a path that does not exist, it started happily, left a zero-byte
/// <c>dmarc.db</c> behind the first time a page touched it, and rendered
/// "Could not read the database: no such table: tenants" on every screen.
///
/// Which is exactly what somebody downloading a copy to try would get, since
/// there is no installer in that story to have run the command first. So the
/// app now creates its own database when there is not one, from the schema
/// compiled into it - the same one <c>dmarc init-db</c> uses.
/// </summary>
internal static class FirstRun
{
    /// <summary>
    /// Creates the database if this install does not have one yet.
    /// </summary>
    /// <remarks>
    /// Deliberately narrow. It creates a database only where there is
    /// effectively nothing - no file, or a zero-byte one, which is what SQLite
    /// leaves behind when something opened a path and never wrote a page. It
    /// does not migrate an existing database and it does not touch a file with
    /// bytes in it, whatever those bytes are: guessing at somebody's file is
    /// how data goes missing, and an upgrade is <c>dmarc init-db</c>'s job,
    /// run by a person who decided to.
    /// </remarks>
    public static async Task EnsureDatabaseAsync(
        string dbPath, ILogger logger, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dbPath);
        ArgumentNullException.ThrowIfNull(logger);

        var existing = new FileInfo(dbPath);

        if (existing.Exists && existing.Length > 0)
        {
            // Somebody's database. Whether it is ours is worth saying, because
            // the alternative is every page reporting a missing table and
            // nothing explaining why.
            if (!await new ReportStore(dbPath).IsInitializedAsync(ct).ConfigureAwait(false))
            {
                FirstRunLog.NotOurs(logger, dbPath);
            }

            return;
        }

        // The directory may not exist either - a configured path pointing
        // somewhere that was never created is the ordinary way this happens.
        var directory = Path.GetDirectoryName(Path.GetFullPath(dbPath));
        if (!string.IsNullOrEmpty(directory)) { Directory.CreateDirectory(directory); }

        try
        {
            await new ReportStore(dbPath)
                .InitializeAsync(DatabaseSchema.Sql, ct)
                .ConfigureAwait(false);

            FirstRunLog.Created(logger, dbPath);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A half-built database is worse than none, because the next start
            // finds some tables and assumes the rest. Remove it and say so;
            // the app still starts, and the pages report a database they
            // cannot read, which is now the truth rather than a mystery.
            FirstRunLog.Failed(logger, dbPath, ex);
            TryDelete(dbPath);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}

internal static partial class FirstRunLog
{
    [LoggerMessage(
        EventId = 1010,
        Level = LogLevel.Information,
        Message = "Created a new database at {Path}. Import reports to fill it: the Import page, "
                + "or `dmarc import --from <folder>`.")]
    public static partial void Created(ILogger logger, string path);

    [LoggerMessage(
        EventId = 1011,
        Level = LogLevel.Warning,
        Message = "{Path} exists but is not a DMARC Monitor database, so it has been left alone. "
                + "Every page will report a database it cannot read until this is moved aside or "
                + "Database:Path points somewhere else.")]
    public static partial void NotOurs(ILogger logger, string path);

    [LoggerMessage(
        EventId = 1012,
        Level = LogLevel.Error,
        Message = "Could not create a database at {Path}. It has been removed rather than left "
                + "half-built.")]
    public static partial void Failed(ILogger logger, string path, Exception exception);
}
