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
    /// Creates the database if this install does not have one yet, and brings
    /// one that is ours but behind up to date where that is this application's
    /// decision to make.
    /// </summary>
    /// <remarks>
    /// Deliberately narrow. It creates a database only where there is
    /// effectively nothing - no file, or a zero-byte one, which is what SQLite
    /// leaves behind when something opened a path and never wrote a page. It
    /// does not touch a file with bytes in it unless that file is a DMARC
    /// Monitor database: guessing at somebody's file is how data goes missing.
    ///
    /// <paramref name="mayUpgrade"/> is the one thing that has changed, and
    /// only for the copy somebody downloaded. Upgrading it used to mean
    /// copying <c>dmarc.db</c> into the new folder and knowing to run
    /// <c>dmarc init-db</c>, which is written down nowhere a person upgrading
    /// would look - so the dashboard either opened empty or reported a
    /// database it could not read, and both of those read as "it lost my
    /// data". On a server it stays off: migrating somebody's production
    /// database because a service restarted is a decision an operator makes,
    /// and <c>deploy/update.sh</c> already makes it explicitly.
    /// </remarks>
    public static async Task EnsureDatabaseAsync(
        string dbPath, ILogger logger, bool mayUpgrade = false, CancellationToken ct = default)
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
                return;
            }

            await UpgradeAsync(dbPath, logger, mayUpgrade, ct).ConfigureAwait(false);
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

    /// <summary>
    /// A database of ours, which may or may not be at the schema this build
    /// expects.
    /// </summary>
    /// <remarks>
    /// Three outcomes, and the two that change nothing still say something.
    /// A database behind this build fails one page at a time - "no such
    /// column: mta_sts_mode" - which names a symptom rather than the thing to
    /// do about it, so where this will not upgrade it says what will.
    /// </remarks>
    private static async Task UpgradeAsync(
        string dbPath, ILogger logger, bool mayUpgrade, CancellationToken ct)
    {
        IReadOnlyList<Migration> pending;
        string version;

        try
        {
            pending = await DatabaseMigrations.PendingAsync(dbPath, ct).ConfigureAwait(false);
            version = await DatabaseMigrations.VersionAsync(dbPath, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Readable enough to answer IsInitializedAsync and not readable
            // now: a file being written by something else, or a disk giving
            // up. Not a reason to refuse to start.
            FirstRunLog.CouldNotCheckSchema(logger, dbPath, ex);
            return;
        }

        if (pending.Count == 0)
        {
            // The other direction, which happens when somebody keeps two
            // copies and opens the older one: nothing here can undo a
            // migration, and a page failing on a table this build has never
            // heard of is otherwise completely baffling.
            var known = DatabaseMigrations.All.Count > 0
                ? DatabaseMigrations.All[^1].Version
                : DatabaseMigrations.BaselineVersion;

            if (string.CompareOrdinal(version, known) > 0)
            {
                FirstRunLog.FromANewerBuild(logger, dbPath, version, known);
            }

            return;
        }

        if (!mayUpgrade)
        {
            FirstRunLog.BehindAndLeftAlone(logger, dbPath, version, pending.Count, dbPath);
            return;
        }

        try
        {
            var result = await DatabaseMigrations.ApplyAsync(dbPath, ct).ConfigureAwait(false);
            FirstRunLog.Upgraded(logger, version, result.Version, string.Join(", ", result.Applied));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Each migration commits with its own version, so what failed did
            // not half-apply. The database is at whatever it really is at, and
            // starting anyway leaves the pages that do work working.
            FirstRunLog.UpgradeFailed(logger, dbPath, ex);
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

    [LoggerMessage(
        EventId = 1013,
        Level = LogLevel.Information,
        Message = "The database was at schema {Was} and this build expects {Now}, so it has been "
                + "brought up to date. Applied: {Applied}. Nothing in it was replaced.")]
    public static partial void Upgraded(ILogger logger, string was, string now, string applied);

    [LoggerMessage(
        EventId = 1014,
        Level = LogLevel.Warning,
        Message = "{Path} is at schema {Version} and this build is {Count} migration(s) ahead of "
                + "it. It has been left exactly as it is, because upgrading a database somebody "
                + "else's work depends on is not something a restart should decide. Run "
                + "`dmarc init-db --db \"{Database}\"` to bring it up to date; until then the "
                + "pages that read the newer columns will report a database they cannot read.")]
    public static partial void BehindAndLeftAlone(
        ILogger logger, string path, string version, int count, string database);

    [LoggerMessage(
        EventId = 1015,
        Level = LogLevel.Warning,
        Message = "{Path} is at schema {Version}, which is newer than the {Known} this build "
                + "knows. It was written by a later version of DMARC Monitor and nothing here can "
                + "undo that. Use the newer build, or point Database:Path at a different file.")]
    public static partial void FromANewerBuild(ILogger logger, string path, string version, string known);

    [LoggerMessage(
        EventId = 1016,
        Level = LogLevel.Warning,
        Message = "Could not tell what schema {Path} is at, so it has been left alone.")]
    public static partial void CouldNotCheckSchema(ILogger logger, string path, Exception exception);

    [LoggerMessage(
        EventId = 1017,
        Level = LogLevel.Error,
        Message = "Could not bring {Path} up to date. Each migration commits with its own version, "
                + "so the database is at a schema it really is at rather than half way to one. "
                + "`dmarc init-db` will report the same failure with more detail.")]
    public static partial void UpgradeFailed(ILogger logger, string path, Exception exception);
}
