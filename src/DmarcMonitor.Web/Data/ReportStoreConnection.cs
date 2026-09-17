using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web.Data;

/// <summary>
/// Opens read connections to the report database.
///
/// Separate from ReportStore because the web app only ever reads: an ingest
/// run writes, and this renders what it wrote. Keeping them apart means a page
/// cannot accidentally modify a customer's data, and a long-running query
/// cannot block a run.
/// </summary>
public sealed class ReportStoreConnection(DatabaseInfo database)
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = database.Path,
        Mode = SqliteOpenMode.ReadOnly,
        Cache = SqliteCacheMode.Shared,
    }.ToString();

    private readonly string _path = database.Path;

    /// <summary>True when there is a database to read at all.</summary>
    public bool Exists => File.Exists(_path);

    public string Path => _path;

    public async Task<SqliteConnection> OpenAsync(CancellationToken ct = default)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        return connection;
    }
}
