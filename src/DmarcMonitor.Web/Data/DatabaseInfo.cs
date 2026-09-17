namespace DmarcMonitor.Web.Data;

/// <summary>
/// Where the SQLite file is.
/// </summary>
/// <remarks>
/// Its own file because several services take it, and it used to sit inside
/// TriageService, which meant moving that service moved this with it.
/// </remarks>
public sealed record DatabaseInfo(string Path);
