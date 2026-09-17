namespace DmarcMonitor.Web;

/// <summary>
/// The lines printed once at startup, saying how this instance is configured.
///
/// Source-generated rather than called through ILogger.LogInformation because
/// the plain call passes its arguments as a params object[], which is an
/// allocation on a path that may be switched off. The generator emits a typed
/// method that allocates nothing and is guarded by IsEnabled, and checks the
/// message template against the parameters at compile time, so a renamed
/// placeholder is a build error rather than a log line reading "{Path}".
/// </summary>
internal static partial class StartupLog
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Sign-in: Microsoft Entra.")]
    public static partial void SignInEntra(ILogger logger);

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Warning,
        Message = "Sign-in: NONE. Local trial mode is serving every address because "
                + "Auth:AllowLocalModeRemotely is set. Anyone who can reach this port can "
                + "read every customer's mail data.")]
    public static partial void SignInNoneRemote(ILogger logger);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Warning,
        Message = "Sign-in: NONE (local trial mode). Only this machine can reach it.")]
    public static partial void SignInNoneLocal(ILogger logger);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Information, Message = "Database: {Path}")]
    public static partial void Database(ILogger logger, string path);
}
