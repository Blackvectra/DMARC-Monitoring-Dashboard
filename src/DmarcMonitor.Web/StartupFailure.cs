using System.Globalization;
using System.Text;
using DmarcMonitor.Core.Platform;
using Microsoft.AspNetCore.Connections;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Web;

/// <summary>
/// What a person sees when the application cannot start.
///
/// On a server this never mattered much: systemd keeps the output, the unit
/// reports failed, and whoever installed it knows to run journalctl. On a
/// desktop it mattered completely. The window is created by Explorer, owned
/// by this process, and destroyed the moment it exits - so an unhandled
/// exception at startup is a flash and nothing else. No message, no log, no
/// exit code anybody can see. "It does not open" is all that can honestly be
/// reported, and it is not enough to act on.
///
/// So a startup failure now does three things it did not do: says what went
/// wrong in a sentence somebody can act on, writes it to a file that outlives
/// the window, and holds the window open long enough to be read.
/// </summary>
internal static class StartupFailure
{
    /// <summary>The conventional exit code for "the software could not start".</summary>
    private const int ExitInternalSoftwareError = 70;

    /// <summary>
    /// Reports <paramref name="ex"/> to whoever is watching and returns the
    /// exit code the process should end with.
    /// </summary>
    /// <param name="ex">The failure.</param>
    /// <param name="directory">
    /// Where to leave the log. Normally the folder holding the database, which
    /// is the one place this application is known to be able to write.
    /// </param>
    public static int Report(Exception ex, string directory)
    {
        ArgumentNullException.ThrowIfNull(ex);

        var console = Console.Error;
        console.WriteLine();
        console.WriteLine("DMARC Monitor could not start.");
        console.WriteLine();
        console.WriteLine(Explain(ex));
        console.WriteLine();

        var log = TryWriteLog(directory, ex);
        if (log is not null)
        {
            console.WriteLine($"The full detail is in: {log}");
        }
        else
        {
            // Could not write the log either, which is itself a strong hint
            // about the folder - so print what would have been in it.
            console.WriteLine("Full detail:");
            console.WriteLine(ex.ToString());
        }

        ConsoleWindow.HoldOpen("Press any key to close this window.");
        return ExitInternalSoftwareError;
    }

    /// <summary>
    /// Turns the exception into the sentence a person needs, or admits that
    /// it cannot.
    /// </summary>
    /// <remarks>
    /// Only the failures that actually happen to somebody running this on
    /// their own machine are translated. Inventing friendly text for a
    /// failure nobody has had produces confident wrong advice, so anything
    /// unrecognised is reported as itself.
    /// </remarks>
    private static string Explain(Exception ex)
    {
        foreach (var cause in Chain(ex))
        {
            switch (cause)
            {
                // The common one by a distance. Port 5000 is a popular default
                // and an IT person's machine often already has something on it.
                case AddressInUseException:
                    return """
                        Another program on this computer is already using the port this
                        needs.

                        Either close that program, or start this one on a different port:

                            set ASPNETCORE_URLS=http://localhost:5050
                            DmarcMonitor.Web.exe

                        and then open http://localhost:5050 yourself.
                        """;

                case UnauthorizedAccessException:
                    return """
                        This folder cannot be written to, and the application keeps its
                        database here.

                        Move the whole folder somewhere that belongs to you - your
                        Desktop or Documents - and run it again. Program Files and the
                        inside of a .zip file are both read-only.
                        """;

                case SqliteException sqlite:
                    return string.Create(
                        CultureInfo.InvariantCulture,
                        $"""
                        The database could not be opened.

                        SQLite reported: {sqlite.Message}

                        If dmarc.db in this folder was copied from elsewhere, or a
                        previous run was interrupted, moving it aside and starting
                        again will build a fresh one.
                        """);
            }
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"""
            {ex.GetType().Name}: {ex.Message}

            This one is not a failure the application knows how to explain, which
            makes it worth reporting.
            """);
    }

    private static IEnumerable<Exception> Chain(Exception ex)
    {
        // Kestrel wraps the interesting failure: a port clash arrives as an
        // IOException whose message is about binding, with the exception that
        // actually says what happened underneath it.
        for (var current = ex; current is not null; current = current.InnerException)
        {
            yield return current;

            if (current is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                {
                    foreach (var nested in Chain(inner)) { yield return nested; }
                }
            }
        }
    }

    /// <summary>
    /// Writes the detail beside the database, or to the temporary directory if
    /// that fails, or gives up.
    /// </summary>
    /// <returns>The file written, or null.</returns>
    private static string? TryWriteLog(string directory, Exception ex)
    {
        var body = new StringBuilder()
            .AppendLine(CultureInfo.InvariantCulture, $"DMARC Monitor {Core.Updates.BuildInfo.Version}")
            .AppendLine(CultureInfo.InvariantCulture, $"Failed to start at {DateTimeOffset.Now:u}")
            .AppendLine(CultureInfo.InvariantCulture, $"Executable: {AppContext.BaseDirectory}")
            .AppendLine()
            .AppendLine(ex.ToString())
            .ToString();

        foreach (var candidate in Candidates(directory))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(candidate)!);
                File.WriteAllText(candidate, body);
                return candidate;
            }
            catch (Exception write) when (write is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                // Try the next place. A failure to log must never replace the
                // failure being logged.
            }
        }

        return null;
    }

    private static IEnumerable<string> Candidates(string directory)
    {
        if (!string.IsNullOrWhiteSpace(directory))
        {
            yield return Path.Combine(directory, "startup-error.log");
        }

        yield return Path.Combine(Path.GetTempPath(), "dmarc-startup-error.log");
    }
}
