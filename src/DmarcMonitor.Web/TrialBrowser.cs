using System.Diagnostics;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace DmarcMonitor.Web;

/// <summary>
/// Opens the dashboard for somebody who double-clicked the application.
///
/// The Windows trial download is one folder with one executable in it, and
/// without this the whole of it is a console window and an address to type
/// correctly. That is a small thing that decides whether somebody sees the
/// product at all.
///
/// It is deliberately the narrowest case that can be described, because every
/// other way this application starts is one where opening a browser would be
/// wrong or absurd:
///
///   - as a Windows service (deploy/bootstrap.ps1), where there is no desktop
///     to open anything on and the account is not a person;
///   - under systemd on a server, same;
///   - with sign-in configured, which means it is a deployment somebody set up
///     rather than a copy somebody is trying;
///   - on a restart, where the person already has the tab open.
///
/// So: Windows only, not a service, local trial mode only, and DMARC_NO_BROWSER
/// switches it off for anyone who wants it off.
/// </summary>
internal static class TrialBrowser
{
    /// <summary>Whether this launch is the one a browser should be opened for.</summary>
    public static bool ShouldOpen(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (!OperatingSystem.IsWindows()) { return false; }
        if (WindowsServiceHelpers.IsWindowsService()) { return false; }
        if (!Environment.UserInteractive) { return false; }

        // A configured deployment, not a trial. Both of these mean somebody
        // has been through setup, and neither wants a browser window on the
        // server console.
        if (Auth.AuthSetup.IsEntraConfigured(configuration)) { return false; }
        if (Auth.AuthSetup.LocalModeAllowedRemotely(configuration)) { return false; }

        return !IsSet("DMARC_NO_BROWSER");
    }

    /// <summary>
    /// Opens the default browser at <paramref name="address"/>, and does not
    /// care if it cannot.
    /// </summary>
    /// <remarks>
    /// Never throws. The application has started and is serving by this point;
    /// failing to launch a browser is a convenience that did not happen, and
    /// bringing the process down over it would turn a working install into a
    /// crash at the last line.
    /// </remarks>
    public static void Open(string address, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        try
        {
            // UseShellExecute is what hands the URL to whatever the user has
            // set as their browser. Without it this tries to execute the URL
            // as a program and fails.
            using var _ = Process.Start(new ProcessStartInfo(address) { UseShellExecute = true });
            TrialBrowserLog.Opened(logger, address);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TrialBrowserLog.CouldNotOpen(logger, address, ex);
        }
    }

    private static bool IsSet(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return !string.IsNullOrWhiteSpace(value)
            && !value.Equals("0", StringComparison.Ordinal)
            && !value.Equals("false", StringComparison.OrdinalIgnoreCase);
    }
}

internal static partial class TrialBrowserLog
{
    [LoggerMessage(EventId = 1020, Level = LogLevel.Information, Message = "Opened {Address} in your browser.")]
    public static partial void Opened(ILogger logger, string address);

    [LoggerMessage(
        EventId = 1021,
        Level = LogLevel.Information,
        Message = "Could not open a browser. Go to {Address}.")]
    public static partial void CouldNotOpen(ILogger logger, string address, Exception exception);
}
