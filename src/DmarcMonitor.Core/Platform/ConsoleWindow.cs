using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DmarcMonitor.Core.Platform;

/// <summary>
/// Whether this process is the only thing attached to its console window -
/// which is to say, whether somebody double-clicked it in Explorer.
///
/// This exists because of a bug report that read: "the app appears like it
/// opens then just closes with a shadow". Nothing had crashed. dmarc.exe had
/// been double-clicked, had printed its help to a console it owned, had
/// exited as it should, and Windows had destroyed the window with the text
/// still in it. A console application that does its job and a console
/// application that dies on its first line are the same half-second flash,
/// and the person watching cannot tell them apart.
///
/// The distinction that matters is not "is there a console" - there always
/// is - but "will this window survive the process". A console started by
/// Explorer belongs to this process and goes when it goes. A console that was
/// already open - cmd, PowerShell, Windows Terminal - belongs to the shell and
/// stays, and pausing in one of those would be an unwanted keystroke in the
/// middle of somebody's script.
/// </summary>
public static class ConsoleWindow
{
    /// <summary>
    /// True when this process owns its console window outright, so anything
    /// written to it is lost the instant the process exits.
    /// </summary>
    /// <remarks>
    /// False everywhere that is not an interactive Windows desktop: Linux,
    /// a Windows service, a redirected or detached console. The caller can
    /// treat a false as "somebody or something else is reading this output",
    /// which is the safe assumption.
    /// </remarks>
    public static bool BelongsToThisProcess()
    {
        if (!OperatingSystem.IsWindows()) { return false; }
        if (!Environment.UserInteractive) { return false; }

        try
        {
            return AttachedProcessCount() == 1;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Not a Windows this runs on. Treating it as somebody else's
            // console only costs a pause that does not happen.
            return false;
        }
    }

    /// <summary>
    /// Holds a console window that is about to be destroyed open until a key
    /// is pressed, so whatever was printed can be read.
    /// </summary>
    /// <remarks>
    /// Does nothing at all unless this process owns the window, so it is safe
    /// to call unconditionally at the end of a command. Never blocks a script,
    /// a pipeline, a service or CI: each of those fails
    /// <see cref="BelongsToThisProcess"/> or has redirected input.
    /// </remarks>
    public static void HoldOpen(string prompt = "Press any key to close this window.")
    {
        if (!BelongsToThisProcess()) { return; }

        // A console can be owned by this process and still have its input
        // redirected - Start-Process -RedirectStandardInput does exactly that,
        // and ReadKey throws InvalidOperationException on one. There is also
        // nobody at the keyboard in that case, so there is nothing to wait for.
        if (Console.IsInputRedirected) { return; }

        Console.WriteLine();
        Console.WriteLine(prompt);

        try
        {
            Console.ReadKey(intercept: true);
        }
        catch (InvalidOperationException)
        {
            // No console input handle after all. The window was going to
            // close; it closes.
        }
    }

    [SupportedOSPlatform("windows")]
    private static uint AttachedProcessCount()
    {
        // The buffer only has to be big enough to count to two. When there is
        // not room for every process the call returns the number required
        // rather than failing, which is all this needs to know - and zero
        // means there is no console attached at all.
        var processes = new uint[2];
        return GetConsoleProcessList(processes, (uint)processes.Length);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList(uint[] processList, uint processCount);
}
