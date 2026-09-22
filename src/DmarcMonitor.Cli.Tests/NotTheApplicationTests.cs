using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// What somebody is told when they double-click dmarc.exe looking for the
/// dashboard.
///
/// They do, because in the Windows download it sits directly above
/// DmarcMonitor.Web.exe in Explorer's alphabetical order, it is 36 MB, and it
/// is named after the product. What it did was print a screen of usage text
/// into a window Windows destroyed in the same instant - reported, accurately,
/// as "the app appears like it opens then just closes with a shadow".
///
/// Whether the banner appears is decided by ConsoleWindow and cannot be
/// exercised from a test runner, which never owns its console. What it says
/// when it does appear is exactly what is being fixed, so that is asserted
/// here.
/// </summary>
public sealed class NotTheApplicationTests
{
    [Fact]
    public void SaysWhichProgramThisIsBeforeSayingWhatItDoes()
    {
        var text = Capture();

        Assert.Contains("not the dashboard", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// The whole point: leaving with the name of the file to open next.
    /// </summary>
    [Fact]
    public void NamesTheExecutableToOpenInstead()
    {
        var text = Capture();

        Assert.Contains("DmarcMonitor.Web.exe", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A test run has no DmarcMonitor.Web.exe beside it, which is also the
    /// case for a dmarc.exe downloaded on its own from the releases page. It
    /// must not tell that person to open a file that is not there - so it
    /// sends them back to the download instead.
    /// </summary>
    [Fact]
    public void DoesNotPointAtAFileThatIsNotThere()
    {
        Assert.False(
            File.Exists(Path.Combine(AppContext.BaseDirectory, "DmarcMonitor.Web.exe")),
            "this test asserts the behaviour for a lone dmarc.exe; the web executable is unexpectedly present");

        var text = Capture();

        Assert.Contains("separate download", text, StringComparison.Ordinal);
        Assert.DoesNotContain("in this same folder", text, StringComparison.OrdinalIgnoreCase);
    }

    private static string Capture()
    {
        var previous = Console.Out;
        using var captured = new StringWriter();

        try
        {
            Console.SetOut(captured);
            Program.NotTheApplication();
        }
        finally
        {
            Console.SetOut(previous);
        }

        return captured.ToString();
    }
}
