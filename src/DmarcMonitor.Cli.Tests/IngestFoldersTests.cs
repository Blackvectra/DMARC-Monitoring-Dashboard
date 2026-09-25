using DmarcMonitor.Cli.Commands;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// Which folders <c>dmarc ingest</c> is told to read.
///
/// It read Inbox and the folders inside it, and nothing could change that.
/// The mailbox it was built for has Outlook rules filing most of its reports
/// into folders beside Inbox, named like <c>DMARC\example.org</c> with a
/// literal backslash, so most of its reports were never collected.
/// </summary>
public sealed class IngestFoldersTests
{
    [Fact]
    public void NothingNamedLeavesTheDefault()
    {
        Assert.Empty(IngestCommand.SourceFolders([], null));
        Assert.Empty(IngestCommand.SourceFolders([], ""));

        // An environment file with the line and no value means "not set", as
        // it does for every other variable the collector reads.
        Assert.Empty(IngestCommand.SourceFolders([], "  ;  "));
    }

    [Fact]
    public void EachFolderFlagIsOneNameWithItsBackslashIntact()
    {
        Assert.Equal(
            [@"DMARC\example.org", @"DMARC\example.net"],
            IngestCommand.SourceFolders(["--folder", @"DMARC\example.org", "--folder", @"DMARC\example.net"], null));
    }

    [Fact]
    public void TheEnvironmentListIsSplitOnSemicolons()
    {
        Assert.Equal(
            [@"DMARC\example.org", @"DMARC\example.net", "Inbox"],
            IngestCommand.SourceFolders([], @" DMARC\example.org ;DMARC\example.net; Inbox ;"));
    }

    [Fact]
    public void ACommaIsPartOfAName()
    {
        // Which is why the list is split on semicolons: a comma is an ordinary
        // thing to put in a folder name.
        Assert.Equal(["Reports, 2026"], IngestCommand.SourceFolders([], "Reports, 2026"));
    }

    [Fact]
    public void FoldersOnTheCommandLineWinOverTheEnvironment()
    {
        Assert.Equal(["Inbox"], IngestCommand.SourceFolders(["--folder", "Inbox"], @"DMARC\example.org"));
    }

    [Fact]
    public async Task TheCommandTakesTheFlagMoreThanOnce()
    {
        // Every other flag is refused when it is repeated; this one exists to
        // be. It gets as far as asking for the rest of its configuration.
        var previous = Console.Error;
        using var error = new StringWriter();

        try
        {
            Console.SetError(error);
            var code = await IngestCommand.RunAsync(
                ["--folder", @"DMARC\example.org", "--folder", @"DMARC\example.net"], CancellationToken.None);

            Assert.Equal(64, code);
        }
        finally
        {
            Console.SetError(previous);
        }

        Assert.DoesNotContain("more than once", error.ToString(), StringComparison.Ordinal);
        Assert.Contains("Missing configuration", error.ToString(), StringComparison.Ordinal);
    }
}
