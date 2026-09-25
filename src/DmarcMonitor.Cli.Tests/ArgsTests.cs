using DmarcMonitor.Cli.Commands;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// Argument parsing, which had no tests until a mistyped flag was found to
/// change what a command did without saying anything.
///
/// This matters more here than in most tools: the flags decide whether DNS is
/// written, which month a customer's report covers, and what permanent slug a
/// client is filed under.
/// </summary>
public sealed class ArgsTests
{
    [Fact]
    public void EveryKnownFlagIsAccepted()
    {
        var code = Args.Reject(
            ["report", "--client", "acme", "--month", "2026-09", "--all", "--db", "x.db"],
            "--client", "--month", "--db", "!--all");

        Assert.Equal(0, code);
    }

    [Theory]
    [InlineData("--moth")]
    [InlineData("--months")]
    [InlineData("--period")]
    [InlineData("--nonsense")]
    public void AnUnknownFlagIsRefusedRatherThanIgnored(string flag)
    {
        // The bug this exists for. "dmarc report --client acme --moth 2026-09"
        // wrote LAST month's report and said nothing, so the operator sent a
        // customer the wrong month.
        var code = Args.Reject(["--client", "acme", flag, "2026-09"], "--client", "--month", "--db");

        Assert.Equal(64, code);
    }

    [Fact]
    public void AValueIsNotMistakenForAFlag()
    {
        // A reason is free text and a customer's own words. "--apply --reason
        // --urgent- fix" must not have "--urgent-" judged as a flag, or the
        // command refuses work that is perfectly well formed.
        var code = Args.Reject(
            ["--domain", "acme.com", "--reason", "--urgent- subdomains were left at sp=none", "--apply"],
            "--domain", "--reason", "!--apply");

        Assert.Equal(0, code);
    }

    [Fact]
    public void ASwitchDoesNotSwallowWhatFollowsIt()
    {
        // --apply takes no value, so the next argument is still judged. This
        // is the mirror of the test above and the two constrain each other:
        // get the distinction wrong and either values are rejected or typos
        // sail through.
        var code = Args.Reject(["--apply", "--nonsense"], "--domain", "!--apply");

        Assert.Equal(64, code);
    }

    [Fact]
    public void SubcommandsAndBarePathsArePassedOver()
    {
        // "dmarc client assign --domain x --client y" and "dmarc explain
        // ./report.xml": neither the verb nor the path is a flag.
        Assert.Equal(0, Args.Reject(
            ["assign", "--domain", "acme.com", "--client", "acme"], "--domain", "--client"));

        Assert.Equal(0, Args.Reject(["./some/report.xml"], "--db"));
    }

    [Fact]
    public void CaseDoesNotDecideWhetherAFlagIsKnown()
    {
        // Value() and Flag() both compare case-insensitively, so this has to
        // agree with them or --DB would be read as a database and refused as
        // unknown in the same run.
        Assert.Equal(0, Args.Reject(["--DB", "x.db"], "--db"));
    }

    [Fact]
    public void ValueAndFlagStillReadWhatTheyShould()
    {
        string[] args = ["--client", "acme", "--apply", "--max", "7"];

        Assert.Equal("acme", Args.Value(args, "--client"));
        Assert.Null(Args.Value(args, "--absent"));
        Assert.True(Args.Flag(args, "--apply"));
        Assert.False(Args.Flag(args, "--dry-run"));
        Assert.Equal(7, Args.Int(args, "--max", fallback: 500));
        Assert.Equal(500, Args.Int(args, "--absent", fallback: 500));
    }

    [Fact]
    public void AFlagAtTheEndWithNoValueIsStillRecognized()
    {
        // "dmarc report --client" is wrong, but it is wrong in the way the
        // command's own usage text explains. It must not be reported as an
        // unknown option, which would send somebody looking for a typo that
        // is not there.
        Assert.Equal(0, Args.Reject(["--client"], "--client", "--db"));
    }

    /// <summary>
    /// The command line that produced this, verbatim, from somebody pasting
    /// twice into a terminal:
    ///
    ///     dmarc import --from .\dmarc.exe import --from "C:\dmarc-export"
    ///
    /// Every flag in it is spelled correctly, so Reject passed it. Value()
    /// returns the FIRST --from, so the importer was pointed at dmarc.exe,
    /// read it, reported "files seen 1, not reports 1" and exited 0 - while
    /// the folder that was actually wanted was never opened. A successful
    /// run that did nothing is the worst available outcome, because there is
    /// nothing to notice.
    /// </summary>
    [Fact]
    public void AFlagGivenTwiceIsRefusedRatherThanSilentlyResolvedToTheFirst()
    {
        var code = Args.Reject(
            ["--from", @".\dmarc.exe", "import", "--from", @"C:\dmarc-export"],
            "--db", "--from", "--org");

        Assert.Equal(64, code);
    }

    [Fact]
    public void ARepeatedValuelessFlagIsRefusedToo()
    {
        Assert.Equal(64, Args.Reject(["--all", "--all"], "--db", "!--all"));
    }

    /// <summary>
    /// The boundary that keeps the check from being a nuisance: repetition is
    /// only repetition when it is the same flag. Two different flags, and a
    /// value that happens to equal another flag's name, are both ordinary.
    /// </summary>
    [Fact]
    public void DifferentFlagsAreNotRepetition()
    {
        Assert.Equal(0, Args.Reject(["--from", "a", "--db", "b", "--org", "c"], "--db", "--from", "--org"));
    }

    [Fact]
    public void AValueThatLooksLikeAnEarlierFlagIsNotRepetition()
    {
        // --db's value is the literal text "--from". It is a value, not a
        // second occurrence of the flag, and Reject already steps over it.
        Assert.Equal(0, Args.Reject(["--from", "reports", "--db", "--from"], "--db", "--from"));
    }

    /// <summary>
    /// The one kind of repetition that is meant: a flag the command declares
    /// repeatable, written with a trailing "..." the way its usage text is.
    /// <c>dmarc ingest --folder A --folder B</c> reads both folders.
    /// </summary>
    [Fact]
    public void AFlagDeclaredRepeatableMayBeGivenMoreThanOnce()
    {
        Assert.Equal(0, Args.Reject(
            ["--folder", @"DMARC\example.org", "--folder", @"DMARC\example.net", "--db", "x.db"],
            "--db", "--folder..."));
    }

    [Fact]
    public void DeclaringOneFlagRepeatableDoesNotExcuseAnother()
    {
        Assert.Equal(64, Args.Reject(
            ["--folder", "a", "--folder", "b", "--db", "x.db", "--db", "y.db"],
            "--db", "--folder..."));
    }

    [Fact]
    public void ARepeatableFlagIsStillOnlyItsOwnName()
    {
        // The marker is not part of the name somebody types.
        Assert.Equal(64, Args.Reject(["--folder...", "a"], "--folder..."));
        Assert.Equal(64, Args.Reject(["--folders", "a"], "--folder..."));
    }

    [Fact]
    public void ValuesReadsEveryOccurrenceInOrderAndKeepsBackslashes()
    {
        string[] args = ["--folder", @"DMARC\example.org", "--db", "x.db", "--folder", "Inbox"];

        Assert.Equal([@"DMARC\example.org", "Inbox"], Args.Values(args, "--folder"));
        Assert.Empty(Args.Values(args, "--absent"));
    }

    [Fact]
    public void ValuesDoesNotMistakeAValueForAnotherOccurrence()
    {
        // A folder literally named "--folder" is somebody's, however unlikely.
        Assert.Equal(["--folder", "Inbox"], Args.Values(["--folder", "--folder", "--folder", "Inbox"], "--folder"));
    }
}
