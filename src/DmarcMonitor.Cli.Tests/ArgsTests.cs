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
    public void AFlagAtTheEndWithNoValueIsStillRecognised()
    {
        // "dmarc report --client" is wrong, but it is wrong in the way the
        // command's own usage text explains. It must not be reported as an
        // unknown option, which would send somebody looking for a typo that
        // is not there.
        Assert.Equal(0, Args.Reject(["--client"], "--client", "--db"));
    }
}
