using DmarcMonitor.Cli.Commands;
using DmarcMonitor.Core.Dns;
using Xunit;

namespace DmarcMonitor.Cli.Tests;

/// <summary>
/// The line <c>dmarc check --save</c> prints under each domain.
///
/// These are about the reason, not the wording. "No DKIM selector seen
/// signing" is a claim about what the reports contain; printed because the
/// lookup timed out, it is a fact nobody read. That is the same error as
/// drawing a cross for a record that was never fetched, and the whole point
/// of this feature is not to make it.
/// </summary>
public sealed class SaveNoteTests
{
    private static ScanResult Result(
        DnsCheckStatus status = DnsCheckStatus.Ok, bool stored = true,
        bool changed = false, int selectors = 0) =>
        new("example.com", status, stored, changed, selectors);

    [Fact]
    public void ALookupThatFailedNeverClaimsTheReportsShowedNoSelector()
    {
        var note = CheckCommand.SaveNote(Result(DnsCheckStatus.Failed));

        Assert.Contains("could not be read", note, StringComparison.Ordinal);
        Assert.DoesNotContain("seen signing", note, StringComparison.Ordinal);
    }

    [Fact]
    public void ANameThatDoesNotExistSaysThatRatherThanCountingSelectors()
    {
        var note = CheckCommand.SaveNote(Result(DnsCheckStatus.NoSuchDomain));

        Assert.Contains("does not exist", note, StringComparison.Ordinal);
        Assert.DoesNotContain("seen signing", note, StringComparison.Ordinal);
    }

    [Fact]
    public void AReadDomainWithNoSelectorSaysWhyThereWasNothingToCheck()
    {
        var note = CheckCommand.SaveNote(Result(selectors: 0));

        Assert.Contains("no DKIM selector seen signing", note, StringComparison.Ordinal);
    }

    [Fact]
    public void SelectorsCheckedAreCounted()
    {
        Assert.Contains("3 DKIM selector(s) checked",
            CheckCommand.SaveNote(Result(selectors: 3)), StringComparison.Ordinal);
    }

    [Fact]
    public void AChangedRecordIsCalledOutBesideTheCount()
    {
        Assert.Contains("records changed since the last reading",
            CheckCommand.SaveNote(Result(selectors: 1, changed: true)), StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnchangedRecordSaysNothingAboutChanging()
    {
        Assert.DoesNotContain("changed",
            CheckCommand.SaveNote(Result(selectors: 1)), StringComparison.Ordinal);
    }

    [Fact]
    public void ADomainNotInTheBookSaysSoRatherThanReportingAReadingThatWentNowhere()
    {
        // The prospect case. A reading with nothing to attach it to is
        // dropped, and a command that printed a selector count here would be
        // describing work it did not keep.
        var note = CheckCommand.SaveNote(Result(stored: false));

        Assert.Contains("not stored", note, StringComparison.Ordinal);
        Assert.Contains("not in the book", note, StringComparison.Ordinal);
    }

    [Fact]
    public void NotInTheBookOutranksEverythingElse()
    {
        // Whatever the lookup found, none of it was kept, and that is the
        // fact worth printing.
        var note = CheckCommand.SaveNote(Result(stored: false, selectors: 4));

        Assert.Contains("not stored", note, StringComparison.Ordinal);
        Assert.DoesNotContain("checked", note, StringComparison.Ordinal);
    }
}
