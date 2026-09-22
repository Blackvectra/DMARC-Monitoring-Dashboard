using DmarcMonitor.Core.Dns;
using Xunit;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// The two indicators that are about transport rather than authentication.
///
/// They answer a question SPF, DKIM and DMARC cannot: those three say whether
/// a message was really from the domain, and these say whether it crossed the
/// internet where nobody could read it. A domain at p=reject with flawless
/// alignment still hands every message to a receiver in plain text if nothing
/// requires TLS.
///
/// MTA-STS is the one place in this product where DNS does not hold the
/// answer. The TXT record at _mta-sts announces a policy id; the mode - the
/// part that decides whether anything is required of senders - is in a file
/// served over HTTPS. So there are four states worth telling apart and three
/// of them look like "there is a record": announced and enforcing, announced
/// and in testing, announced and not served at all, and announced with nobody
/// having fetched it. Most of these tests are about not collapsing them.
/// </summary>
public sealed class TransportChipTests
{
    private static DomainDns Read(
        string? mtaSts = null, string mode = "", string? tlsRpt = null,
        DateTimeOffset? checkedAt = null) =>
        new()
        {
            Domain = "example.com",
            Status = DnsCheckStatus.Ok,
            CheckedAt = checkedAt ?? DateTimeOffset.UtcNow,
            CapturedAt = DateTimeOffset.UtcNow.AddDays(-40),
            MtaStsRecord = mtaSts,
            MtaStsMode = mode,
            TlsRptRecord = tlsRpt,
        };

    [Fact]
    public void BothChipsAreOnTheRow()
    {
        var labels = RecordStatus.For(Read()).Select(c => c.Label).ToList();

        Assert.Equal(["SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT"], labels);
    }

    // ---- MTA-STS -----------------------------------------------------------

    [Fact]
    public void NoRecordIsAnAbsenceAndSaysWhatItCosts()
    {
        var chip = RecordStatus.MtaSts(Read());

        Assert.Equal(RecordState.Missing, chip.State);
        Assert.Contains("_mta-sts.example.com", chip.Detail, StringComparison.Ordinal);
        Assert.Contains("plain text", chip.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// The trap this chip exists for.
    /// </summary>
    /// <remarks>
    /// A policy in testing has its failures reported and its mail delivered
    /// over plain text anyway. A domain can sit in it for years producing
    /// perfectly clean reports while being no better protected than one with
    /// no policy at all, so a tick here would be the product telling somebody
    /// they were safe when nothing was stopping a downgrade.
    /// </remarks>
    [Fact]
    public void TestingIsNotProtection()
    {
        var chip = RecordStatus.MtaSts(Read("v=STSv1; id=20260101", MtaStsMode.Testing));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.NotEqual("✓", chip.Glyph);
        Assert.Contains("enforces nothing", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void EnforceIsTheOnlyModeThatEarnsATick()
    {
        var chip = RecordStatus.MtaSts(Read("v=STSv1; id=20260101", MtaStsMode.Enforce));

        Assert.Equal(RecordState.Ok, chip.State);
        Assert.Equal("✓", chip.Glyph);
    }

    [Fact]
    public void NoneIsAPolicySwitchedOff()
    {
        var chip = RecordStatus.MtaSts(Read("v=STSv1; id=20260101", MtaStsMode.None));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("switched off", chip.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Announced and not served: a job somebody started and stopped. The
    /// record claims a policy exists, no sender can fetch it, so none of them
    /// applies it.
    /// </summary>
    [Fact]
    public void AnnouncedAndNotServedIsItsOwnState()
    {
        var chip = RecordStatus.MtaSts(Read("v=STSv1; id=20260101", "unreachable"));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("could not be fetched", chip.Detail, StringComparison.Ordinal);
        Assert.Contains("protects nothing", chip.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nobody having fetched the file is not a fault and must not look like
    /// one. The mode is not in DNS at all, so a reading taken by something
    /// that makes no HTTPS requests never knew it - which is a different thing
    /// from a domain that is doing nothing.
    /// </summary>
    [Fact]
    public void ARecordNobodyHasFetchedThePolicyForIsUnknown()
    {
        var chip = RecordStatus.MtaSts(Read("v=STSv1; id=20260101"));

        Assert.Equal(RecordState.Unknown, chip.State);
        Assert.NotEqual("✗", chip.Glyph);
        Assert.Contains("has not been fetched", chip.Detail, StringComparison.Ordinal);

        // What to do, not what to type. These sentences are tooltips on a
        // page that has a "Read DNS now" button on it.
        Assert.Contains("Reading this domain's DNS again", chip.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("dmarc ", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedLookupNeverBecomesAMissingPolicy()
    {
        var failed = new DomainDns
        {
            Domain = "example.com",
            Status = DnsCheckStatus.Failed,
            CheckedAt = DateTimeOffset.UtcNow,
        };

        foreach (var chip in new[] { RecordStatus.MtaSts(failed), RecordStatus.TlsRpt(failed) })
        {
            Assert.Equal(RecordState.Unreadable, chip.State);
            Assert.Contains("not the same as having no", chip.Detail, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ModeIsReadWithoutRegardToCase()
    {
        Assert.Equal(
            RecordState.Ok,
            RecordStatus.MtaSts(Read("v=STSv1; id=1", "ENFORCE")).State);
    }

    // ---- TLS-RPT -----------------------------------------------------------

    [Fact]
    public void NoTlsReportingIsAnAbsence()
    {
        var chip = RecordStatus.TlsRpt(Read());

        Assert.Equal(RecordState.Missing, chip.State);
        Assert.Contains("_smtp._tls.example.com", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void WhereTheReportsGoIsStatedRatherThanJudged()
    {
        // Pointed at another provider entirely, which is a deliberate
        // arrangement and not a fault - and does mean this product will never
        // see those reports. Saying where they go beats a week of wondering
        // why the TLS reports page is empty.
        var chip = RecordStatus.TlsRpt(
            Read(tlsRpt: "v=TLSRPTv1; rua=mailto:tls@tls.us.dmarcian.com"));

        Assert.Equal(RecordState.Ok, chip.State);
        Assert.Contains("tls@tls.us.dmarcian.com", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ARecordThatNamesNowhereToReportToIsWeak()
    {
        var chip = RecordStatus.TlsRpt(Read(tlsRpt: "v=TLSRPTv1;"));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("no rua=", chip.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// RFC 8460 §3 allows a list of endpoints. The first is named and the rest
    /// counted, rather than a second endpoint grammar being written here to
    /// fill a tooltip.
    /// </summary>
    [Fact]
    public void SeveralDestinationsAreCountedRatherThanListed()
    {
        var chip = RecordStatus.TlsRpt(
            Read(tlsRpt: "v=TLSRPTv1; rua=mailto:a@example.com,mailto:b@example.net,https://example.org/r"));

        Assert.Contains("a@example.com and 2 more", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AnHttpsEndpointIsShownAsItself()
    {
        var chip = RecordStatus.TlsRpt(Read(tlsRpt: "v=TLSRPTv1; rua=https://example.org/report"));

        Assert.Equal(RecordState.Ok, chip.State);
        Assert.Contains("https://example.org/report", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOldReadingIsFadedRatherThanRestated()
    {
        var old = Read(
            tlsRpt: "v=TLSRPTv1; rua=mailto:tls@example.com",
            checkedAt: DateTimeOffset.UtcNow.AddDays(-RecordStatus.StaleAfterDays - 1));

        var chip = RecordStatus.TlsRpt(old);

        Assert.True(chip.Stale);
        Assert.Equal(RecordState.Ok, chip.State);
        Assert.Contains("days ago", chip.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void NeitherChipTakesANullReading()
    {
        Assert.Throws<ArgumentNullException>(() => RecordStatus.MtaSts(null!));
        Assert.Throws<ArgumentNullException>(() => RecordStatus.TlsRpt(null!));
    }
}
