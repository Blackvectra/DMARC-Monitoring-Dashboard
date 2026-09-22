using DmarcMonitor.Core.Dns;
using Xunit;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// What the record indicators on the domains table are allowed to say.
///
/// Most of these are about the cases where the honest answer is "I do not
/// know". A cross is a claim - the resolver answered and there was no record -
/// and an operator acts on it by publishing one. Drawn for a domain nobody
/// has read yet, or for one whose lookup timed out, it sends somebody to
/// publish a second DMARC record over the top of a working first, which is
/// the failure this whole product is built to avoid.
/// </summary>
public sealed class RecordStatusTests
{
    private static DomainDns Read(
        string? spf = null, string? dmarc = null, int spfCount = -1, int? lookups = 0,
        string all = "-all", IReadOnlyList<ObservedSelector>? selectors = null,
        DateTimeOffset? checkedAt = null) =>
        new()
        {
            Domain = "example.com",
            Status = DnsCheckStatus.Ok,
            CheckedAt = checkedAt ?? DateTimeOffset.UtcNow,
            CapturedAt = DateTimeOffset.UtcNow.AddDays(-40),
            SpfRecord = spf,
            SpfRecordCount = spfCount >= 0 ? spfCount : spf is null ? 0 : 1,
            SpfLookups = lookups,
            SpfAll = spf is null ? "" : all,
            DmarcRecord = dmarc,
            DkimSelectors = selectors ?? [],
        };

    [Fact]
    public void NothingIsACrossUntilSomebodyHasLooked()
    {
        var never = new DomainDns { Domain = "example.com" };

        foreach (var chip in RecordStatus.For(never))
        {
            Assert.Equal(RecordState.Unknown, chip.State);
            Assert.Contains("has not been read yet", chip.Detail, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void AFailedLookupIsNotAnAbsentRecord()
    {
        // The rule the rest of the codebase already holds to, held to here as
        // well. A timeout and a domain with no records return the same empty
        // answer, and telling them apart is the difference between "publish
        // this" and "try again".
        var failed = new DomainDns
        {
            Domain = "example.com",
            Status = DnsCheckStatus.Failed,
            CheckedAt = DateTimeOffset.UtcNow,
        };

        foreach (var chip in RecordStatus.For(failed))
        {
            Assert.Equal(RecordState.Unreadable, chip.State);
            Assert.DoesNotContain("No ", chip.Detail, StringComparison.Ordinal);
            Assert.Contains("not the same as having no", chip.Detail, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ADomainThatDoesNotExistSaysSoRatherThanListingWhatToPublish()
    {
        var gone = new DomainDns
        {
            Domain = "exmaple.com",
            Status = DnsCheckStatus.NoSuchDomain,
            CheckedAt = DateTimeOffset.UtcNow,
        };

        var chip = RecordStatus.Dmarc(gone);

        Assert.Equal(RecordState.Missing, chip.State);
        Assert.Contains("no domain called exmaple.com", chip.Detail, StringComparison.Ordinal);
        Assert.Contains("typo", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AReadingOlderThanAWeekIsMarkedStaleWithoutLosingWhatItFound()
    {
        var old = Read(spf: "v=spf1 -all", checkedAt: DateTimeOffset.UtcNow.AddDays(-30));
        var chip = RecordStatus.Spf(old);

        // Still the answer it found: an old reading is the best information
        // there is, it just is not news. Blanking it would replace something
        // true with nothing.
        Assert.Equal(RecordState.Ok, chip.State);
        Assert.True(chip.Stale);
    }

    [Fact]
    public void AFreshReadingIsNotStale()
    {
        Assert.False(RecordStatus.Spf(Read(spf: "v=spf1 -all")).Stale);
    }

    // ---- DMARC ------------------------------------------------------------

    [Fact]
    public void NoDmarcRecordIsMissing()
    {
        var chip = RecordStatus.Dmarc(Read());

        Assert.Equal(RecordState.Missing, chip.State);
        Assert.Contains("_dmarc.example.com", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ADmarcRecordWithNoRuaIsWeakBecauseNobodySeesAnything()
    {
        var chip = RecordStatus.Dmarc(Read(dmarc: "v=DMARC1; p=reject"));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("no rua=", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyNoneIsNotAFaultOfTheRecord()
    {
        // The policy column shows p=none and the triage pip ranks how long the
        // domain has sat at it. Warning here as well would be the same thing
        // said three times in one row, and the row has other things to say.
        var chip = RecordStatus.Dmarc(Read(dmarc: "v=DMARC1; p=none; rua=mailto:d@example.net"));

        Assert.Equal(RecordState.Ok, chip.State);
    }

    [Fact]
    public void SomethingElseAtTheDmarcNameIsWeakRatherThanMissing()
    {
        // There IS a record there. Reporting it as absent would have somebody
        // publish beside it rather than look at what is already published.
        var chip = RecordStatus.Dmarc(Read(dmarc: "google-site-verification=abc123"));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("not usable DMARC", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void APartialRolloutIsReportedAsWhatItIs()
    {
        var chip = RecordStatus.Dmarc(Read(dmarc: "v=DMARC1; p=reject; pct=25; rua=mailto:d@example.net"));

        Assert.Equal(RecordState.Ok, chip.State);
        Assert.Contains("25% of mail", chip.Detail, StringComparison.Ordinal);
    }

    // ---- SPF --------------------------------------------------------------

    [Fact]
    public void NoSpfRecordIsMissing()
    {
        Assert.Equal(RecordState.Missing, RecordStatus.Spf(Read()).State);
    }

    [Fact]
    public void TwoSpfRecordsAreAFaultEvenThoughBothLookCorrect()
    {
        var chip = RecordStatus.Spf(Read(spf: "v=spf1 -all", spfCount: 2));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("permerror", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void OverTheLookupLimitIsWeak()
    {
        var chip = RecordStatus.Spf(Read(spf: "v=spf1 -all", lookups: DnsHygiene.SpfLookupLimit + 1));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("permerror", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ExactlyTheLookupLimitIsStillFine()
    {
        // The limit is what is allowed, not what is forbidden. Off by one here
        // would have somebody rewrite a record that works.
        var chip = RecordStatus.Spf(Read(spf: "v=spf1 -all", lookups: DnsHygiene.SpfLookupLimit));

        Assert.Equal(RecordState.Ok, chip.State);
    }

    [Theory]
    [InlineData("+all")]
    [InlineData("all")]
    [InlineData("?all")]
    public void ARecordThatProtectsNothingIsWeak(string all)
    {
        Assert.Equal(RecordState.Weak, RecordStatus.Spf(Read(spf: "v=spf1 " + all, all: all)).State);
    }

    [Fact]
    public void AMissingAllMechanismIsWeakBecauseItDefaultsToNeutral()
    {
        var dns = Read(spf: "v=spf1 include:example.net") with { SpfAll = "" };
        var chip = RecordStatus.Spf(dns);

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("?all", chip.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("-all")]
    [InlineData("~all")]
    public void AnEnforcingOrSoftFailRecordIsFine(string all)
    {
        Assert.Equal(RecordState.Ok, RecordStatus.Spf(Read(spf: "v=spf1 " + all, all: all)).State);
    }

    // ---- DKIM -------------------------------------------------------------

    [Fact]
    public void NoSelectorSeenMeansUnknownRatherThanMissing()
    {
        // A domain can sign everything perfectly and simply have sent nothing
        // this month. DNS offers no way to ask which selectors exist, so
        // "none observed" is the absence of evidence and nothing more.
        var chip = RecordStatus.Dkim(Read(spf: "v=spf1 -all"));

        Assert.Equal(RecordState.Unknown, chip.State);
        Assert.Contains("cannot be asked which selectors", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void SelectorsThatSignedButNoLongerResolveAreMissing()
    {
        var chip = RecordStatus.Dkim(Read(selectors:
        [
            new ObservedSelector("s1", "invalid", null, DateTimeOffset.UtcNow),
            new ObservedSelector("s2", "invalid", null, DateTimeOffset.UtcNow),
        ]));

        Assert.Equal(RecordState.Missing, chip.State);
        Assert.Contains("s1, s2", chip.Detail, StringComparison.Ordinal);
        Assert.Contains("fails DKIM", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void OneSelectorOfSeveralNotResolvingIsWeak()
    {
        var chip = RecordStatus.Dkim(Read(selectors:
        [
            new ObservedSelector("good", "strong", 2048, DateTimeOffset.UtcNow),
            new ObservedSelector("gone", "invalid", null, DateTimeOffset.UtcNow),
        ]));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("gone", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ARevokedSelectorStillSigningIsWeak()
    {
        var chip = RecordStatus.Dkim(Read(selectors:
        [
            new ObservedSelector("live", "strong", 2048, DateTimeOffset.UtcNow),
            new ObservedSelector("old", "revoked", null, DateTimeOffset.UtcNow),
        ]));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("revoked", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AShortKeyIsWeak()
    {
        var chip = RecordStatus.Dkim(Read(selectors:
            [new ObservedSelector("s", "weak", 512, DateTimeOffset.UtcNow)]));

        Assert.Equal(RecordState.Weak, chip.State);
        Assert.Contains("1024", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void EverySelectorResolvingIsFineAndSaysTheSmallestKey()
    {
        var chip = RecordStatus.Dkim(Read(selectors:
        [
            new ObservedSelector("a", "strong", 2048, DateTimeOffset.UtcNow),
            new ObservedSelector("b", "acceptable", 1024, DateTimeOffset.UtcNow),
        ]));

        Assert.Equal(RecordState.Ok, chip.State);
        Assert.Contains("smallest 1024 bits", chip.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ALongListOfSelectorsIsSummarizedRatherThanPrintedWhole()
    {
        var many = Enumerable.Range(1, 9)
            .Select(i => new ObservedSelector($"s{i}", "invalid", null, DateTimeOffset.UtcNow))
            .ToList();

        var chip = RecordStatus.Dkim(Read(selectors: many));

        Assert.Contains("and 6 more", chip.Detail, StringComparison.Ordinal);
    }

    // ---- what gets drawn --------------------------------------------------

    [Fact]
    public void EveryStateHasItsOwnShapeAndNotOnlyItsOwnColor()
    {
        // Roughly one man in twelve cannot tell the red one from the green
        // one. A column eighty rows deep separated by hue alone is a column
        // that person cannot read.
        var glyphs = new[]
        {
            RecordState.Ok, RecordState.Weak, RecordState.Missing,
            RecordState.Unreadable, RecordState.Unknown,
        }
        .Select(s => new RecordChip("SPF", s, "").Glyph)
        .ToList();

        Assert.Equal(glyphs.Count, glyphs.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void TheTitleCarriesHowOldTheReadingIs()
    {
        var chip = RecordStatus.Spf(Read(spf: "v=spf1 -all", checkedAt: DateTimeOffset.UtcNow.AddDays(-3)));

        Assert.Contains("Last read 3 days ago.", chip.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void AChipWithNoReadingBehindItClaimsNoDate()
    {
        var chip = RecordStatus.Spf(new DomainDns { Domain = "example.com" });

        Assert.DoesNotContain("Last read", chip.Title, StringComparison.Ordinal);
    }
}
