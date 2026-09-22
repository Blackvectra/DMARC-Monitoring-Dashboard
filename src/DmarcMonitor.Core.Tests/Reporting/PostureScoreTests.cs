using DmarcMonitor.Core.Reporting;
using Xunit;

namespace DmarcMonitor.Core.Tests.Reporting;

/// <summary>
/// The number at the top of the dashboard.
///
/// Every product in this market puts a score there and none of them says what
/// it is made of, which is why the tests below are mostly about the score
/// being unflattering: an estate that is monitoring rather than protecting
/// must not be able to reach a comfortable number, and an install with no
/// data must not reach any number at all.
/// </summary>
public sealed class PostureScoreTests
{
    private static AuthenticationRates Rates(long messages = 1000, long aligned = 1000) =>
        new() { Messages = messages, DmarcPass = aligned, SpfPass = aligned, DkimPass = aligned };

    [Fact]
    public void EverythingRightIsOneHundred()
    {
        var score = PostureScore.For(enforcing: 4, domains: 4, reporting: 4, tlsEnforcing: 4, Rates());

        Assert.Equal(100, score.Score);
        Assert.Equal("Strong", score.Band);
        Assert.Contains("Every domain enforcing", score.Weakest, StringComparison.Ordinal);
    }

    /// <summary>
    /// The trap this score exists to avoid.
    /// </summary>
    /// <remarks>
    /// p=none with flawless authentication is the most common state in this
    /// product's data and the most dangerous to present well: every message
    /// aligns, so a score built on alignment alone reads as protected, while
    /// no receiver has been asked to do anything about the ones that do not.
    /// </remarks>
    [Fact]
    public void PerfectAlignmentWithNoEnforcementCannotPassSixty()
    {
        var score = PostureScore.For(enforcing: 0, domains: 4, reporting: 4, tlsEnforcing: 4, Rates());

        Assert.Equal(60, score.Score);
        Assert.Equal("Needs work", score.Band);
        Assert.Contains("domains not yet enforcing", score.Weakest, StringComparison.Ordinal);
    }

    /// <summary>
    /// The opposite mistake, and the one that breaks a customer's mail.
    /// </summary>
    [Fact]
    public void EnforcingWhileLosingMailIsNotStrongEither()
    {
        var score = PostureScore.For(
            enforcing: 4, domains: 4, reporting: 4, tlsEnforcing: 4,
            Rates(messages: 1000, aligned: 500));

        Assert.Equal(80, score.Score);
        Assert.Contains("mail that does not align", score.Weakest, StringComparison.Ordinal);
    }

    /// <summary>
    /// A fresh install must not be told its estate is at risk, because the
    /// two look identical on a dial and only one of them is true.
    /// </summary>
    [Fact]
    public void NothingToScoreIsNotAScoreOfZero()
    {
        var empty = PostureScore.For(0, 0, 0, 0, new AuthenticationRates());

        Assert.False(empty.Known);
        Assert.Contains("Not enough reported mail", empty.Weakest, StringComparison.Ordinal);

        // And the same where there are domains but no mail has been reported
        // about them: a policy in DNS is what the records SAY, not what the
        // mail does, and scoring on it alone would flatter an install that has
        // never seen a report.
        Assert.False(PostureScore.For(4, 4, 0, 4, new AuthenticationRates()).Known);
    }

    [Fact]
    public void EachPartIsWorthWhatItSaysItIs()
    {
        // Losing only the transport points, from a perfect estate.
        var noTls = PostureScore.For(enforcing: 2, domains: 2, reporting: 2, tlsEnforcing: 0, Rates());
        Assert.Equal(100 - PostureScore.TransportWeight, noTls.Score);

        var noVisibility = PostureScore.For(enforcing: 2, domains: 2, reporting: 0, tlsEnforcing: 2, Rates());
        Assert.Equal(100 - PostureScore.VisibilityWeight, noVisibility.Score);
    }

    /// <summary>
    /// Counts that do not fit inside their denominator cannot buy extra
    /// points. Defensive rather than expected: the callers derive both numbers
    /// from the same list, and a later one may not.
    /// </summary>
    [Fact]
    public void MoreEnforcingThanDomainsIsStillOnlyFullMarks()
    {
        var score = PostureScore.For(enforcing: 9, domains: 2, reporting: 9, tlsEnforcing: 9, Rates());

        Assert.Equal(100, score.Score);
    }

    [Fact]
    public void RatesAreSharesOfTheSameDenominator()
    {
        var rates = new AuthenticationRates
        {
            Messages = 200,
            DmarcPass = 100,
            SpfPass = 150,
            DkimPass = 50,
        };

        Assert.Equal(50, rates.DmarcRate);
        Assert.Equal(75, rates.SpfRate);
        Assert.Equal(25, rates.DkimRate);
        Assert.True(rates.HasMail);
    }

    [Fact]
    public void NoMailIsZeroRatherThanADivideByZero()
    {
        var none = new AuthenticationRates();

        Assert.False(none.HasMail);
        Assert.Equal(0, none.DmarcRate);
    }

    [Fact]
    public void ANullRatesArgumentIsRefusedRatherThanScoredAsEmpty()
    {
        Assert.Throws<ArgumentNullException>(() => PostureScore.For(1, 1, 1, 1, null!));
    }

    /// <summary>
    /// A host with a name shows the name; one without shows its address. The
    /// same rule as the report's, because the two are read side by side.
    /// </summary>
    [Fact]
    public void AHostIsShownByItsNameWhenItHasOne()
    {
        var named = new SendingHost { SourceIp = "203.0.113.4", ReverseName = "mail.example.net", Messages = 10 };
        var bare = new SendingHost { SourceIp = "203.0.113.5", Messages = 10 };

        Assert.Equal("mail.example.net", named.Display);
        Assert.True(named.IsNamed);
        Assert.Equal("203.0.113.5", bare.Display);
        Assert.False(bare.IsNamed);
    }
}
