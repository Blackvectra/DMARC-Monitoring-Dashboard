using DmarcMonitor.Core.Dns;

namespace DmarcMonitor.Core.Tests.Dns;

/// <summary>
/// The MTA-STS policy file.
///
/// The one calculation that matters here is <see cref="MtaStsPolicy.Covers"/>:
/// under enforce, a mail server the policy does not cover stops receiving
/// mail. Getting the wildcard rule wrong in the permissive direction means
/// saying a policy is safe to enforce when it is not.
/// </summary>
public sealed class MtaStsPolicyTests
{
    [Fact]
    public void WritesTheFileTheWayTheRfcRequiresIt()
    {
        var policy = new MtaStsPolicy
        {
            Mode = MtaStsMode.Testing,
            Mx = ["acme-com.mail.protection.outlook.com", "*.backup.example.net"],
            Id = "20260918120000",
        };

        // CRLF, per RFC 8461 §3.2. Plenty of parsers accept LF and the ones
        // that do not fail somewhere nobody is looking.
        Assert.Equal(
            "version: STSv1\r\n"
            + "mode: testing\r\n"
            + "mx: acme-com.mail.protection.outlook.com\r\n"
            + "mx: *.backup.example.net\r\n"
            + "max_age: 604800\r\n",
            policy.ToFile());

        Assert.Equal("v=STSv1; id=20260918120000", policy.ToRecord());
    }

    [Fact]
    public void ReadsBackWhatItWrites()
    {
        var original = MtaStsPolicy.ForTesting(["mail.acme.com"], DateTimeOffset.UtcNow);

        var parsed = MtaStsPolicy.ParseFile(original.ToFile());

        Assert.NotNull(parsed);
        Assert.Equal(original.Mode, parsed.Mode);
        Assert.Equal(original.Mx, parsed.Mx);
        Assert.Equal(original.MaxAgeSeconds, parsed.MaxAgeSeconds);
    }

    [Fact]
    public void ReadsAFileSomebodyElseWrote()
    {
        // Line endings, spacing and case are all as found in the wild.
        var parsed = MtaStsPolicy.ParseFile(
            "version: STSv1\n"
            + "mode: ENFORCE\n"
            + "mx:  mail.acme.com.\n"
            + "max_age:86400\n");

        Assert.NotNull(parsed);
        Assert.Equal("enforce", parsed.Mode);
        Assert.Equal(["mail.acme.com"], parsed.Mx);
        Assert.Equal(86400, parsed.MaxAgeSeconds);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("mode: enforce\nmx: mail.acme.com")]          // no version line
    [InlineData("version: STSv2\nmode: enforce")]             // wrong version
    [InlineData("version: STSv1\nmx: mail.acme.com")]         // no mode
    [InlineData("<html><body>404</body></html>")]
    public void RefusesAnythingThatIsNotAPolicy(string text)
    {
        // What comes back from a web server that is serving something else
        // entirely, which is the common case for a domain nobody has set this
        // up for.
        Assert.Null(MtaStsPolicy.ParseFile(text));
    }

    // ---- the calculation that decides whether enforcing is safe ---------------

    [Theory]
    [InlineData("mail.acme.com", "mail.acme.com", true)]
    [InlineData("mail.acme.com", "MAIL.ACME.COM.", true)]
    [InlineData("mail.acme.com", "other.acme.com", false)]
    [InlineData("*.acme.com", "mail.acme.com", true)]
    [InlineData("*.acme.com", "acme.com", false)]
    [InlineData("*.acme.com", "a.b.acme.com", false)]
    [InlineData("*.mail.protection.outlook.com", "acme-com.mail.protection.outlook.com", true)]
    public void AWildcardMatchesExactlyOneLabel(string pattern, string host, bool covered)
    {
        // RFC 8461 §4.1. Matching more than one label would call a policy safe
        // to enforce when a sender would disagree and refuse the mail.
        var policy = new MtaStsPolicy { Mode = MtaStsMode.Enforce, Mx = [pattern], Id = "1" };

        Assert.Equal(covered, policy.Covers(host));
    }

    [Fact]
    public void NamesEveryMailServerThatWouldStopReceiving()
    {
        var policy = new MtaStsPolicy { Mode = MtaStsMode.Enforce, Mx = ["*.acme.com"], Id = "1" };

        var uncovered = policy.Uncovered(["mail.acme.com", "backup.example.net", "old.mail.acme.com"]);

        Assert.Equal(["backup.example.net", "old.mail.acme.com"], uncovered);
    }

    [Fact]
    public void AnIdMovesOnlyWhenSomethingChanges()
    {
        // Senders re-fetch when the id changes. One that moved on every read
        // would have every sender on the internet fetching the file
        // constantly; one that never moved would leave them on a stale policy.
        var when = new DateTimeOffset(2026, 9, 18, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal("20260918120000", MtaStsPolicy.IdFor(when));
        Assert.Equal(MtaStsPolicy.IdFor(when), MtaStsPolicy.IdFor(when));
        Assert.NotEqual(MtaStsPolicy.IdFor(when), MtaStsPolicy.IdFor(when.AddSeconds(1)));
    }

    [Fact]
    public void TheUrlIsWhereASenderWouldLook()
    {
        Assert.Equal(
            "https://mta-sts.acme.com/.well-known/mta-sts.txt",
            MtaStsFetcher.UrlFor("ACME.com."));
    }
}
