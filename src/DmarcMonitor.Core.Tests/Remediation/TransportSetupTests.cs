using DmarcMonitor.Core.Dns;
using DmarcMonitor.Core.Remediation;

namespace DmarcMonitor.Core.Tests.Remediation;

/// <summary>
/// The records themselves, as opposed to whether changing them is safe.
///
/// TransportPlanner answers "may this be applied". This answers the question
/// that comes before it and had no answer at all: what does this domain need
/// to exist. An operator was told "no MTA-STS policy for example.com" and
/// given a command to run, and nothing anywhere named the two records or the
/// host the CNAME points at.
/// </summary>
public sealed class TransportSetupTests
{
    private static MtaStsPolicy Policy(string id = "20260918120000") => new()
    {
        Mode = MtaStsMode.Testing,
        Mx = ["acme-com.mail.protection.outlook.com"],
        Id = id,
    };

    // ---- TLS-RPT -------------------------------------------------------------

    [Fact]
    public void TlsReportingIsOneRecordAtTheRightName()
    {
        var record = TransportSetup.TlsReporting("acme.com", "dmarc@nrgtechservices.com");

        Assert.Equal("_smtp._tls.acme.com", record.Name);
        Assert.Equal("TXT", record.Type);
        Assert.Equal("v=TLSRPTv1; rua=mailto:dmarc@nrgtechservices.com", record.Value);
    }

    [Theory]
    [InlineData("acme.com.")]
    [InlineData("  ACME.com  ")]
    public void ATrailingDotOrStrayCaseDoesNotReachTheRecord(string domain)
    {
        // A name copied out of a zone file carries the dot, and a record built
        // from "_smtp._tls.acme.com.." is one nobody can find.
        var record = TransportSetup.TlsReporting(domain, "dmarc@nrgtechservices.com");

        Assert.DoesNotContain("..", record.Name, StringComparison.Ordinal);
        Assert.EndsWith("acme.com", record.Name, StringComparison.OrdinalIgnoreCase);
    }

    // ---- MTA-STS -------------------------------------------------------------

    [Fact]
    public void MtaStsNeedsTheCnameAndTheTxt()
    {
        var records = TransportSetup.MtaSts("acme.com", "dmarc.nextlayersec.ai", Policy());

        Assert.Equal(2, records.Count);

        var cname = records.Single(r => r.Type == "CNAME");
        Assert.Equal("mta-sts.acme.com", cname.Name);
        Assert.Equal("dmarc.nextlayersec.ai", cname.Value);

        var txt = records.Single(r => r.Type == "TXT");
        Assert.Equal("_mta-sts.acme.com", txt.Name);
        Assert.Equal("v=STSv1; id=20260918120000", txt.Value);
    }

    [Fact]
    public void TheTxtComesAfterTheCname()
    {
        // Order is the whole point. Announcing a policy that is not yet being
        // served is worse than announcing nothing, because senders cache the
        // failure for max_age - and the fix outlives the mistake.
        var records = TransportSetup.MtaSts("acme.com", "dmarc.nextlayersec.ai", Policy());

        Assert.Equal("CNAME", records[0].Type);
        Assert.Equal("TXT", records[1].Type);
        Assert.Contains("LAST", records[1].Why, StringComparison.Ordinal);
    }

    [Fact]
    public void WithNoPolicyHostTheTargetIsNamedAsUnknownRatherThanGuessed()
    {
        // A CNAME pointed at the wrong host is a policy no sender can fetch,
        // and this product has no way to know where it is reachable from the
        // outside. Saying so is the only honest answer.
        var records = TransportSetup.MtaSts("acme.com", null, Policy());

        var cname = records.Single(r => r.Type == "CNAME");
        Assert.Contains("<", cname.Value, StringComparison.Ordinal);
        Assert.False(cname.CanBeAutomated);
    }

    [Fact]
    public void WithAPolicyHostTheCnameIsSomethingThatCouldBeWritten()
    {
        var cname = TransportSetup.MtaSts("acme.com", "dmarc.nextlayersec.ai", Policy())
            .Single(r => r.Type == "CNAME");

        Assert.True(cname.CanBeAutomated);
    }

    [Fact]
    public void TheCnameSaysWhyTheCertificateMatters()
    {
        // The failure this prevents is subtle and total: a sender that cannot
        // validate the certificate for mta-sts.<domain> treats the domain as
        // having no policy, and nothing in the zone looks wrong.
        var cname = TransportSetup.MtaSts("acme.com", "dmarc.nextlayersec.ai", Policy())
            .Single(r => r.Type == "CNAME");

        Assert.Contains("certificate", cname.Why, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ThePolicyFileKeepsTheLineEndingsASenderExpects()
    {
        // RFC 8461 §3.2 says CRLF. Plenty of parsers accept LF and the ones
        // that do not fail invisibly.
        var file = TransportSetup.PolicyFile(Policy());

        Assert.Contains("\r\n", file, StringComparison.Ordinal);
        Assert.Contains("version: STSv1", file, StringComparison.Ordinal);
        Assert.Contains("mode: testing", file, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePolicyFileNeverCarriesTheId()
    {
        // The reason both call sites got this wrong: the id is in the TXT
        // record and nowhere else, so it cannot be recovered by fetching the
        // file. If it ever appears here, something has been misunderstood.
        Assert.DoesNotContain("id", TransportSetup.PolicyFile(Policy()), StringComparison.Ordinal);
    }
}
