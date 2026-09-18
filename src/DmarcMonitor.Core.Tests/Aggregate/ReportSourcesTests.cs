using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Domains;

namespace DmarcMonitor.Core.Tests.Aggregate;

/// <summary>
/// The diagnosis behind `dmarc explain`, which had no tests at all and was
/// wrong in three ways.
///
/// It is the one tool that works the moment somebody is handed a report - no
/// mailbox, no database, no configuration - so it is wrong at the moment it
/// matters most.
/// </summary>
public sealed class ReportSourcesTests
{
    private static string Report(string adkim, string aspf, params string[] records) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feedback>
          <report_metadata>
            <org_name>google.com</org_name><report_id>r1</report_id>
            <date_range><begin>1789000000</begin><end>1789086400</end></date_range>
          </report_metadata>
          <policy_published><domain>acme.com</domain><p>reject</p><pct>100</pct>
            <adkim>{adkim}</adkim><aspf>{aspf}</aspf></policy_published>
          {string.Join("\n  ", records)}
        </feedback>
        """;

    private static string Row(
        string ip, int count, string evaluated,
        string dkimDomain, string dkimResult, string spfDomain, string spfResult,
        string spfScope = "mfrom", string headerFrom = "acme.com") => $"""
        <record>
            <row><source_ip>{ip}</source_ip><count>{count}</count>
              <policy_evaluated><disposition>none</disposition>
                <dkim>{evaluated}</dkim><spf>{evaluated}</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{dkimDomain}</domain><selector>s1</selector><result>{dkimResult}</result></dkim>
              <spf><domain>{spfDomain}</domain><scope>{spfScope}</scope><result>{spfResult}</result></spf>
            </auth_results>
          </record>
        """;

    private static IReadOnlyList<SourceExplanation> Describe(string xml)
    {
        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        return ReportSources.Describe(parsed.Report!);
    }

    [Fact]
    public void AVerifiedSignatureForSomebodyElseIsSaidToBeExactlyThat()
    {
        var sources = Describe(Report("r", "r",
            Row("147.160.167.15", 289, "fail", "training.knowbe4.com", "pass", "psm.knowbe4.com", "pass")));

        var s = Assert.Single(sources);
        Assert.Equal(SourceOutcome.SignedForAnotherDomain, s.Outcome);
        Assert.Equal("training.knowbe4.com", Assert.Single(s.UnalignedDkim).Domain);
        Assert.Equal(289, s.Failing);
    }

    [Fact]
    public void ASignatureThatDidNotVerifyIsNotReportedAsASuccess()
    {
        // The first fault. Every authentication result was read without
        // checking whether it had passed, so a signature that FAILED for a
        // vendor's domain was announced as "authentication succeeded, but for
        // the vendor" - the opposite diagnosis, pointing at the opposite fix.
        var sources = Describe(Report("r", "r",
            Row("198.51.100.7", 40, "fail", "vendor.example", "fail", "vendor.example", "fail")));

        var s = Assert.Single(sources);
        Assert.Equal(SourceOutcome.Unauthenticated, s.Outcome);
        Assert.Empty(s.UnalignedDkim);
        Assert.Empty(s.UnalignedSpf);
    }

    [Fact]
    public void ASubdomainSignatureUnderStrictAlignmentIsNotCalledUnauthenticated()
    {
        // The second fault, and the worst of them. The old helper only knew
        // relaxed alignment, so it judged this signature aligned, found nothing
        // to report, and fell through to "nothing authenticated" - telling an
        // operator to go looking for a key that is present and working.
        var sources = Describe(Report("s", "s",
            Row("203.0.113.40", 61, "fail", "mail.acme.com", "pass", "mail.acme.com", "pass")));

        var s = Assert.Single(sources);
        Assert.Equal(SourceOutcome.SignedForAnotherDomain, s.Outcome);

        var signature = Assert.Single(s.UnalignedDkim);
        Assert.Equal(AlignmentVerdict.Organizational, signature.Verdict);
        Assert.True(signature.WouldAlignIfRelaxed);
        Assert.True(s.WouldAlignIfRelaxed);
    }

    [Fact]
    public void TheSameSubdomainUnderRelaxedAlignmentIsNotOfferedTheCheapFix()
    {
        // Relaxing what is already relaxed fixes nothing. If this is failing,
        // something else is wrong and the report should not send somebody to
        // weaken their record for no gain.
        var sources = Describe(Report("r", "r",
            Row("203.0.113.41", 61, "fail", "mail.acme.com", "pass", "mail.acme.com", "pass")));

        Assert.False(Assert.Single(sources).WouldAlignIfRelaxed);
    }

    [Fact]
    public void AnSpfOnlyPassIsKeptApartFromASigningProblem()
    {
        // The third fault: SPF and DKIM were merged into one list, so a relay
        // passing SPF under its own envelope drew the advice written for a
        // vendor signing its own domain. There is no signature to re-issue, so
        // "ask them to sign as you instead" is not advice that fits.
        var sources = Describe(Report("r", "r",
            Row("203.0.113.77", 25, "fail", "", "none", "relay.example.net", "pass")));

        var s = Assert.Single(sources);
        Assert.Equal(SourceOutcome.PassedSpfForAnotherDomain, s.Outcome);
        Assert.Equal("relay.example.net", Assert.Single(s.UnalignedSpf));
        Assert.Empty(s.UnalignedDkim);
    }

    [Fact]
    public void AHeloScopedSpfPassProvesNothingAboutAlignment()
    {
        // RFC 7489 §3.1.1: only the MAIL FROM identity contributes. Counting a
        // helo pass would report evidence the receiver never credited.
        var sources = Describe(Report("r", "r",
            Row("203.0.113.78", 25, "fail", "", "none", "mta.example.net", "pass", spfScope: "helo")));

        var s = Assert.Single(sources);
        Assert.Equal(SourceOutcome.Unauthenticated, s.Outcome);
        Assert.Empty(s.UnalignedSpf);
    }

    [Fact]
    public void ASignatureForTheDomainItselfIsNotAMismatch()
    {
        var sources = Describe(Report("s", "s",
            Row("198.51.100.8", 12, "fail", "acme.com", "pass", "relay.example.net", "pass")));

        Assert.Empty(Assert.Single(sources).UnalignedDkim);
    }

    [Fact]
    public void AForwardedFailureIsNotSomebodysMisconfiguration()
    {
        const string forwarded = """
            <record>
                <row><source_ip>203.0.113.99</source_ip><count>9</count>
                  <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                    <reason><type>forwarded</type><comment>mailing list</comment></reason>
                  </policy_evaluated>
                </row>
                <identifiers><header_from>acme.com</header_from></identifiers>
                <auth_results>
                  <dkim><domain>acme.com</domain><result>fail</result></dkim>
                  <spf><domain>acme.com</domain><result>fail</result></spf>
                </auth_results>
              </record>
            """;

        var sources = Describe(Report("r", "r", forwarded));

        Assert.Equal(SourceOutcome.Forwarded, Assert.Single(sources).Outcome);
    }

    [Fact]
    public void ASourceThatNeverFailedIsClean()
    {
        var sources = Describe(Report("r", "r",
            Row("192.0.2.25", 400, "pass", "acme.com", "pass", "acme.com", "pass")));

        var s = Assert.Single(sources);
        Assert.Equal(SourceOutcome.Authenticated, s.Outcome);
        Assert.Equal(0, s.Failing);
    }

    [Fact]
    public void OnlyTheFailingRowsDecideTheDiagnosis()
    {
        // A gateway that signs correctly most of the time and breaks a share of
        // its signatures in transit. Judged across everything it sent, the
        // broken messages disappear behind the working ones.
        var sources = Describe(Report("r", "r",
            Row("35.174.145.124", 113, "pass", "acme.com", "pass", "acme.com", "pass"),
            Row("35.174.145.124", 239, "fail", "vendor.example", "pass", "acme.com", "fail")));

        var s = Assert.Single(sources);
        Assert.Equal(352, s.Messages);
        Assert.Equal(239, s.Failing);
        Assert.Equal(SourceOutcome.SignedForAnotherDomain, s.Outcome);
        Assert.Equal("vendor.example", Assert.Single(s.UnalignedDkim).Domain);
    }

    [Fact]
    public void ProblemsAreListedBeforeCleanSources()
    {
        // A clean source is the one thing nobody needs to read.
        var sources = Describe(Report("r", "r",
            Row("192.0.2.25", 4000, "pass", "acme.com", "pass", "acme.com", "pass"),
            Row("198.51.100.7", 3, "fail", "vendor.example", "pass", "vendor.example", "pass")));

        Assert.Equal("198.51.100.7", sources[0].SourceIp);
    }
}
