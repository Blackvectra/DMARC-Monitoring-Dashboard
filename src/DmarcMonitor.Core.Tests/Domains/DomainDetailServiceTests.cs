using DmarcMonitor.Core.Aggregate;
using DmarcMonitor.Core.Domains;
using DmarcMonitor.Core.Rollout;
using DmarcMonitor.Core.Storage;
using Microsoft.Data.Sqlite;

namespace DmarcMonitor.Core.Tests.Domains;

/// <summary>
/// The page an operator opens from triage.
///
/// It carries the same three-bucket rule as the client report - the domain's
/// own sending paths, third-party services signing as themselves, and sources
/// impersonating it - and that rule was corrected on inspection rather than on
/// a failing test. These are the tests that should have caught it.
/// </summary>
public sealed class DomainDetailServiceTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"dmarc-detail-{Guid.NewGuid():N}.db");
    private readonly ReportStore _store;

    public DomainDetailServiceTests()
    {
        _store = new ReportStore(_dbPath);
        _store.InitializeAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch (IOException) { }
        }
    }

    private static string Row(
        string ip, int count, string dmarc, string headerFrom, string dkimDomain, string dkimResult) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>{dmarc}</dkim><spf>fail</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{dkimDomain}</domain><selector>selector1</selector><result>{dkimResult}</result></dkim>
              <spf><domain>{dkimDomain}</domain><result>{dkimResult}</result></spf>
            </auth_results>
          </record>
        """;

    /// <summary>A row the receiving provider overrode, as a mailing list produces.</summary>
    private static string ForwardedRow(string ip, int count, string domain) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated>
                <disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
                <reason><type>forwarded</type><comment>mailing list</comment></reason>
              </policy_evaluated>
            </row>
            <identifiers><header_from>{domain}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{domain}</domain><result>fail</result></dkim>
              <spf><domain>{domain}</domain><result>fail</result></spf>
            </auth_results>
          </record>
        """;

    /// <summary>
    /// Mail that authenticated, which the receiver nonetheless attached an
    /// override note to. Microsoft does this constantly: "SPF ignored due to
    /// local policy" on traffic that passed by DKIM.
    /// </summary>
    private static string OverriddenButPassingRow(string ip, int count, string domain) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated>
                <disposition>none</disposition><dkim>pass</dkim><spf>pass</spf>
                <reason><type>local_policy</type><comment>SPF ignored due to local policy</comment></reason>
              </policy_evaluated>
            </row>
            <identifiers><header_from>{domain}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{domain}</domain><selector>selector1</selector><result>pass</result></dkim>
              <spf><domain>{domain}</domain><result>pass</result></spf>
            </auth_results>
          </record>
        """;

    private async Task StoreAsync(string domain, string policy, params string[] rows) =>
        await StoreAsync(domain, policy, daysAgo: 2, rows);

    private Task StoreAsync(string domain, string policy, int daysAgo, params string[] rows) =>
        StoreFromAsync("google.com", domain, policy, daysAgo, rows);

    private async Task StoreFromAsync(string org, string domain, string policy, int daysAgo, params string[] rows)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-daysAgo);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>{org}</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>{policy}</p><pct>100</pct></policy_published>
              {string.Join("\n  ", rows)}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    private Task<DomainDetail?> GetAsync(string domain) =>
        new DomainDetailService(_dbPath).GetAsync(domain);

    // ---- what may name a gateway ----------------------------------------------
    //
    // A source filed as a gateway leaves the list of impersonators, so what
    // names one has to be something the sender cannot write. MAIL FROM and a
    // PTR are both written by whoever sends; the envelope domain's SPF record
    // and the name's forward DNS are written by whoever owns the domain.

    /// <summary>Mail signed as the domain and broken, sent with the given envelope.</summary>
    private static string EnvelopeRow(string ip, int count, string headerFrom, string envelope, string spfResult) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{headerFrom}</domain><selector>selector1</selector><result>fail</result></dkim>
              <spf><domain>{envelope}</domain><result>{spfResult}</result></spf>
            </auth_results>
          </record>
        """;

    [Fact]
    public async Task AGatewayIsRecognizedByAnEnvelopeItsSpfAuthorizes()
    {
        // shield.security's SPF names the address, so the envelope is proof.
        await StoreAsync("acme.com", "reject",
            EnvelopeRow("3.133.222.181", 7, "acme.com", "courier.shield.security", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.Equal("a hosted mail security gateway", Assert.Single(detail!.Forwarders).GatewayName);
        Assert.Empty(detail.Impersonating);
    }

    [Fact]
    public async Task ClaimingAGatewaysEnvelopeDoesNotHideAForgery()
    {
        // Anybody can send from bounces@inkyphishfence.com. This address is not
        // in INKY's SPF, so the claim identifies nothing and the mail is what
        // it looks like: sent as the domain by somebody who could not prove it.
        await StoreAsync("acme.com", "reject",
            EnvelopeRow("203.0.113.66", 7, "acme.com", "ipw.inkyphishfence.com", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.Empty(detail!.Forwarders);
        Assert.Equal("203.0.113.66", Assert.Single(detail.Impersonating).SourceIp);
    }

    [Fact]
    public async Task AGatewayIsRecognizedByAConfirmedReverseName()
    {
        // How INKY actually arrives: its envelope domain publishes no SPF, so
        // nothing verifies the envelope, and INKY's own forward DNS names the
        // relay. The client report recognizes it the same way; the page and the
        // report must not disagree about one address.
        await StoreAsync("acme.com", "reject",
            EnvelopeRow("100.24.129.5", 6, "acme.com", "ipw.inkyphishfence.com", "none"));
        await new DmarcMonitor.Core.Intelligence.SourceNameStore(_dbPath)
            .SaveAsync("100.24.129.5", "ipw-outbound.inkyphishfence.com", answered: true, forwardConfirmed: true);

        var detail = await GetAsync("acme.com");

        Assert.Equal("INKY", Assert.Single(detail!.Forwarders).GatewayName);
        Assert.Empty(detail.Impersonating);
    }

    [Fact]
    public async Task AnUnconfirmedGatewayNameDoesNotHideAForgery()
    {
        // The forger's own PTR, which it chose. Printed as the hostname it
        // claims, never as "INKY", and it stays an impersonator.
        await StoreAsync("acme.com", "reject",
            EnvelopeRow("203.0.113.67", 6, "acme.com", "acme.com", "fail"));
        await new DmarcMonitor.Core.Intelligence.SourceNameStore(_dbPath)
            .SaveAsync("203.0.113.67", "mail.inkyphishfence.com", answered: true, forwardConfirmed: false);

        var detail = await GetAsync("acme.com");

        Assert.Empty(detail!.Forwarders);
        var source = Assert.Single(detail.Impersonating);
        Assert.Equal("mail.inkyphishfence.com", source.Display);
    }

    // ---- the three buckets ---------------------------------------------------

    [Fact]
    public async Task ADomainsOwnSendingPathIsNotAccusedOfImpersonatingIt()
    {
        // The gateway again: signs as the domain, breaks a share of its
        // signatures in transit. Judged on the failing rows alone the page
        // tells an operator the customer's own infrastructure is impersonating
        // them, which sends them investigating their own relay.
        await StoreAsync("acme.com", "reject",
            Row("35.174.145.124", 113, "pass", "acme.com", "acme.com", "pass"),
            Row("35.174.145.124", 239, "fail", "acme.com", "acme.com", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Empty(detail!.Impersonating);
        var source = Assert.Single(detail.Misconfigured);
        Assert.Equal(352, source.Messages);
        Assert.Equal(239, source.Failing);
    }

    [Fact]
    public async Task ASourceThatNeverPassedForThisDomainIsImpersonation()
    {
        await StoreAsync("acme.com", "reject",
            Row("203.0.113.9", 40, "fail", "acme.com", "acme.com", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Single(detail!.Impersonating);
        Assert.Empty(detail.Misconfigured);
    }

    [Fact]
    public async Task AThirdPartySigningAsItselfIsNamedRatherThanAccused()
    {
        await StoreAsync("acme.com", "reject",
            Row("198.51.100.7", 55, "fail", "acme.com", "mailchimpapp.net", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var source = Assert.Single(detail!.Misconfigured);
        Assert.Equal("mailchimpapp.net", source.AuthenticatedFor);
        Assert.Empty(detail.Impersonating);
    }

    [Fact]
    public async Task TheThreeBucketsNeverShareASource()
    {
        await StoreAsync("acme.com", "reject",
            Row("192.0.2.25", 400, "pass", "acme.com", "acme.com", "pass"),
            Row("198.51.100.7", 55, "fail", "acme.com", "mailchimpapp.net", "pass"),
            Row("203.0.113.9", 20, "fail", "acme.com", "acme.com", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var all = detail!.Clean.Concat(detail.Misconfigured).Concat(detail.Impersonating)
            .Select(s => s.SourceIp).ToList();

        Assert.Equal(3, all.Count);
        Assert.Equal(all.Count, all.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task ExplainsTheGapBetweenTheHeadlineAndTheSourceTables()
    {
        // Forwarded and receiver-overridden traffic is deliberately kept out
        // of the source tables - a mailing list breaking authentication is
        // expected and buries the findings that matter - but it is still
        // counted in the total. On the live data that is 7,970 against 8,018
        // for one domain, and an unexplained 48 reads as broken arithmetic.
        await StoreAsync("acme.com", "reject",
            Row("192.0.2.25", 100, "pass", "acme.com", "acme.com", "pass"),
            ForwardedRow("192.0.2.50", 48, "acme.com"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Equal(148, detail!.Messages);
        Assert.Equal(48, detail.OverriddenMessages);

        // And the source tables really do leave it out, or there would be
        // nothing to explain.
        var listed = detail.Clean.Concat(detail.Misconfigured).Concat(detail.Impersonating)
            .Sum(s => s.Messages);
        Assert.Equal(detail.Messages - detail.OverriddenMessages, listed);
    }

    [Fact]
    public async Task MailThatPassedIsNotTreatedAsLeftOutJustBecauseTheReceiverAnnotatedIt()
    {
        // An override is only the receiver saying it did not apply the policy
        // as asked. It says that about mail that PASSED as often as about mail
        // that failed - "SPF ignored due to local policy" on DKIM-authenticated
        // traffic is routine from Microsoft.
        //
        // Excluding every annotated record took a domain's own clean mail out
        // of the source tables and then described it to the operator as traffic
        // left out, alongside forwarded failures. On the live data that was 19
        // of mortonnd.gov's 84 messages: its own mail servers, passing, and the
        // page implied there was something unresolved about them.
        await StoreAsync("acme.com", "reject",
            Row("192.0.2.25", 100, "pass", "acme.com", "acme.com", "pass"),
            OverriddenButPassingRow("192.0.2.80", 19, "acme.com"),
            ForwardedRow("192.0.2.50", 48, "acme.com"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Equal(167, detail!.Messages);

        // Only the forwarded failure is left out. The annotated-but-passing
        // mail is the domain's own and stays in.
        Assert.Equal(48, detail.OverriddenMessages);

        var listed = detail.Clean.Concat(detail.Misconfigured).Concat(detail.Impersonating).ToList();
        Assert.Contains(listed, s => s.SourceIp == "192.0.2.80");
        Assert.Equal(19, listed.Single(s => s.SourceIp == "192.0.2.80").Messages);

        // And the arithmetic the operator can do by eye still works.
        Assert.Equal(detail.Messages - detail.OverriddenMessages, listed.Sum(s => s.Messages));
    }

    // ---- a reporter that goes quiet -----------------------------------------

    [Fact]
    public async Task NoticesWhenTheReceiverCarryingMostOfTheMailStopsReporting()
    {
        // The shape that hid a real problem. mortonnd.gov read as 100% passing
        // and "ready to move to p=reject" over fourteen days, because
        // Enterprise Outlook - which had carried 73.5% of everything ever
        // reported for it - stopped sending about that domain two months
        // earlier, while still reporting on every other domain in the book.
        // Reports kept arriving from the others, so nothing looked wrong.
        await StoreFromAsync("Enterprise Outlook", "acme.com", "none", daysAgo: 70,
            Row("192.0.2.25", 800, "pass", "acme.com", "acme.com", "pass"));
        await StoreFromAsync("google.com", "acme.com", "none", daysAgo: 2,
            Row("192.0.2.25", 40, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);

        var outlook = detail!.Reporters.Single(r => r.OrgName == "Enterprise Outlook");
        Assert.True(outlook.HasGoneQuiet, "the reporter carrying most of the mail went quiet and was not flagged");
        Assert.True(outlook.Share > 90);

        // The one still reporting is not flagged, or the warning means nothing.
        Assert.False(detail.Reporters.Single(r => r.OrgName == "google.com").HasGoneQuiet);
    }

    [Fact]
    public async Task ASmallReporterGoingQuietIsNotWorthSaying()
    {
        // Plenty of receivers send one report when a single message happens to
        // pass through them and are never heard from again. Flagging those
        // would bury the one that matters.
        await StoreFromAsync("google.com", "acme.com", "none", daysAgo: 2,
            Row("192.0.2.25", 900, "pass", "acme.com", "acme.com", "pass"));
        await StoreFromAsync("tiny.example", "acme.com", "none", daysAgo: 80,
            Row("192.0.2.99", 1, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.False(detail!.Reporters.Single(r => r.OrgName == "tiny.example").HasGoneQuiet);
        Assert.DoesNotContain(detail.Reporters, r => r.HasGoneQuiet);
    }

    [Fact]
    public async Task AnOldImportDoesNotMakeEveryReporterLookQuiet()
    {
        // Silence is measured against the newest report for the domain, not
        // against the clock. Restoring a backup, or importing an archive of
        // last year's reports, must not light up every row at once.
        await StoreFromAsync("Enterprise Outlook", "acme.com", "none", daysAgo: 400,
            Row("192.0.2.25", 800, "pass", "acme.com", "acme.com", "pass"));
        await StoreFromAsync("google.com", "acme.com", "none", daysAgo: 402,
            Row("192.0.2.26", 700, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.DoesNotContain(detail!.Reporters, r => r.HasGoneQuiet);
    }

    [Fact]
    public async Task SaysNothingAboutOverridesWhenThereAreNone()
    {
        await StoreAsync("acme.com", "reject",
            Row("192.0.2.25", 100, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Equal(0, detail!.OverriddenMessages);
    }

    // ---- the verdict ---------------------------------------------------------

    [Fact]
    public async Task TheVerdictIsTheOneTheTriageListWouldGive()
    {
        // Two pages describing one domain differently is worse than either
        // description alone, so the page must not recompute this.
        await StoreAsync("acme.com", "reject",
            Row("192.0.2.25", 800, "pass", "acme.com", "acme.com", "pass"),
            Row("203.0.113.9", 200, "fail", "acme.com", "acme.com", "fail"));

        var detail = await GetAsync("acme.com");
        Assert.NotNull(detail);

        var expected = RolloutAssessment.Assess(new DomainState
        {
            Domain = "acme.com",
            Policy = detail!.Policy,
            PolicyTarget = detail.PolicyTarget,
            Messages = detail.Messages,
            Passing = detail.Passing,
            FailingSources = detail.Misconfigured.Count + detail.Impersonating.Count,
            LastReport = detail.LastReport,
            BaselineStarted = detail.BaselineStarted,
            BaselineDays = detail.BaselineDays,
        });

        Assert.Equal(expected.Level, detail.Level);
        Assert.Equal(expected.Headline, detail.Headline);
    }

    [Fact]
    public async Task ReadsThePolicyFromTheMostRecentReport()
    {
        // An older report describes a policy that may since have changed, and
        // checking the current policy is the commonest reason to open this.
        await StoreAsync("acme.com", "none", daysAgo: 5, Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass"));
        await StoreAsync("acme.com", "reject", daysAgo: 1, Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Equal("reject", detail!.Policy);
    }

    [Fact]
    public async Task NamesEveryReceiverThatReported()
    {
        // A clean pass rate heard from one receiver is a partial picture, and
        // an operator should be able to see which it is.
        await StoreAsync("acme.com", "reject", Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var reporter = Assert.Single(detail!.Reporters);
        Assert.Equal("google.com", reporter.OrgName);
        Assert.Equal(1, reporter.Reports);
    }

    [Fact]
    public async Task ReturnsNothingForADomainNobodyHasReportedOn()
    {
        // Not an error: a domain published this morning has no reports yet,
        // and the page says what would make it appear.
        Assert.Null(await GetAsync("never-seen.example"));
    }

    [Fact]
    public async Task MatchesTheDomainWithoutCareForCaseOrATrailingDot()
    {
        await StoreAsync("acme.com", "reject", Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass"));

        Assert.NotNull(await GetAsync("ACME.com."));
    }

    // ---- a signature that verified and was thrown away anyway ----------------

    /// <summary>
    /// A row with the two mechanisms said separately, which the shorthand
    /// helper above cannot express. The shape that matters here is a signature
    /// that VERIFIES over a domain that is not the one being sent as.
    /// </summary>
    private static string SignedRow(
        string ip, int count, string headerFrom,
        string dkimDomain, string dkimResult, string spfDomain, string spfResult, string evaluated) => $"""
        <record>
            <row>
              <source_ip>{ip}</source_ip>
              <count>{count}</count>
              <policy_evaluated><disposition>none</disposition>
                <dkim>{evaluated}</dkim><spf>{evaluated}</spf></policy_evaluated>
            </row>
            <identifiers><header_from>{headerFrom}</header_from></identifiers>
            <auth_results>
              <dkim><domain>{dkimDomain}</domain><selector>s1</selector><result>{dkimResult}</result></dkim>
              <spf><domain>{spfDomain}</domain><result>{spfResult}</result></spf>
            </auth_results>
          </record>
        """;

    /// <summary>The same store, with the domain's alignment mode spelled out.</summary>
    private async Task StoreAlignedAsync(string domain, string policy, string adkim, params string[] rows)
    {
        var begin = DateTimeOffset.UtcNow.AddDays(-2);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <feedback>
              <report_metadata>
                <org_name>google.com</org_name>
                <report_id>{Guid.NewGuid():N}</report_id>
                <date_range><begin>{begin.ToUnixTimeSeconds()}</begin>
                            <end>{begin.AddHours(23).ToUnixTimeSeconds()}</end></date_range>
              </report_metadata>
              <policy_published><domain>{domain}</domain><p>{policy}</p><pct>100</pct>
                <adkim>{adkim}</adkim><aspf>{adkim}</aspf></policy_published>
              {string.Join("\n  ", rows)}
            </feedback>
            """;

        var parsed = AggregateReportParser.Parse(xml);
        Assert.True(parsed.Success, parsed.Error);
        await _store.SaveAggregateAsync(parsed.Report!, xml, null);
    }

    [Fact]
    public async Task AValidSignatureForSomebodyElsesDomainIsNamedAsUnaligned()
    {
        // The live case this was built for. KnowBe4 signs its training mail
        // with its own key over training.knowbe4.com, the signature verifies,
        // and every message is rejected at p=reject. The report row says
        // "dkim=pass" next to "dmarc=fail", and without something saying why,
        // an operator who has already set DKIM up concludes the product is
        // wrong rather than that one sending path was missed.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("147.160.167.15", 289, "acme.com",
                "training.knowbe4.com", "pass", "psm.knowbe4.com", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var source = Assert.Single(detail!.SigningUnaligned);
        Assert.Equal("147.160.167.15", source.SourceIp);

        var signature = Assert.Single(source.UnalignedDkim);
        Assert.Equal("training.knowbe4.com", signature.Domain);
        Assert.Equal(AlignmentVerdict.Unrelated, signature.Verdict);

        // Not a near miss. No alignment setting on acme.com makes a signature
        // over knowbe4.com count, so suggesting one would be a wrong fix.
        Assert.False(signature.WouldAlignIfRelaxed);
        Assert.False(detail.AnyWouldAlignIfRelaxed);
    }

    [Fact]
    public async Task ASignatureThatDidNotVerifyIsNotCalledUnaligned()
    {
        // Opposite problem, opposite fix: this key is broken or the message was
        // modified in transit. Calling it a domain mismatch sends the operator
        // to the vendor's alignment settings, where they will find nothing.
        await StoreAlignedAsync("acme.com", "reject", "r",
            SignedRow("198.51.100.7", 40, "acme.com",
                "acme.com", "fail", "acme.com", "fail", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Empty(detail!.SigningUnaligned);
    }

    [Fact]
    public async Task ASignatureForTheDomainItselfIsNotCalledUnaligned()
    {
        // Verified, for exactly the right domain, and the message still failed.
        // Whatever went wrong, it was not the signing domain.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("198.51.100.8", 12, "acme.com",
                "acme.com", "pass", "relay.example.net", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Empty(detail!.SigningUnaligned);
    }

    [Fact]
    public async Task ASubdomainSignatureIsANearMissWhenAlignmentIsStrict()
    {
        // The cheapest fix in DMARC and the easiest to miss: the sender is
        // already signing the customer's own namespace, and one character of
        // the customer's own record is refusing it.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("203.0.113.40", 61, "acme.com",
                "mail.acme.com", "pass", "mail.acme.com", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.True(detail!.StrictDkim);

        var signature = Assert.Single(Assert.Single(detail.SigningUnaligned).UnalignedDkim);
        Assert.Equal(AlignmentVerdict.Organizational, signature.Verdict);
        Assert.True(signature.WouldAlignIfRelaxed);
        Assert.True(detail.AnyWouldAlignIfRelaxed);
    }

    [Fact]
    public async Task ASubdomainSignatureIsNotOfferedAsANearMissWhenAlignmentIsAlreadyRelaxed()
    {
        // Relaxing what is already relaxed fixes nothing, and offering it as a
        // fix would have somebody weaken a record for no gain.
        await StoreAlignedAsync("acme.com", "reject", "r",
            SignedRow("203.0.113.41", 61, "acme.com",
                "mail.acme.com", "pass", "mail.acme.com", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.False(detail!.StrictDkim);

        var signature = Assert.Single(Assert.Single(detail.SigningUnaligned).UnalignedDkim);
        Assert.Equal(AlignmentVerdict.Organizational, signature.Verdict);
        Assert.False(signature.WouldAlignIfRelaxed);
        Assert.False(detail.AnyWouldAlignIfRelaxed);
    }

    [Fact]
    public async Task AnotherHostOfTheSameServiceSigningCorrectlyIsNamed()
    {
        // What turns a support ticket into a closed one. Both hosts carry the
        // same service's mail - the same envelope domain says so - and one of
        // them already signs as the customer. The vendor cannot answer that it
        // is unable to.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("23.21.109.197", 14, "acme.com",
                "acme.com", "pass", "psm.knowbe4.com", "pass", "pass"),
            SignedRow("147.160.167.15", 289, "acme.com",
                "training.knowbe4.com", "pass", "psm.knowbe4.com", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var broken = Assert.Single(detail!.SigningUnaligned);
        Assert.Equal("147.160.167.15", broken.SourceIp);
        Assert.Equal("23.21.109.197", broken.SameServiceSigningCorrectly);
    }

    [Fact]
    public async Task ASourceThatPassesWithoutEverSigningTheDomainIsNotOfferedAsProof()
    {
        // Found by running this against real data. Three addresses pass DMARC
        // for bmcedc.com and every one of them signs
        // antispam.mailspamprotection.com - the same unaligned domain the
        // failing address signs. Read as "that path signs as the customer", it
        // sends somebody to a vendor with a claim the vendor can disprove in
        // one line, which is worse than saying nothing.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("185.56.86.128", 20, "acme.com",
                "antispam.example.net", "pass", "djga.example", "pass", "pass"),
            SignedRow("185.56.86.144", 30, "acme.com",
                "antispam.example.net", "pass", "djga.example", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var broken = Assert.Single(detail!.SigningUnaligned);
        Assert.Equal("185.56.86.144", broken.SourceIp);
        Assert.Null(broken.SameServiceSigningCorrectly);
    }

    [Fact]
    public async Task OneStrayMessageDoesNotEarnACalloutOfItsOwn()
    {
        // A forwarded message produces exactly this shape. Six of them on one
        // domain sat above the finding that mattered.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("209.85.208.100", 1, "acme.com",
                "alwaysanalytics.example", "pass", "alwaysanalytics.example", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Empty(detail!.SigningUnaligned);

        // Not hidden, though. The source is still listed as failing, still
        // carries the reason, and the table still marks it.
        var source = Assert.Single(detail.Misconfigured);
        Assert.Single(source.UnalignedDkim);
    }

    [Fact]
    public async Task AServiceLosingRealMailIsNotBuriedByTheStrayMessagesAroundIt()
    {
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("209.85.208.100", 1, "acme.com",
                "alwaysanalytics.example", "pass", "alwaysanalytics.example", "pass", "fail"),
            SignedRow("35.174.145.124", 45, "acme.com",
                "chambermaster.example", "pass", "us.cloud-sec-av.example", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var flagged = Assert.Single(detail!.SigningUnaligned);
        Assert.Equal("35.174.145.124", flagged.SourceIp);
    }

    [Fact]
    public async Task TheDomainsOwnServersAreNotOfferedAsProofAgainstEachOther()
    {
        // Every one of a domain's own hosts shares the domain's own envelope,
        // so without excluding them this would point at one of the customer's
        // servers as evidence about a third party that is not involved.
        await StoreAlignedAsync("acme.com", "reject", "s",
            SignedRow("192.0.2.25", 400, "acme.com",
                "acme.com", "pass", "acme.com", "pass", "pass"),
            SignedRow("192.0.2.26", 30, "acme.com",
                "mail.acme.com", "pass", "acme.com", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        var near = Assert.Single(detail!.SigningUnaligned);
        Assert.Null(near.SameServiceSigningCorrectly);
    }

    [Fact]
    public async Task AnUnalignedSpfPassIsNotReportedAsASigningProblem()
    {
        // A relay passing SPF for its own envelope is how relays work. It is
        // not a signature, there is nothing to re-sign, and the fix for it is
        // not the fix offered here.
        await StoreAlignedAsync("acme.com", "reject", "r",
            SignedRow("203.0.113.77", 25, "acme.com",
                "", "none", "relay.example.net", "pass", "fail"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.Empty(detail!.SigningUnaligned);

        // Still counted as a real service failing, which it is.
        Assert.Single(detail.Misconfigured);
    }

    [Fact]
    public async Task AlignmentDefaultsToRelaxedWhenTheReportDoesNotSay()
    {
        // RFC 7489's default. Assuming strict would invent near misses on every
        // domain whose receivers omit the tag.
        await StoreAsync("acme.com", "reject", Row("192.0.2.25", 10, "pass", "acme.com", "acme.com", "pass"));

        var detail = await GetAsync("acme.com");

        Assert.NotNull(detail);
        Assert.False(detail!.StrictDkim);
        Assert.False(detail.StrictSpf);
    }
}
