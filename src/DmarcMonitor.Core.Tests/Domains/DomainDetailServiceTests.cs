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
        _store.InitialiseAsync(DatabaseSchema.Sql).GetAwaiter().GetResult();
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
}
